"""Tests for routes/profile.py — all runtime branches covered."""

import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlmodel import select

from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.db_models.api_keys import ApiKey
from auth_user_service.db_models.identity_blocks import IdentityBlock
from auth_user_service.db_models.outbox import (
    EFFECT_BLACKLIST,
    EFFECT_PUBLISH,
    RevocationOutbox,
)
from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.users import UpdatePassword, User, UserUpdateMe
from auth_user_service.routes.profile import (
    delete_user_me,
    read_user_me,
    update_password_me,
    update_user_me,
)
from auth_user_service.services.generation import GenerationController
from tests.conftest import TEST_PASSWORD


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user(*, is_superuser: bool = False, user_id: uuid.UUID | None = None) -> MagicMock:
    m = MagicMock()
    m.id = user_id or uuid.uuid4()
    m.is_superuser = is_superuser
    # Keep the role/flag pair canonical so the SDK superuser predicate resolves
    # correctly (is_superuser=True <=> role SUPERADMIN).
    m.role = RoleType.SUPERADMIN if is_superuser else RoleType.USER
    return m


def _mock_session(db_user: object = None) -> MagicMock:
    s = MagicMock()
    s.get.return_value = db_user
    return s


def _add_api_key(db_session, user_id: uuid.UUID) -> ApiKey:
    api_key = ApiKey(
        name="Self delete key",
        key_hash=uuid.uuid4().hex + uuid.uuid4().hex,
        user_id=user_id,
    )
    db_session.add(api_key)
    db_session.commit()
    db_session.refresh(api_key)
    return api_key


# ---------------------------------------------------------------------------
# read_user_me
# ---------------------------------------------------------------------------


class TestReadUserMe:
    def test_returns_current_user(self) -> None:
        current_user = _user()
        assert read_user_me(current_user=current_user) is current_user


# ---------------------------------------------------------------------------
# update_user_me
# ---------------------------------------------------------------------------


class TestUpdateUserMe:
    """Self-service update; the email-change rules run on the real service."""

    def test_no_email_update_succeeds(self, db_session, sample_user) -> None:
        """No email in payload — no re-authentication, no revocation."""
        generation = sample_user.auth_generation
        result = update_user_me(
            session=db_session,
            current_user=sample_user,
            user_in=UserUpdateMe(full_name="Updated Name"),
        )
        assert result.success is True
        assert result.user.full_name == "Updated Name"
        assert result.user.email_verified is True
        db_session.refresh(sample_user)
        assert sample_user.auth_generation == generation

    def test_same_email_is_not_a_change(self, db_session, sample_user) -> None:
        """Re-sending the current address needs no password and revokes nothing."""
        generation = sample_user.auth_generation
        result = update_user_me(
            session=db_session,
            current_user=sample_user,
            user_in=UserUpdateMe(email=sample_user.email),
        )
        assert result.success is True
        assert result.user.email_verified is True
        db_session.refresh(sample_user)
        assert sample_user.auth_generation == generation

    def test_null_email_is_ignored(self, db_session, sample_user) -> None:
        email = sample_user.email
        result = update_user_me(
            session=db_session,
            current_user=sample_user,
            user_in=UserUpdateMe.model_validate({"email": None, "full_name": "N"}),
        )
        assert result.user.email == email

    def test_email_change_with_current_password_succeeds(
        self, db_session, sample_user
    ) -> None:
        new_email = f"new_{uuid.uuid4().hex[:8]}@example.com"
        result = update_user_me(
            session=db_session,
            current_user=sample_user,
            user_in=UserUpdateMe(email=new_email, current_password=TEST_PASSWORD),
        )
        assert result.success is True
        assert result.user.email == new_email

    def test_email_change_without_current_password_is_refused(
        self, db_session, sample_user
    ) -> None:
        email = sample_user.email
        with pytest.raises(HTTPException) as exc:
            update_user_me(
                session=db_session,
                current_user=sample_user,
                user_in=UserUpdateMe(email="nopass@example.com"),
            )
        assert exc.value.status_code == 400
        assert "current_password" in exc.value.detail
        db_session.refresh(sample_user)
        assert sample_user.email == email

    def test_email_change_with_wrong_password_is_refused(
        self, db_session, sample_user
    ) -> None:
        with pytest.raises(HTTPException) as exc:
            update_user_me(
                session=db_session,
                current_user=sample_user,
                user_in=UserUpdateMe(
                    email="wrongpass@example.com", current_password="not-the-password"
                ),
            )
        assert exc.value.status_code == 400
        assert exc.value.detail == "Incorrect password"

    def test_google_account_cannot_change_email(self, db_session, google_user) -> None:
        email = google_user.email
        with pytest.raises(HTTPException) as exc:
            update_user_me(
                session=db_session,
                current_user=google_user,
                user_in=UserUpdateMe(
                    email="squat@example.com", current_password=TEST_PASSWORD
                ),
            )
        assert exc.value.status_code == 403
        db_session.refresh(google_user)
        assert google_user.email == email

    def test_google_account_can_update_other_fields(
        self, db_session, google_user
    ) -> None:
        result = update_user_me(
            session=db_session,
            current_user=google_user,
            user_in=UserUpdateMe(full_name="Renamed"),
        )
        assert result.user.full_name == "Renamed"

    def test_email_conflict_raises_409(
        self, db_session, sample_user, superuser
    ) -> None:
        with pytest.raises(HTTPException) as exc:
            update_user_me(
                session=db_session,
                current_user=sample_user,
                user_in=UserUpdateMe(
                    email=superuser.email, current_password=TEST_PASSWORD
                ),
            )
        assert exc.value.status_code == 409

    def test_conflict_is_not_revealed_without_the_password(
        self, db_session, sample_user, superuser
    ) -> None:
        """The password is checked before the address is looked up."""
        with pytest.raises(HTTPException) as exc:
            update_user_me(
                session=db_session,
                current_user=sample_user,
                user_in=UserUpdateMe(
                    email=superuser.email, current_password="not-the-password"
                ),
            )
        assert exc.value.status_code == 400

    def test_db_user_not_found_raises_404(self, sample_user) -> None:
        """session.get returns None → 404."""
        session = _mock_session(db_user=None)
        with pytest.raises(HTTPException) as exc:
            update_user_me(
                session=session,
                current_user=sample_user,
                user_in=UserUpdateMe(full_name="New Name"),
            )
        assert exc.value.status_code == 404

    def test_generic_exception_delegated(self, sample_user) -> None:
        """Unexpected exception → delegated to handle_route_exception."""
        session = _mock_session(db_user=sample_user)
        session.commit.side_effect = RuntimeError("boom")
        with patch(
            "auth_user_service.routes.profile.handle_route_exception"
        ) as mock_handle:
            mock_handle.return_value = MagicMock()
            update_user_me(
                session=session,
                current_user=sample_user,
                user_in=UserUpdateMe(full_name="New Name"),
            )
        mock_handle.assert_called_once()

    def test_privileged_field_not_persisted(self, db_session, sample_user) -> None:
        """Privileged field injected into model_dump must be filtered by the allowlist."""
        user_in = MagicMock(spec=UserUpdateMe)
        user_in.email = None
        user_in.model_dump.return_value = {
            "full_name": "Injected",
            "is_superuser": True,
            "current_password": TEST_PASSWORD,
        }
        original_superuser = sample_user.is_superuser
        result = update_user_me(
            session=db_session,
            current_user=sample_user,
            user_in=user_in,
        )
        assert result.success is True
        db_session.refresh(sample_user)
        assert sample_user.is_superuser == original_superuser


# ---------------------------------------------------------------------------
# update_password_me
# ---------------------------------------------------------------------------

_PASS = "oldpassword12"
_NEW_PASS = "newpassword12"


class TestUpdatePasswordMe:
    def test_db_user_not_found_raises_404(self, sample_user) -> None:
        session = _mock_session(db_user=None)
        body = UpdatePassword(current_password=_PASS, new_password=_NEW_PASS)
        with pytest.raises(HTTPException) as exc:
            update_password_me(session=session, body=body, current_user=sample_user)
        assert exc.value.status_code == 404

    def test_wrong_password_raises_400(self, sample_user) -> None:
        session = _mock_session(db_user=sample_user)
        body = UpdatePassword(current_password=_PASS, new_password=_NEW_PASS)
        with patch("auth_user_service.routes.profile.SecurityHelper") as mock_sec:
            mock_sec.verify_password.return_value = False
            with pytest.raises(HTTPException) as exc:
                update_password_me(session=session, body=body, current_user=sample_user)
        assert exc.value.status_code == 400

    def test_same_password_raises_400(self, sample_user) -> None:
        session = _mock_session(db_user=sample_user)
        body = UpdatePassword(current_password=_PASS, new_password=_PASS)
        with patch("auth_user_service.routes.profile.SecurityHelper") as mock_sec:
            mock_sec.verify_password.return_value = True
            with pytest.raises(HTTPException) as exc:
                update_password_me(session=session, body=body, current_user=sample_user)
        assert exc.value.status_code == 400

    def test_success(self, sample_user) -> None:
        session = _mock_session(db_user=sample_user)
        body = UpdatePassword(current_password=_PASS, new_password=_NEW_PASS)
        with patch("auth_user_service.routes.profile.SecurityHelper") as mock_sec:
            mock_sec.verify_password.return_value = True
            mock_sec.get_password_hash.return_value = "new_hashed"
            result = update_password_me(
                session=session, body=body, current_user=sample_user
            )
        assert "Password" in result.message

    def test_generic_exception_delegated(self, sample_user) -> None:
        session = _mock_session(db_user=sample_user)
        session.commit.side_effect = RuntimeError("db exploded")
        body = UpdatePassword(current_password=_PASS, new_password=_NEW_PASS)
        with (
            patch("auth_user_service.routes.profile.SecurityHelper") as mock_sec,
            patch(
                "auth_user_service.routes.profile.handle_route_exception"
            ) as mock_handle,
        ):
            mock_sec.verify_password.return_value = True
            mock_sec.get_password_hash.return_value = "hashed"
            mock_handle.return_value = MagicMock()
            update_password_me(session=session, body=body, current_user=sample_user)
        mock_handle.assert_called_once()


# ---------------------------------------------------------------------------
# delete_user_me
# ---------------------------------------------------------------------------


class TestDeleteUserMe:
    def test_superuser_raises_403(self) -> None:
        current_user = _user(is_superuser=True)
        session = _mock_session()
        with pytest.raises(HTTPException) as exc:
            delete_user_me(session=session, current_user=current_user)
        assert exc.value.status_code == 403

    def test_db_user_not_found_raises_404(self, sample_user) -> None:
        session = _mock_session(db_user=None)
        with pytest.raises(HTTPException) as exc:
            delete_user_me(session=session, current_user=sample_user)
        assert exc.value.status_code == 404

    def test_success_tombstones_and_revokes(
        self, db_session, sample_user, sample_client_session
    ) -> None:
        """S1A (N19): the admin transaction — tombstone, revocation, outbox."""
        user_id, jti = sample_user.id, sample_client_session.jwt_jti

        result = delete_user_me(session=db_session, current_user=sample_user)

        assert "deleted" in result.message.lower()
        assert db_session.get(User, user_id) is None
        assert GenerationController.subject_is_tombstoned(db_session, user_id)
        remaining = db_session.exec(
            select(ClientSession).where(ClientSession.user_id == user_id)
        ).all()
        assert remaining == []
        effects = {
            (row.effect_type, row.payload.get("jti"))
            for row in db_session.exec(
                select(RevocationOutbox).where(RevocationOutbox.user_id == user_id)
            )
        }
        assert (EFFECT_BLACKLIST, jti) in effects
        assert any(effect == EFFECT_PUBLISH for effect, _ in effects)

    def test_self_deletion_does_not_block_a_google_identity(
        self, db_session, google_user
    ) -> None:
        user_id = google_user.id
        delete_user_me(session=db_session, current_user=google_user)

        blocks = db_session.exec(
            select(IdentityBlock).where(IdentityBlock.user_id == user_id)
        ).all()
        assert blocks == []

    def test_success_deletes_owned_api_keys(self, db_session, sample_user) -> None:
        api_key = _add_api_key(db_session, sample_user.id)

        result = delete_user_me(session=db_session, current_user=sample_user)

        deleted_key = db_session.exec(
            select(ApiKey).where(ApiKey.id == api_key.id)
        ).first()
        assert "deleted" in result.message.lower()
        assert deleted_key is None

    def test_generic_exception_delegated(self, sample_user) -> None:
        session = _mock_session(db_user=sample_user)
        with (
            patch(
                "auth_user_service.routes.profile.delete_user_account",
                side_effect=RuntimeError("boom"),
            ),
            patch(
                "auth_user_service.routes.profile.handle_route_exception"
            ) as mock_handle,
        ):
            mock_handle.return_value = MagicMock()
            delete_user_me(session=session, current_user=sample_user)
        mock_handle.assert_called_once()
