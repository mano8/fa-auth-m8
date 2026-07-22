"""Tests for routes/users.py."""

import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlmodel import delete, select

from auth_sdk_m8.schemas.base import RoleType
from auth_user_service.db_models.api_keys import ApiKey
from auth_user_service.db_models.tombstones import AuthTombstone
from auth_user_service.db_models.users import User, UserCreate, UserRegister, UserUpdate
from auth_user_service.routes.users import (
    create_new_user_with_password,
    delete_user,
    read_user_by_id,
    read_users,
    register_user,
    update_current_user,
)

_PASS = "testpassword123"


def _clear_other_superadmins(db_session, keep_id: uuid.UUID) -> None:
    # Isolates the last-superuser invariant from other superusers left behind
    # by earlier tests on the shared session-scoped test database.
    db_session.exec(
        delete(User).where(User.id != keep_id, User.role == RoleType.SUPERADMIN)
    )
    db_session.flush()


def _add_api_key(db_session, user_id: uuid.UUID) -> ApiKey:
    api_key = ApiKey(
        name="Delete cascade key",
        key_hash=uuid.uuid4().hex + uuid.uuid4().hex,
        user_id=user_id,
    )
    db_session.add(api_key)
    db_session.commit()
    db_session.refresh(api_key)
    return api_key


class TestDeleteUser:
    def test_deletes_owned_api_keys(self, db_session, sample_user, superuser) -> None:
        api_key = _add_api_key(db_session, sample_user.id)

        with patch("auth_user_service.routes.users.emit"):
            result = delete_user(
                session=db_session,
                current_user=superuser,
                user_id=sample_user.id,
            )

        deleted_key = db_session.exec(
            select(ApiKey).where(ApiKey.id == api_key.id)
        ).first()
        assert "deleted" in result.message.lower()
        assert deleted_key is None

    def test_writes_durable_tombstone(self, db_session, sample_user, superuser) -> None:
        expected_terminal = sample_user.auth_generation + 1

        with patch("auth_user_service.routes.users.emit"):
            delete_user(
                session=db_session,
                current_user=superuser,
                user_id=sample_user.id,
            )

        # The tombstone survives the user's deletion (no FK cascade) and records a
        # terminal generation, so introspection treats the subject as revoked.
        tombstone = db_session.get(AuthTombstone, sample_user.id)
        assert tombstone is not None
        assert tombstone.terminal_generation == expected_terminal


class TestUpdateUserResponseContract:
    def test_role_change_returns_generation_and_enqueued_flag(
        self, db_session, sample_user, superuser
    ) -> None:
        start_gen = sample_user.auth_generation

        response = update_current_user(
            session=db_session,
            current_user=superuser,
            user_id=sample_user.id,
            user_in=UserUpdate(role=RoleType.WRITER),
        )

        # 200 body carries the updated user plus the two contract fields (3.5.2).
        assert response.id == sample_user.id
        assert response.role == RoleType.WRITER
        assert response.auth_generation == start_gen + 1
        assert response.revocation_enqueued is True

    def test_profile_only_update_reports_no_revocation(
        self, db_session, sample_user, superuser
    ) -> None:
        start_gen = sample_user.auth_generation

        response = update_current_user(
            session=db_session,
            current_user=superuser,
            user_id=sample_user.id,
            user_in=UserUpdate(full_name="Renamed"),
        )

        assert response.full_name == "Renamed"
        assert response.auth_generation == start_gen
        assert response.revocation_enqueued is False


class TestReadUsers:
    def test_lists_users_with_count(self, db_session, sample_user) -> None:
        result = read_users(session=db_session, skip=0, limit=100)
        assert result.count >= 1
        assert any(u.id == sample_user.id for u in result.data)

    def test_generic_exception_delegated(self, db_session) -> None:
        with (
            patch(
                "auth_user_service.routes.users.select",
                side_effect=RuntimeError("boom"),
            ),
            patch(
                "auth_user_service.routes.users.handle_route_exception"
            ) as mock_handle,
        ):
            mock_handle.return_value = MagicMock()
            read_users(session=db_session)
        mock_handle.assert_called_once()


class TestCreateNewUserWithPassword:
    def test_creates_user(self, db_session) -> None:
        email = f"created_{uuid.uuid4().hex[:8]}@example.com"
        user = create_new_user_with_password(
            session=db_session,
            user_in=UserCreate(email=email, password=_PASS),
        )
        assert user.email == email

    def test_duplicate_email_returns_400(self, db_session, sample_user) -> None:
        with pytest.raises(HTTPException) as exc:
            create_new_user_with_password(
                session=db_session,
                user_in=UserCreate(email=sample_user.email, password=_PASS),
            )
        assert exc.value.status_code == 400


class TestRegisterUser:
    def test_registers_user(self, db_session) -> None:
        email = f"registered_{uuid.uuid4().hex[:8]}@example.com"
        user = register_user(
            session=db_session,
            user_in=UserRegister(email=email, password=_PASS),
        )
        assert user.email == email

    def test_duplicate_email_returns_400(self, db_session, sample_user) -> None:
        with pytest.raises(HTTPException) as exc:
            register_user(
                session=db_session,
                user_in=UserRegister(email=sample_user.email, password=_PASS),
            )
        assert exc.value.status_code == 400


class TestReadUserById:
    def test_missing_user_returns_404(self, db_session, superuser) -> None:
        with pytest.raises(HTTPException) as exc:
            read_user_by_id(
                user_id=uuid.uuid4(), session=db_session, current_user=superuser
            )
        assert exc.value.status_code == 404

    def test_self_access_allowed(self, db_session, sample_user) -> None:
        result = read_user_by_id(
            user_id=sample_user.id, session=db_session, current_user=sample_user
        )
        assert result.id == sample_user.id

    def test_superuser_can_read_other_user(
        self, db_session, sample_user, superuser
    ) -> None:
        result = read_user_by_id(
            user_id=sample_user.id, session=db_session, current_user=superuser
        )
        assert result.id == sample_user.id

    def test_non_privileged_other_user_returns_403(
        self, db_session, sample_user, superuser
    ) -> None:
        with pytest.raises(HTTPException) as exc:
            read_user_by_id(
                user_id=superuser.id, session=db_session, current_user=sample_user
            )
        assert exc.value.status_code == 403


class TestUpdateCurrentUserErrorMapping:
    def test_missing_user_returns_404(self, db_session, superuser) -> None:
        with pytest.raises(HTTPException) as exc:
            update_current_user(
                session=db_session,
                current_user=superuser,
                user_id=uuid.uuid4(),
                user_in=UserUpdate(full_name="Nobody"),
            )
        assert exc.value.status_code == 404

    def test_email_change_to_unused_address_succeeds(
        self, db_session, sample_user
    ) -> None:
        new_email = f"changed_{uuid.uuid4().hex[:8]}@example.com"
        response = update_current_user(
            session=db_session,
            current_user=sample_user,
            user_id=sample_user.id,
            user_in=UserUpdate(email=new_email),
        )
        assert response.email == new_email

    def test_email_conflict_returns_409(
        self, db_session, sample_user, superuser
    ) -> None:
        with pytest.raises(HTTPException) as exc:
            update_current_user(
                session=db_session,
                current_user=superuser,
                user_id=superuser.id,
                user_in=UserUpdate(email=sample_user.email),
            )
        assert exc.value.status_code == 409
        assert exc.value.detail == "User with this email already exists"

    def test_self_promotion_returns_403(self, db_session, sample_user) -> None:
        with pytest.raises(HTTPException) as exc:
            update_current_user(
                session=db_session,
                current_user=sample_user,
                user_id=sample_user.id,
                user_in=UserUpdate(role=RoleType.WRITER),
            )
        assert exc.value.status_code == 403
        assert exc.value.detail == "A user may not raise their own role"

    def test_last_superuser_demotion_returns_409(self, db_session, superuser) -> None:
        _clear_other_superadmins(db_session, superuser.id)
        with pytest.raises(HTTPException) as exc:
            update_current_user(
                session=db_session,
                current_user=superuser,
                user_id=superuser.id,
                user_in=UserUpdate(role=RoleType.USER),
            )
        assert exc.value.status_code == 409
        assert exc.value.detail == "last_superuser_required"

    def test_generic_exception_delegated(self, db_session, sample_user) -> None:
        with (
            patch(
                "auth_user_service.routes.users.change_user_authorization",
                side_effect=RuntimeError("boom"),
            ),
            patch(
                "auth_user_service.routes.users.handle_route_exception"
            ) as mock_handle,
        ):
            mock_handle.return_value = MagicMock()
            update_current_user(
                session=db_session,
                current_user=sample_user,
                user_id=sample_user.id,
                user_in=UserUpdate(full_name="Renamed"),
            )
        mock_handle.assert_called_once()


class TestDeleteUserErrorMapping:
    def test_missing_user_returns_404(self, db_session, superuser) -> None:
        with pytest.raises(HTTPException) as exc:
            delete_user(
                session=db_session,
                current_user=superuser,
                user_id=uuid.uuid4(),
            )
        assert exc.value.status_code == 404

    def test_last_superuser_delete_returns_409(self, db_session, superuser) -> None:
        _clear_other_superadmins(db_session, superuser.id)
        with pytest.raises(HTTPException) as exc:
            delete_user(
                session=db_session,
                current_user=superuser,
                user_id=superuser.id,
            )
        assert exc.value.status_code == 409
        assert exc.value.detail == "last_superuser_required"

    def test_generic_exception_delegated(self, db_session, sample_user) -> None:
        with (
            patch(
                "auth_user_service.routes.users.delete_user_account",
                side_effect=RuntimeError("boom"),
            ),
            patch(
                "auth_user_service.routes.users.handle_route_exception"
            ) as mock_handle,
        ):
            mock_handle.return_value = MagicMock()
            delete_user(
                session=db_session,
                current_user=sample_user,
                user_id=sample_user.id,
            )
        mock_handle.assert_called_once()
