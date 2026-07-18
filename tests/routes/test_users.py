"""Tests for routes/users.py."""

import uuid
from unittest.mock import patch

from sqlmodel import select

from auth_sdk_m8.schemas.base import RoleType
from auth_user_service.db_models.api_keys import ApiKey
from auth_user_service.db_models.tombstones import AuthTombstone
from auth_user_service.db_models.users import UserUpdate
from auth_user_service.routes.users import delete_user, update_current_user


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
