"""Unit tests for services.users.UserController."""

import uuid
from unittest.mock import MagicMock

import pytest

from auth_user_service.db_models.users import UserCreate, UserUpdate
from auth_user_service.services.users import (
    UserController,
    UserUpdateOutcome,
    _derive_is_superuser,
)
from auth_sdk_m8.schemas.base import AuthProviderType, RoleType


class TestCreateUser:
    def test_password_provider_hashes_password(self, db_session):
        user_create = UserCreate(
            email=f"newuser_{uuid.uuid4().hex[:6]}@example.com",
            password="securepassword",
            provider=AuthProviderType.PASSWORD,
        )

        user = UserController.create_user(session=db_session, user_create=user_create)

        assert user.id is not None
        assert user.hashed_password is not None
        assert user.hashed_password != "securepassword"
        assert user.email == user_create.email

    def test_new_user_starts_at_generation_one(self, db_session):
        user_create = UserCreate(
            email=f"gen_{uuid.uuid4().hex[:6]}@example.com",
            password="securepassword",
            provider=AuthProviderType.PASSWORD,
        )

        user = UserController.create_user(session=db_session, user_create=user_create)

        assert user.auth_generation == 1

    def test_password_provider_sets_uuid_id(self, db_session):
        user_create = UserCreate(
            email=f"uid_{uuid.uuid4().hex[:6]}@example.com",
            password="securepassword",
            provider=AuthProviderType.PASSWORD,
        )

        user = UserController.create_user(session=db_session, user_create=user_create)

        assert user.id is not None
        uuid.UUID(str(user.id))  # validates it is a UUID

    def test_google_provider_creates_without_password(self, db_session):
        user_create = UserCreate(
            email=f"google_{uuid.uuid4().hex[:6]}@example.com",
            oauth_user_id=f"gid_{uuid.uuid4().hex}",
            provider=AuthProviderType.GOOGLE,
        )

        user = UserController.create_user(session=db_session, user_create=user_create)

        assert user.id is not None
        assert user.hashed_password is None
        assert user.oauth_user_id == user_create.oauth_user_id

    def test_password_provider_missing_password_raises(self, db_session):
        bad_create = UserCreate.model_construct(
            email=f"bad_{uuid.uuid4().hex[:6]}@example.com",
            password=None,
            provider=AuthProviderType.PASSWORD,
        )
        with pytest.raises(ValueError, match="password is required"):
            UserController.create_user(session=db_session, user_create=bad_create)

    def test_superadmin_role_derives_flag_true(self, db_session):
        user_create = UserCreate(
            email=f"super_{uuid.uuid4().hex[:6]}@example.com",
            password="securepassword",
            provider=AuthProviderType.PASSWORD,
            role=RoleType.SUPERADMIN,
        )

        user = UserController.create_user(session=db_session, user_create=user_create)

        assert user.role == RoleType.SUPERADMIN
        assert user.is_superuser is True

    def test_client_supplied_flag_is_ignored(self, db_session):
        """A client-supplied is_superuser on a lower role is overridden to False."""
        user_create = UserCreate(
            email=f"inject_{uuid.uuid4().hex[:6]}@example.com",
            password="securepassword",
            provider=AuthProviderType.PASSWORD,
            role=RoleType.USER,
            is_superuser=True,
        )

        user = UserController.create_user(session=db_session, user_create=user_create)

        assert user.role == RoleType.USER
        assert user.is_superuser is False


class TestUpdateUser:
    def test_update_full_name(self, db_session, sample_user):
        update = UserUpdate(full_name="New Name")

        updated = UserController.update_user(
            session=db_session,
            db_user=sample_user,
            user_in=update,
        )

        assert updated.full_name == "New Name"

    def test_update_password_rehashes(self, db_session, sample_user):
        old_hash = sample_user.hashed_password
        update = UserUpdate(
            provider=AuthProviderType.PASSWORD,
            password="newpassword123",
        )

        updated = UserController.update_user(
            session=db_session,
            db_user=sample_user,
            user_in=update,
        )

        assert updated.hashed_password != old_hash

    def test_update_without_password_preserves_hash(self, db_session, sample_user):
        old_hash = sample_user.hashed_password
        update = UserUpdate(full_name="Only Name Update")

        updated = UserController.update_user(
            session=db_session,
            db_user=sample_user,
            user_in=update,
        )

        assert updated.hashed_password == old_hash

    def test_role_promotion_to_superadmin_derives_flag(self, db_session, sample_user):
        update = UserUpdate(role=RoleType.SUPERADMIN)

        updated = UserController.update_user(
            session=db_session,
            db_user=sample_user,
            user_in=update,
        )

        db_session.refresh(updated)
        assert updated.role == RoleType.SUPERADMIN
        assert updated.is_superuser is True

    def test_role_demotion_from_superadmin_clears_flag(self, db_session, superuser):
        update = UserUpdate(role=RoleType.USER)

        updated = UserController.update_user(
            session=db_session,
            db_user=superuser,
            user_in=update,
        )

        db_session.refresh(updated)
        assert updated.role == RoleType.USER
        assert updated.is_superuser is False

    def test_role_change_bumps_generation(self, db_session, sample_user):
        start = sample_user.auth_generation
        updated = UserController.update_user(
            session=db_session,
            db_user=sample_user,
            user_in=UserUpdate(role=RoleType.ADMIN),
        )
        db_session.refresh(updated)
        assert updated.auth_generation == start + 1

    def test_same_role_update_does_not_bump_generation(self, db_session, sample_user):
        start = sample_user.auth_generation
        # A non-role update (and a same-role submission) is not an authorization
        # transition here, so the generation stays put.
        updated = UserController.update_user(
            session=db_session,
            db_user=sample_user,
            user_in=UserUpdate(full_name="No Auth Change"),
        )
        db_session.refresh(updated)
        assert updated.auth_generation == start

    def test_privileged_field_blocked_by_allowlist(self, db_session, sample_user):
        """is_superuser injected into the update dict must be dropped by _ADMIN_UPDATE_FIELDS."""
        user_in = MagicMock()
        user_in.model_dump.return_value = {
            "is_superuser": True,
            "full_name": "Injected",
        }
        original_superuser = sample_user.is_superuser

        updated = UserController.update_user(
            session=db_session,
            db_user=sample_user,
            user_in=user_in,
        )

        db_session.refresh(updated)
        assert updated.is_superuser == original_superuser
        assert updated.full_name == "Injected"


class TestApplyUserUpdate:
    def test_neutral_apply_does_not_commit_or_bump(self, db_session, sample_user):
        start_gen = sample_user.auth_generation
        outcome = UserController.apply_user_update(
            db_user=sample_user, user_in=UserUpdate(role=RoleType.ADMIN)
        )
        # In-memory mutation only: the flag is derived and role_changed is
        # reported, but the generation is untouched (the caller owns that).
        assert isinstance(outcome, UserUpdateOutcome)
        assert outcome.previous_role == RoleType.USER
        assert outcome.new_role == RoleType.ADMIN
        assert outcome.role_changed is True
        assert sample_user.is_superuser is False
        assert sample_user.auth_generation == start_gen

    def test_no_role_change_reports_unchanged(self, db_session, sample_user):
        outcome = UserController.apply_user_update(
            db_user=sample_user, user_in=UserUpdate(full_name="X")
        )
        assert outcome.role_changed is False


class TestDeriveIsSuperuser:
    def test_superadmin_is_true(self):
        assert _derive_is_superuser(RoleType.SUPERADMIN) is True

    @pytest.mark.parametrize(
        "role",
        [RoleType.ADMIN, RoleType.WRITER, RoleType.READER, RoleType.USER],
    )
    def test_lower_roles_are_false(self, role):
        assert _derive_is_superuser(role) is False


class TestGetUser:
    def test_returns_user_by_id(self, db_session, sample_user):
        result = UserController.get_user(session=db_session, user_id=sample_user.id)

        assert result is not None
        assert str(result.id) == str(sample_user.id)

    def test_returns_none_for_unknown_id(self, db_session):
        result = UserController.get_user(session=db_session, user_id=uuid.uuid4())

        assert result is None


class TestGetUserByEmail:
    def test_returns_user_by_email(self, db_session, sample_user):
        result = UserController.get_user_by_email(
            session=db_session, email=sample_user.email
        )

        assert result is not None
        assert result.email == sample_user.email

    def test_returns_none_for_unknown_email(self, db_session):
        result = UserController.get_user_by_email(
            session=db_session, email="nobody@nowhere.com"
        )

        assert result is None


class TestCountUsers:
    def test_count_increases_after_create(self, db_session):
        before = UserController.count_users(session=db_session)

        user_create = UserCreate(
            email=f"count_{uuid.uuid4().hex[:6]}@example.com",
            password="password123",
            provider=AuthProviderType.PASSWORD,
        )
        UserController.create_user(session=db_session, user_create=user_create)

        after = UserController.count_users(session=db_session)
        assert after == before + 1

    def test_count_returns_integer(self, db_session):
        result = UserController.count_users(session=db_session)
        assert isinstance(result, int)
        assert result >= 0
