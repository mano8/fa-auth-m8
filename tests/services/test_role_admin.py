"""Unit tests for the route-owned superuser-set transaction (services.role_admin).

Covers the centralized last-superuser predicate, the portable singleton
policy-row lock (seed + existing branches), the role-administration matrix
(SUPERADMIN-only via the route guard; no self-promotion), and the atomic
role/activation/deletion transactions — including that **deactivation revokes the
owner's API keys in the same transaction** and **reactivation never un-revokes
them** (3.5, 3.5.3, 3.10, 3.11).
"""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from sqlmodel import delete, select

from auth_sdk_m8.schemas.base import AuthProviderType, RoleType

from auth_user_service.core.security import SecurityHelper
from auth_user_service.db_models.api_keys import ApiKey
from auth_user_service.db_models.security_policy import (
    SUPERUSER_SET_POLICY_KEY,
    SecurityPolicy,
)
from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.tombstones import AuthTombstone
from auth_user_service.db_models.users import User, UserUpdate
from auth_user_service.services.role_admin import (
    LastSuperuserError,
    SelfPromotionError,
    _is_promotion,
    acquire_superuser_set_lock,
    change_user_authorization,
    count_active_canonical_superusers,
    delete_user_account,
    is_active_canonical_superuser,
)

TEST_PASSWORD = "testpassword123"


def _make_superuser(db_session, *, is_active: bool = True) -> User:
    user = User(
        id=uuid.uuid4(),
        email=f"su_{uuid.uuid4().hex[:8]}@example.com",
        full_name="Extra Super",
        hashed_password=SecurityHelper.get_password_hash(TEST_PASSWORD),
        provider=AuthProviderType.PASSWORD,
        is_active=is_active,
        email_verified=True,
        is_superuser=True,
        role=RoleType.SUPERADMIN,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _add_api_key(db_session, user_id, *, revoked: bool = False) -> ApiKey:
    api_key = ApiKey(
        name="key",
        key_hash=uuid.uuid4().hex + uuid.uuid4().hex,
        user_id=user_id,
        revoked=revoked,
    )
    db_session.add(api_key)
    db_session.commit()
    db_session.refresh(api_key)
    return api_key


def _add_session(db_session, user) -> ClientSession:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cs = ClientSession(
        id=str(uuid.uuid4()),
        user_id=user.id,
        provider=AuthProviderType.PASSWORD,
        jwt_jti=str(uuid.uuid4()),
        refresh_token_hash="a" * 64,
        jwt_expires_at=now + timedelta(hours=1),
        refresh_expires_at=now + timedelta(days=7),
        revoked=False,
        auth_generation=user.auth_generation,
    )
    db_session.add(cs)
    db_session.commit()
    db_session.refresh(cs)
    return cs


class TestLastSuperuserPredicate:
    def test_active_superuser_is_true(self, superuser):
        assert is_active_canonical_superuser(superuser) is True

    def test_non_superuser_is_false(self, sample_user):
        assert is_active_canonical_superuser(sample_user) is False

    def test_inactive_superuser_is_false(self, db_session):
        su = _make_superuser(db_session, is_active=False)
        assert is_active_canonical_superuser(su) is False

    def test_count_excludes_requested_user(self, db_session, superuser):
        other = _make_superuser(db_session)
        assert count_active_canonical_superusers(db_session) >= 2
        excluded = count_active_canonical_superusers(
            db_session, exclude_user_id=other.id
        )
        assert excluded == count_active_canonical_superusers(db_session) - 1


class TestPromotionHelper:
    def test_strict_promotion_is_true(self):
        assert _is_promotion(RoleType.USER, RoleType.ADMIN) is True

    def test_same_role_is_false(self):
        assert _is_promotion(RoleType.ADMIN, RoleType.ADMIN) is False

    def test_demotion_is_false(self):
        assert _is_promotion(RoleType.ADMIN, RoleType.USER) is False


class TestAcquireSuperuserSetLock:
    def test_seeds_when_absent_then_finds_existing(self, db_session):
        # Remove any policy row seeded by earlier tests so the seed branch runs
        # deterministically inside this (rolled-back) transaction.
        db_session.exec(delete(SecurityPolicy))
        db_session.flush()

        seeded = acquire_superuser_set_lock(db_session)
        assert seeded is not None
        assert seeded.policy_key == SUPERUSER_SET_POLICY_KEY
        assert seeded.revision == 0

        again = acquire_superuser_set_lock(db_session)
        assert again.policy_key == SUPERUSER_SET_POLICY_KEY


class TestChangeUserAuthorizationProfileOnly:
    def test_pure_profile_update_takes_no_lock_and_no_bump(
        self, db_session, sample_user
    ):
        start_gen = sample_user.auth_generation
        result = change_user_authorization(
            session=db_session,
            actor_id=uuid.uuid4(),
            db_user=sample_user,
            user_in=UserUpdate(full_name="Renamed"),
        )
        assert result.full_name == "Renamed"
        assert result.auth_generation == start_gen


class TestChangeUserAuthorizationRole:
    def test_promotion_bumps_generation_and_revokes_sessions(
        self, db_session, sample_user
    ):
        start_gen = sample_user.auth_generation
        _add_session(db_session, sample_user)

        result = change_user_authorization(
            session=db_session,
            actor_id=uuid.uuid4(),
            db_user=sample_user,
            user_in=UserUpdate(role=RoleType.ADMIN),
        )

        assert result.role == RoleType.ADMIN
        assert result.auth_generation == start_gen + 1
        remaining = db_session.exec(
            select(ClientSession).where(ClientSession.user_id == sample_user.id)
        ).all()
        assert remaining == []

    def test_same_role_is_noop_for_revocation(self, db_session, sample_user):
        start_gen = sample_user.auth_generation
        policy_before = db_session.get(SecurityPolicy, SUPERUSER_SET_POLICY_KEY)
        rev_before = policy_before.revision if policy_before else 0

        result = change_user_authorization(
            session=db_session,
            actor_id=uuid.uuid4(),
            db_user=sample_user,
            user_in=UserUpdate(role=RoleType.USER),  # already USER
        )

        assert result.auth_generation == start_gen
        policy_after = db_session.get(SecurityPolicy, SUPERUSER_SET_POLICY_KEY)
        assert policy_after.revision == rev_before

    def test_demoting_last_superuser_raises(self, db_session, superuser):
        # Ensure no other active canonical superuser survives this transaction.
        db_session.exec(
            delete(User).where(
                User.id != superuser.id, User.role == RoleType.SUPERADMIN
            )
        )
        db_session.flush()
        with pytest.raises(LastSuperuserError):
            change_user_authorization(
                session=db_session,
                actor_id=uuid.uuid4(),
                db_user=superuser,
                user_in=UserUpdate(role=RoleType.USER),
            )

    def test_demoting_superuser_with_another_present_succeeds(
        self, db_session, superuser
    ):
        _make_superuser(db_session)  # a second active canonical superuser
        result = change_user_authorization(
            session=db_session,
            actor_id=uuid.uuid4(),
            db_user=superuser,
            user_in=UserUpdate(role=RoleType.USER),
        )
        assert result.role == RoleType.USER
        assert result.is_superuser is False

    def test_self_promotion_is_forbidden(self, db_session, sample_user):
        with pytest.raises(SelfPromotionError):
            change_user_authorization(
                session=db_session,
                actor_id=sample_user.id,
                db_user=sample_user,
                user_in=UserUpdate(role=RoleType.ADMIN),
            )

    def test_self_demotion_allowed_subject_to_last_superuser(
        self, db_session, superuser
    ):
        _make_superuser(db_session)  # another superuser so self-demotion is allowed
        result = change_user_authorization(
            session=db_session,
            actor_id=superuser.id,  # actor == target: self-demotion
            db_user=superuser,
            user_in=UserUpdate(role=RoleType.READER),
        )
        assert result.role == RoleType.READER

    def test_promotion_with_mock_redis_runs_post_commit(self, db_session, sample_user):
        _add_session(db_session, sample_user)
        result = change_user_authorization(
            session=db_session,
            actor_id=uuid.uuid4(),
            db_user=sample_user,
            user_in=UserUpdate(role=RoleType.WRITER),
            redis=MagicMock(),
        )
        assert result.role == RoleType.WRITER


class TestChangeUserAuthorizationActivation:
    def test_deactivation_revokes_api_keys_and_bumps_generation(
        self, db_session, sample_user
    ):
        start_gen = sample_user.auth_generation
        key = _add_api_key(db_session, sample_user.id)

        result = change_user_authorization(
            session=db_session,
            actor_id=uuid.uuid4(),
            db_user=sample_user,
            user_in=UserUpdate(is_active=False),
        )

        assert result.is_active is False
        assert result.auth_generation == start_gen + 1
        db_session.refresh(key)
        assert key.revoked is True

    def test_reactivation_never_unrevokes_keys(self, db_session):
        user = User(
            id=uuid.uuid4(),
            email=f"react_{uuid.uuid4().hex[:8]}@example.com",
            hashed_password=SecurityHelper.get_password_hash(TEST_PASSWORD),
            provider=AuthProviderType.PASSWORD,
            is_active=False,
            is_superuser=False,
            role=RoleType.USER,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        start_gen = user.auth_generation
        revoked_key = _add_api_key(db_session, user.id, revoked=True)

        result = change_user_authorization(
            session=db_session,
            actor_id=uuid.uuid4(),
            db_user=user,
            user_in=UserUpdate(is_active=True),
        )

        assert result.is_active is True
        # Reactivation is an authorization transition (generation bumps) but must
        # never clear a prior revocation.
        assert result.auth_generation == start_gen + 1
        db_session.refresh(revoked_key)
        assert revoked_key.revoked is True

    def test_deactivating_last_superuser_raises(self, db_session, superuser):
        db_session.exec(
            delete(User).where(
                User.id != superuser.id, User.role == RoleType.SUPERADMIN
            )
        )
        db_session.flush()
        with pytest.raises(LastSuperuserError):
            change_user_authorization(
                session=db_session,
                actor_id=uuid.uuid4(),
                db_user=superuser,
                user_in=UserUpdate(is_active=False),
            )


class TestDeleteUserAccount:
    def test_deletes_non_superuser_and_writes_tombstone(self, db_session, sample_user):
        expected_terminal = sample_user.auth_generation + 1
        _add_session(db_session, sample_user)
        uid = sample_user.id

        delete_user_account(
            session=db_session,
            actor_id=uuid.uuid4(),
            db_user=sample_user,
        )

        assert db_session.get(User, uid) is None
        tombstone = db_session.get(AuthTombstone, uid)
        assert tombstone is not None
        assert tombstone.terminal_generation == expected_terminal

    def test_deleting_last_superuser_raises(self, db_session, superuser):
        db_session.exec(
            delete(User).where(
                User.id != superuser.id, User.role == RoleType.SUPERADMIN
            )
        )
        db_session.flush()
        with pytest.raises(LastSuperuserError):
            delete_user_account(
                session=db_session,
                actor_id=uuid.uuid4(),
                db_user=superuser,
            )

    def test_deleting_superuser_with_another_present_succeeds(
        self, db_session, superuser
    ):
        _make_superuser(db_session)
        uid = superuser.id
        delete_user_account(
            session=db_session,
            actor_id=superuser.id,  # self-delete permitted subject to last-superuser
            db_user=superuser,
        )
        assert db_session.get(User, uid) is None
