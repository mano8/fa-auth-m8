"""Unit tests for the audited role/flag-mismatch repair command (4.1).

Mirrors the raw-column simulation strategy of
``tests/services/test_security_preflight.py``: SQLite's named CHECK
constraint already rejects a mismatched row through every Python and SQL path
in this schema, so tests toggle ``PRAGMA ignore_check_constraints`` around
exactly one raw insert (always restoring it) to model the pre-Enforce
production state a real repair run would find.
"""

import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import col, select, text

from auth_sdk_m8.schemas.base import AuthProviderType, RoleType

from auth_user_service.db_models.outbox import (
    EFFECT_BLACKLIST,
    EFFECT_PUBLISH,
    RevocationOutbox,
)
from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.users import User
from auth_user_service.services.security_preflight import (
    NotMismatchedError,
    SecurityRepairController,
    UserNotFoundError,
)


@contextmanager
def _check_constraints_disabled(session):
    """Temporarily disable SQLite CHECK enforcement, always restoring it."""
    session.execute(text("PRAGMA ignore_check_constraints=ON"))
    try:
        yield
    finally:
        session.execute(text("PRAGMA ignore_check_constraints=OFF"))


def _raw_insert_mismatched_user(session, *, role: str, is_superuser: int) -> uuid.UUID:
    """Insert a role/flag-mismatched row bypassing ORM validation and the CHECK."""
    user_id = uuid.uuid4()
    with _check_constraints_disabled(session):
        session.execute(
            text(
                f"INSERT INTO {User.__tablename__} "
                "(id, provider, email, is_active, email_verified, is_superuser, role) "
                f"VALUES (:id, 'PASSWORD', :email, 1, 0, {is_superuser}, '{role}')"
            ),
            {"id": user_id.hex, "email": f"mismatch_{user_id.hex[:8]}@example.com"},
        )
        session.commit()
    return user_id


def _raw_row(session, user_id: uuid.UUID):
    return session.exec(
        select(
            User.id,
            User.role,
            User.is_superuser,
            User.auth_generation,
        ).where(col(User.id) == user_id)
    ).first()


def _add_active_session(session, user_id: uuid.UUID, *, jti: str) -> None:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    session.add(
        ClientSession(
            id=str(uuid.uuid4()),
            user_id=user_id,
            provider=AuthProviderType.PASSWORD,
            jwt_jti=jti,
            refresh_token_hash="s" * 64,
            jwt_expires_at=now + timedelta(hours=1),
            refresh_expires_at=now + timedelta(days=7),
            revoked=False,
            auth_generation=1,
        )
    )
    session.commit()


def _outbox_rows(session, user_id: uuid.UUID):
    return session.exec(
        select(RevocationOutbox).where(col(RevocationOutbox.user_id) == user_id)
    ).all()


class TestRepairUserErrors:
    def test_missing_user_raises_not_found(self, db_session):
        with pytest.raises(UserNotFoundError):
            SecurityRepairController.repair_user(
                db_session,
                user_id=uuid.uuid4(),
                intended_role=RoleType.USER,
                actor="ops",
                reason="test",
            )

    def test_consistent_row_with_different_role_raises_not_mismatched(
        self, db_session, sample_user
    ):
        # sample_user is already role/flag-consistent (RoleType.USER) — this is
        # a plain role change, not a mismatch this command may resolve.
        with pytest.raises(NotMismatchedError):
            SecurityRepairController.repair_user(
                db_session,
                user_id=sample_user.id,
                intended_role=RoleType.WRITER,
                actor="ops",
                reason="test",
            )
        # Nothing was written.
        row = _raw_row(db_session, sample_user.id)
        assert row.role == RoleType.USER
        assert row.auth_generation == sample_user.auth_generation

    def test_consistent_row_same_role_is_idempotent_noop(self, db_session, sample_user):
        result = SecurityRepairController.repair_user(
            db_session,
            user_id=sample_user.id,
            intended_role=RoleType.USER,
            actor="ops",
            reason="test",
        )
        assert result.already_repaired is True
        assert result.revocation_enqueued is False
        assert result.auth_generation == sample_user.auth_generation
        assert _outbox_rows(db_session, sample_user.id) == []


class TestRepairUserFlaggedNotSuperadmin:
    def test_repairs_to_non_superadmin_and_clears_flag(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="USER", is_superuser=1
        )
        result = SecurityRepairController.repair_user(
            db_session,
            user_id=mismatched_id,
            intended_role=RoleType.USER,
            actor="ops",
            reason="resolve preflight mismatch",
        )
        assert result.already_repaired is False
        assert result.previous_role == RoleType.USER
        assert result.previous_is_superuser is True
        assert result.intended_role == RoleType.USER
        assert result.revocation_enqueued is True

        row = _raw_row(db_session, mismatched_id)
        assert row.role == RoleType.USER
        assert row.is_superuser is False
        assert row.auth_generation == result.auth_generation
        assert row.auth_generation > 1

    def test_repairs_to_superadmin_and_sets_flag(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="USER", is_superuser=1
        )
        result = SecurityRepairController.repair_user(
            db_session,
            user_id=mismatched_id,
            intended_role=RoleType.SUPERADMIN,
            actor="ops",
            reason="operator confirms this account is a real superadmin",
        )
        row = _raw_row(db_session, mismatched_id)
        assert row.role == RoleType.SUPERADMIN
        assert row.is_superuser is True
        assert result.revocation_enqueued is True


class TestRepairUserSuperadminNotFlagged:
    def test_repairs_by_clearing_role_to_match_flag(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="SUPERADMIN", is_superuser=0
        )
        result = SecurityRepairController.repair_user(
            db_session,
            user_id=mismatched_id,
            intended_role=RoleType.READER,
            actor="ops",
            reason="downgrade compromised row",
        )
        row = _raw_row(db_session, mismatched_id)
        assert row.role == RoleType.READER
        assert row.is_superuser is False
        assert result.previous_role == RoleType.SUPERADMIN
        assert result.previous_is_superuser is False

    def test_repairs_by_raising_flag_to_match_role(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="SUPERADMIN", is_superuser=0
        )
        SecurityRepairController.repair_user(
            db_session,
            user_id=mismatched_id,
            intended_role=RoleType.SUPERADMIN,
            actor="ops",
            reason="operator confirms superadmin intent",
        )
        row = _raw_row(db_session, mismatched_id)
        assert row.role == RoleType.SUPERADMIN
        assert row.is_superuser is True


class TestRepairUserPropagation:
    def test_revokes_active_session_and_enqueues_outbox_effects(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="USER", is_superuser=1
        )
        _add_active_session(db_session, mismatched_id, jti="active-" + uuid.uuid4().hex)
        result = SecurityRepairController.repair_user(
            db_session,
            user_id=mismatched_id,
            intended_role=RoleType.USER,
            actor="ops",
            reason="resolve preflight mismatch",
        )
        # Authoritative revocation: the session row is gone.
        remaining = db_session.exec(
            select(ClientSession).where(col(ClientSession.user_id) == mismatched_id)
        ).all()
        assert remaining == []

        rows = _outbox_rows(db_session, mismatched_id)
        effect_types = sorted(r.effect_type for r in rows)
        assert effect_types == [EFFECT_BLACKLIST, EFFECT_PUBLISH]
        for row in rows:
            assert row.auth_generation == result.auth_generation

    def test_no_active_session_still_enqueues_only_the_publish_event(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="SUPERADMIN", is_superuser=0
        )
        SecurityRepairController.repair_user(
            db_session,
            user_id=mismatched_id,
            intended_role=RoleType.USER,
            actor="ops",
            reason="resolve preflight mismatch",
        )
        rows = _outbox_rows(db_session, mismatched_id)
        assert [r.effect_type for r in rows] == [EFFECT_PUBLISH]


class TestRepairUserIdempotency:
    def test_repeating_the_same_repair_is_a_noop(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="USER", is_superuser=1
        )
        first = SecurityRepairController.repair_user(
            db_session,
            user_id=mismatched_id,
            intended_role=RoleType.USER,
            actor="ops",
            reason="resolve preflight mismatch",
        )
        second = SecurityRepairController.repair_user(
            db_session,
            user_id=mismatched_id,
            intended_role=RoleType.USER,
            actor="ops",
            reason="repeat call",
        )
        assert second.already_repaired is True
        assert second.revocation_enqueued is False
        assert second.auth_generation == first.auth_generation
        # No additional outbox rows were enqueued by the repeat call.
        rows = _outbox_rows(db_session, mismatched_id)
        assert len(rows) == 1  # only the publish row from the first (real) repair

    def test_repeat_with_a_different_role_raises_not_mismatched(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="USER", is_superuser=1
        )
        SecurityRepairController.repair_user(
            db_session,
            user_id=mismatched_id,
            intended_role=RoleType.USER,
            actor="ops",
            reason="resolve preflight mismatch",
        )
        with pytest.raises(NotMismatchedError):
            SecurityRepairController.repair_user(
                db_session,
                user_id=mismatched_id,
                intended_role=RoleType.WRITER,
                actor="ops",
                reason="change my mind",
            )
