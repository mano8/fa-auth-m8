"""Unit tests for the read-only mismatch/last-superuser preflight (4.1).

The strict ``User`` model and its named DB check constraint already reject an
inconsistent ``role``/``is_superuser`` pair through every Python and SQL path
in this schema (see ``tests/db_models/test_superuser_invariant.py``), so a
mismatched row cannot normally exist here. To exercise the preflight's
detection logic, tests simulate the pre-Enforce production state -- Expand has
no equivalence CHECK yet (4.1) -- by disabling SQLite's CHECK enforcement for
exactly the duration of one raw insert, then always restoring it, so no other
test on the shared session-scoped database ever observes it disabled.
"""

import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from sqlmodel import text

from auth_sdk_m8.schemas.base import AuthProviderType

from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.users import User
from auth_user_service.services.security_preflight import (
    SecurityPreflightController,
    SecurityPreflightReport,
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


def _add_session(
    session, user_id: uuid.UUID, *, jti: str, revoked: bool = False
) -> None:
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
            revoked=revoked,
            auth_generation=1,
        )
    )
    session.commit()


class TestSecurityPreflightController:
    def test_clean_rows_are_never_flagged(self, db_session, sample_user, superuser):
        report = SecurityPreflightController.run(db_session)
        assert sample_user.id not in report.flagged_not_superadmin_ids
        assert sample_user.id not in report.superadmin_not_flagged_ids
        assert superuser.id not in report.flagged_not_superadmin_ids
        assert superuser.id not in report.superadmin_not_flagged_ids
        assert report.active_canonical_superuser_count >= 1

    def test_detects_flagged_not_superadmin(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="USER", is_superuser=1
        )
        report = SecurityPreflightController.run(db_session)
        assert mismatched_id in report.flagged_not_superadmin_ids
        assert mismatched_id not in report.superadmin_not_flagged_ids
        assert report.flagged_not_superadmin_count >= 1
        assert report.clean is False

    def test_detects_superadmin_not_flagged(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="SUPERADMIN", is_superuser=0
        )
        report = SecurityPreflightController.run(db_session)
        assert mismatched_id in report.superadmin_not_flagged_ids
        assert mismatched_id not in report.flagged_not_superadmin_ids
        assert report.superadmin_not_flagged_count >= 1
        assert report.clean is False

    def test_superadmin_not_flagged_excluded_from_active_superuser_count(
        self, db_session
    ):
        # role=SUPERADMIN, is_superuser=False must not satisfy the dual-evidence
        # canonical-superuser predicate (3.5.3) merely because the role matches.
        before = SecurityPreflightController.run(
            db_session
        ).active_canonical_superuser_count
        _raw_insert_mismatched_user(db_session, role="SUPERADMIN", is_superuser=0)
        after = SecurityPreflightController.run(
            db_session
        ).active_canonical_superuser_count
        assert after == before

    def test_mismatch_with_active_session_is_flagged(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="USER", is_superuser=1
        )
        _add_session(db_session, mismatched_id, jti="active-jti-" + uuid.uuid4().hex)
        report = SecurityPreflightController.run(db_session)
        assert mismatched_id in report.inconsistent_ids_with_active_sessions

    def test_mismatch_without_session_not_flagged(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="USER", is_superuser=1
        )
        report = SecurityPreflightController.run(db_session)
        assert mismatched_id not in report.inconsistent_ids_with_active_sessions

    def test_revoked_session_not_counted_as_active(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="USER", is_superuser=1
        )
        _add_session(
            db_session,
            mismatched_id,
            jti="revoked-jti-" + uuid.uuid4().hex,
            revoked=True,
        )
        report = SecurityPreflightController.run(db_session)
        assert mismatched_id not in report.inconsistent_ids_with_active_sessions

    def test_expired_refresh_session_not_counted_as_active(self, db_session):
        mismatched_id = _raw_insert_mismatched_user(
            db_session, role="USER", is_superuser=1
        )
        past = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
        db_session.add(
            ClientSession(
                id=str(uuid.uuid4()),
                user_id=mismatched_id,
                provider=AuthProviderType.PASSWORD,
                jwt_jti="expired-jti-" + uuid.uuid4().hex,
                refresh_token_hash="s" * 64,
                jwt_expires_at=past,
                refresh_expires_at=past,
                revoked=False,
                auth_generation=1,
            )
        )
        db_session.commit()
        report = SecurityPreflightController.run(db_session)
        assert mismatched_id not in report.inconsistent_ids_with_active_sessions

    def test_consistent_users_never_join_the_session_scan(
        self, db_session, sample_user
    ):
        # A consistent user's own active session must never appear here -- the
        # session-ownership scan is scoped to inconsistent ids only.
        _add_session(db_session, sample_user.id, jti="clean-jti-" + uuid.uuid4().hex)
        report = SecurityPreflightController.run(db_session)
        assert sample_user.id not in report.inconsistent_ids_with_active_sessions

    def test_empty_id_tuple_short_circuits_without_querying_sessions(self, db_session):
        assert (
            SecurityPreflightController._ids_with_active_sessions(db_session, ()) == ()
        )


class TestSecurityPreflightReport:
    def test_clean_true_only_when_both_mismatch_lists_empty(self):
        clean = SecurityPreflightReport(
            flagged_not_superadmin_ids=(),
            superadmin_not_flagged_ids=(),
            active_canonical_superuser_count=1,
            inconsistent_ids_with_active_sessions=(),
        )
        assert clean.clean is True
        assert clean.flagged_not_superadmin_count == 0
        assert clean.superadmin_not_flagged_count == 0

    def test_not_clean_when_either_mismatch_list_nonempty(self):
        one_id = uuid.uuid4()
        dirty = SecurityPreflightReport(
            flagged_not_superadmin_ids=(one_id,),
            superadmin_not_flagged_ids=(),
            active_canonical_superuser_count=1,
            inconsistent_ids_with_active_sessions=(),
        )
        assert dirty.clean is False
        assert dirty.flagged_not_superadmin_count == 1
