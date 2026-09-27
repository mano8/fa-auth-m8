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

from auth_sdk_m8.schemas.base import AuthProviderType, RoleType

from auth_user_service.core.config import settings
from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.users import User
from auth_user_service.schemas.account_lifecycle import EmailVerificationMode
from auth_user_service.services.security_preflight import (
    LoginMethods,
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
    now = datetime.now(timezone.utc)
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
        past = datetime.now(timezone.utc) - timedelta(days=1)
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


# ── account-lifecycle rollout report (C2, N11) ───────────────────────────────

_PASSWORD_ONLY = LoginMethods(password=True, google=False, verification_required=False)


def _add_user(
    session,
    *,
    provider: AuthProviderType = AuthProviderType.PASSWORD,
    superuser: bool = False,
    verified: bool = False,
    active: bool = True,
) -> uuid.UUID:
    is_google = provider == AuthProviderType.GOOGLE
    user = User(
        id=uuid.uuid4(),
        email=f"rollout_{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=None if is_google else "not-a-real-hash",
        oauth_user_id=f"sub-{uuid.uuid4().hex}" if is_google else None,
        provider=provider,
        is_active=active,
        email_verified=verified,
        is_superuser=superuser,
        role=RoleType.SUPERADMIN if superuser else RoleType.USER,
    )
    session.add(user)
    session.commit()
    return user.id


class TestAccountLifecycleRollout:
    def test_counts_active_unverified_password_accounts(self, db_session):
        before = SecurityPreflightController.run(
            db_session, login_methods=_PASSWORD_ONLY
        )
        _add_user(db_session)
        _add_user(db_session, superuser=True)
        # Not counted: verified, inactive, or Google (verified by Google).
        _add_user(db_session, verified=True)
        _add_user(db_session, active=False)
        _add_user(db_session, provider=AuthProviderType.GOOGLE)
        after = SecurityPreflightController.run(
            db_session, login_methods=_PASSWORD_ONLY
        )
        assert after.unverified_active_count == before.unverified_active_count + 2
        assert (
            after.unverified_active_superuser_count
            == before.unverified_active_superuser_count + 1
        )

    def test_password_superuser_is_locked_out_without_password_login(self, db_session):
        su = _add_user(db_session, superuser=True, verified=True)
        google_only = LoginMethods(
            password=False, google=True, verification_required=False
        )
        report = SecurityPreflightController.run(db_session, login_methods=google_only)
        assert su in report.superuser_lockout_ids

    def test_unverified_superuser_is_locked_out_under_required(self, db_session):
        unverified = _add_user(db_session, superuser=True)
        verified = _add_user(db_session, superuser=True, verified=True)
        required = LoginMethods(password=True, google=False, verification_required=True)
        report = SecurityPreflightController.run(db_session, login_methods=required)
        assert unverified in report.superuser_lockout_ids
        assert verified not in report.superuser_lockout_ids

    def test_google_superuser_is_locked_out_without_google(self, db_session):
        su = _add_user(db_session, provider=AuthProviderType.GOOGLE, superuser=True)
        report = SecurityPreflightController.run(
            db_session, login_methods=_PASSWORD_ONLY
        )
        assert su in report.superuser_lockout_ids
        with_google = LoginMethods(
            password=True, google=True, verification_required=True
        )
        report = SecurityPreflightController.run(db_session, login_methods=with_google)
        assert su not in report.superuser_lockout_ids

    def test_inactive_and_plain_users_are_never_lockouts(self, db_session):
        inactive = _add_user(db_session, superuser=True, active=False)
        plain = _add_user(db_session)
        nothing = LoginMethods(password=False, google=False, verification_required=True)
        report = SecurityPreflightController.run(db_session, login_methods=nothing)
        assert inactive not in report.superuser_lockout_ids
        assert plain not in report.superuser_lockout_ids

    def test_lockouts_never_change_clean(self, db_session):
        _add_user(db_session, superuser=True, verified=True)
        nothing = LoginMethods(password=False, google=False, verification_required=True)
        report = SecurityPreflightController.run(db_session, login_methods=nothing)
        assert report.superuser_lockout_ids
        assert report.clean is (
            not report.flagged_not_superadmin_ids
            and not report.superadmin_not_flagged_ids
        )

    def test_defaults_to_the_configured_login_methods(self, db_session, monkeypatch):
        su = _add_user(db_session, superuser=True)
        monkeypatch.setattr(
            settings, "EMAIL_VERIFICATION_MODE", EmailVerificationMode.REQUIRED
        )
        assert su in SecurityPreflightController.run(db_session).superuser_lockout_ids
        monkeypatch.setattr(
            settings, "EMAIL_VERIFICATION_MODE", EmailVerificationMode.OFF
        )
        report = SecurityPreflightController.run(db_session)
        assert su not in report.superuser_lockout_ids

    def test_login_methods_from_settings(self, monkeypatch):
        monkeypatch.setattr(settings, "PASSWORD_LOGIN_ENABLED", False)
        monkeypatch.setattr(settings, "GOOGLE_OAUTH_ENABLED", True)
        monkeypatch.setattr(
            settings, "EMAIL_VERIFICATION_MODE", EmailVerificationMode.OPTIONAL
        )
        assert LoginMethods.from_settings() == LoginMethods(
            password=False, google=True, verification_required=False
        )

    def test_new_fields_default_so_existing_reports_stay_valid(self):
        report = SecurityPreflightReport(
            flagged_not_superadmin_ids=(),
            superadmin_not_flagged_ids=(),
            active_canonical_superuser_count=1,
            inconsistent_ids_with_active_sessions=(),
        )
        assert report.unverified_active_count == 0
        assert report.unverified_active_superuser_count == 0
        assert report.superuser_lockout_ids == ()
