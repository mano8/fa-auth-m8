"""Unit tests for global legacy-session revocation at cutover (4.1 step 5).

Mirrors the fixture style of ``tests/services/test_security_repair.py``:
sessions are inserted directly with an explicit ``auth_generation`` (``None``
for a legacy row, an integer for a post-cutover row) to model the mixed state
the sweep runs against between Expand and Enforce.

The test database's ``ClientSession`` table is shared (session-scoped engine)
across the whole test suite, and several other test modules leave their own
``auth_generation=None`` rows behind by design (they predate this feature or
test unrelated legacy-row handling). So assertions never assume the table
starts empty: they capture a baseline legacy-row count before adding rows and
assert against the delta, and scope "what remains" checks to the ids created
within the test.
"""

import uuid
from datetime import datetime, timedelta, timezone

from sqlmodel import col, select

from auth_sdk_m8.schemas.base import AuthProviderType

from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.services.legacy_session_revocation import (
    GlobalLegacySessionRevocationController,
)


def _add_session(session, user_id, *, jti: str, auth_generation) -> None:
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
            auth_generation=auth_generation,
        )
    )
    session.commit()


def _sessions_for(session, *user_ids):
    """Sessions scoped to *user_ids* only -- see module docstring."""
    return session.exec(
        select(ClientSession).where(col(ClientSession.user_id).in_(user_ids))
    ).all()


def _legacy_row_count(session) -> int:
    """Total rows with no ``auth_generation`` across the whole shared table."""
    return len(
        session.exec(
            select(ClientSession.id).where(col(ClientSession.auth_generation).is_(None))
        ).all()
    )


class TestRevokeLegacySessions:
    def test_deletes_only_rows_with_no_generation(self, db_session, sample_user):
        baseline = _legacy_row_count(db_session)
        _add_session(
            db_session,
            sample_user.id,
            jti="legacy-" + uuid.uuid4().hex,
            auth_generation=None,
        )
        _add_session(
            db_session,
            sample_user.id,
            jti="current-" + uuid.uuid4().hex,
            auth_generation=1,
        )

        result = GlobalLegacySessionRevocationController.revoke_legacy_sessions(
            db_session
        )

        assert result.revoked_count == baseline + 1
        remaining = _sessions_for(db_session, sample_user.id)
        assert len(remaining) == 1
        assert remaining[0].auth_generation == 1

    def test_sweeps_legacy_rows_across_every_user(
        self, db_session, sample_user, inactive_user
    ):
        baseline = _legacy_row_count(db_session)
        _add_session(
            db_session,
            sample_user.id,
            jti="legacy-a-" + uuid.uuid4().hex,
            auth_generation=None,
        )
        _add_session(
            db_session,
            inactive_user.id,
            jti="legacy-b-" + uuid.uuid4().hex,
            auth_generation=None,
        )

        result = GlobalLegacySessionRevocationController.revoke_legacy_sessions(
            db_session
        )

        assert result.revoked_count == baseline + 2
        assert _sessions_for(db_session, sample_user.id, inactive_user.id) == []

    def test_no_legacy_rows_is_a_safe_noop(self, db_session, sample_user):
        _add_session(
            db_session,
            sample_user.id,
            jti="current-" + uuid.uuid4().hex,
            auth_generation=1,
        )

        result = GlobalLegacySessionRevocationController.revoke_legacy_sessions(
            db_session
        )

        # This user's own current-generation row must never be touched,
        # regardless of legacy rows other tests left behind in the shared table.
        assert len(_sessions_for(db_session, sample_user.id)) == 1
        assert result.revoked_count >= 0

    def test_repeat_sweep_is_idempotent(self, db_session, sample_user):
        _add_session(
            db_session,
            sample_user.id,
            jti="legacy-" + uuid.uuid4().hex,
            auth_generation=None,
        )

        first = GlobalLegacySessionRevocationController.revoke_legacy_sessions(
            db_session
        )
        second = GlobalLegacySessionRevocationController.revoke_legacy_sessions(
            db_session
        )

        assert first.revoked_count >= 1
        assert second.revoked_count == 0
        assert _sessions_for(db_session, sample_user.id) == []

    def test_empty_table_is_a_safe_noop(self, db_session):
        first = GlobalLegacySessionRevocationController.revoke_legacy_sessions(
            db_session
        )
        second = GlobalLegacySessionRevocationController.revoke_legacy_sessions(
            db_session
        )

        # After one sweep every legacy row (including ones other tests left
        # behind) is gone, so an immediate repeat always finds zero.
        assert second.revoked_count == 0
        assert first.revoked_count >= 0
