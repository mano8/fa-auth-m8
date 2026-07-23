"""Per-path revocation-persistence tests — `REV-PATH-01` (3.5.4).

The database is the source of revocation correctness; the Redis blacklist, the
outbox and the ``session-revoked`` event are accelerators only. Every path
enumerated in 3.5.4 is exercised here against a real session, and each one is
asserted twice:

1. the authoritative ``ClientSession`` state is persisted in the same
   transaction/operation as the revocation, and
2. **with Redis down** (``redis=None`` — no blacklist entry, no event delivery)
   a fresh subject-bound v2 ``/private/v1/jti-status`` request still denies,
   decided from database state alone.

The second assertion drives the real route function, so the proof covers the
composed decision (ordered algorithm + Redis accelerator step), not only the
``GenerationController`` primitive. ``TestNoRedisOnlyRevocationPath`` is the
regression lock: every ``SessionController`` entry point that writes to Redis
must require an authoritative DB session, so no future caller can reintroduce a
Redis-only revocation.
"""

import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from inspect import signature
from unittest.mock import MagicMock, patch

import pytest
from sqlmodel import col, select, text

import auth_user_service.events.hub as hubmod
from auth_sdk_m8.schemas.base import AuthProviderType, RoleType
from auth_sdk_m8.schemas.jti_status import JtiStatusInactiveResponse

from auth_user_service.db_models.sessions import ClientSession, ClientSessionCreate
from auth_user_service.db_models.users import User, UserUpdate
from auth_user_service.routes.private import JtiStatusRequest, check_jti_status
from auth_user_service.services.client_sessions import (
    RevocationTarget,
    SessionController,
)
from auth_user_service.services.legacy_session_revocation import (
    GlobalLegacySessionRevocationController,
)
from auth_user_service.services.role_admin import (
    change_user_authorization,
    delete_user_account,
)
from auth_user_service.services.security_preflight import SecurityRepairController


@pytest.fixture
def anyio_backend():
    return "asyncio"


class _RecordingHub:
    def __init__(self):
        self.events = []

    def publish(self, event_type, payload):
        self.events.append((event_type, payload))


@pytest.fixture
def recording_hub(monkeypatch):
    """Record the best-effort accelerator events instead of publishing them."""
    hub = _RecordingHub()
    monkeypatch.setattr(hubmod, "_hub", hub)
    return hub


# ── helpers ───────────────────────────────────────────────────────────────────


def _session_create(jti: str | None = None) -> ClientSessionCreate:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return ClientSessionCreate(
        jwt_jti=jti or str(uuid.uuid4()),
        refresh_token_hash="r" * 64,
        jwt_expires_at=now + timedelta(hours=1),
        refresh_expires_at=now + timedelta(days=7),
    )


def _issue_session(db_session, user, jti: str | None = None) -> ClientSession:
    """Issue a session through the real issuance path (stamps the generation)."""
    return SessionController.create_client_session(
        session=db_session,
        current_user=user,
        session_data=_session_create(jti),
    )


def _row_for(db_session, jti: str) -> ClientSession | None:
    return db_session.exec(
        select(ClientSession).where(col(ClientSession.jwt_jti) == jti)
    ).first()


async def _jti_status(db_session, jti: str, user_id) -> object:
    """Drive the v2 route with Redis unavailable — DB state is the only input."""
    with patch("auth_user_service.routes.private.settings") as mock_cfg:
        mock_cfg.is_stateful = True
        return await check_jti_status(
            body=JtiStatusRequest(
                jti=jti, expected_user_id=user_id, schema_version="2"
            ),
            session=db_session,
            redis=None,
        )


async def _assert_denied_with_redis_down(db_session, jti: str, user_id) -> None:
    result = await _jti_status(db_session, jti, user_id)
    assert isinstance(result, JtiStatusInactiveResponse)
    assert result.active is False


async def _assert_active_with_redis_down(db_session, jti: str, user_id) -> None:
    result = await _jti_status(db_session, jti, user_id)
    assert getattr(result, "active", False) is True


@contextmanager
def _check_constraints_disabled(session):
    """Temporarily disable SQLite CHECK enforcement, always restoring it."""
    session.execute(text("PRAGMA ignore_check_constraints=ON"))
    try:
        yield
    finally:
        session.execute(text("PRAGMA ignore_check_constraints=OFF"))


def _raw_insert_mismatched_user(session) -> uuid.UUID:
    """Insert a role/flag-mismatched row, as a real repair run would find it."""
    user_id = uuid.uuid4()
    with _check_constraints_disabled(session):
        session.execute(
            text(
                f"INSERT INTO {User.__tablename__} "
                "(id, provider, email, is_active, email_verified, is_superuser, "
                "role, auth_generation) "
                "VALUES (:id, 'PASSWORD', :email, 1, 0, 1, 'USER', 1)"
            ),
            {"id": user_id.hex, "email": f"mismatch_{user_id.hex[:8]}@example.com"},
        )
        session.commit()
    return user_id


# ── baseline: an untouched session is active from DB state alone ──────────────


class TestActiveBaseline:
    @pytest.mark.anyio
    async def test_issued_session_is_active_with_redis_down(
        self, db_session, sample_user
    ):
        """Guards the suite: denial below is caused by revocation, not by setup."""
        issued = _issue_session(db_session, sample_user)

        await _assert_active_with_redis_down(db_session, issued.jwt_jti, sample_user.id)


# ── individual session revocation (the previously Redis-only primitive) ───────


class TestIndividualSessionRevocation:
    def test_deletes_authoritative_row_and_blacklists(self, db_session, sample_user):
        issued = _issue_session(db_session, sample_user)
        manager = MagicMock()

        with patch(
            "auth_user_service.services.client_sessions.RedisSessionManager"
        ) as mock_cls:
            mock_cls.return_value = manager
            SessionController.revoke_session_jti(
                issued.jwt_jti,
                datetime.now(timezone.utc) + timedelta(hours=1),
                MagicMock(),
                session=db_session,
                user_id=str(sample_user.id),
            )

        assert _row_for(db_session, issued.jwt_jti) is None
        manager.blacklist_jti.assert_called_once()

    @pytest.mark.anyio
    async def test_revokes_from_db_when_redis_is_unavailable(
        self, db_session, sample_user
    ):
        """The revocation is no longer lost when Redis is down (audit finding 8)."""
        issued = _issue_session(db_session, sample_user)

        SessionController.revoke_session_jti(
            issued.jwt_jti,
            datetime.now(timezone.utc) + timedelta(hours=1),
            None,
            session=db_session,
            user_id=str(sample_user.id),
        )

        assert _row_for(db_session, issued.jwt_jti) is None
        await _assert_denied_with_redis_down(db_session, issued.jwt_jti, sample_user.id)

    @pytest.mark.anyio
    async def test_authoritative_delete_survives_a_failing_blacklist_write(
        self, db_session, sample_user
    ):
        """The DB delete commits *before* Redis, so a Redis error cannot undo it."""
        issued = _issue_session(db_session, sample_user)

        with patch(
            "auth_user_service.services.client_sessions.RedisSessionManager",
            side_effect=RuntimeError("redis exploded"),
        ):
            with pytest.raises(RuntimeError):
                SessionController.revoke_session_jti(
                    issued.jwt_jti,
                    datetime.now(timezone.utc) + timedelta(hours=1),
                    MagicMock(),
                    session=db_session,
                )

        assert _row_for(db_session, issued.jwt_jti) is None
        await _assert_denied_with_redis_down(db_session, issued.jwt_jti, sample_user.id)


# ── logout ────────────────────────────────────────────────────────────────────


class TestLogoutPath:
    @pytest.mark.anyio
    async def test_logout_primitives_persist_the_revocation(
        self, db_session, sample_user
    ):
        """Logout composes ``revoke_session_jti`` + the idempotent row delete."""
        issued = _issue_session(db_session, sample_user)

        SessionController.revoke_session_jti(
            issued.jwt_jti,
            datetime.now(timezone.utc) + timedelta(hours=1),
            None,
            session=db_session,
            user_id=str(sample_user.id),
        )
        # The second delete is a no-op — logout stays idempotent.
        SessionController.delete_session_by_jti(session=db_session, jti=issued.jwt_jti)

        assert _row_for(db_session, issued.jwt_jti) is None
        await _assert_denied_with_redis_down(db_session, issued.jwt_jti, sample_user.id)


# ── administrative revocation ─────────────────────────────────────────────────


class TestAdministrativeRevocation:
    @pytest.mark.anyio
    async def test_single_session_delete_persists_and_accelerates(
        self, db_session, sample_user
    ):
        issued = _issue_session(db_session, sample_user)
        manager = MagicMock()
        refresh_store = MagicMock()

        with (
            patch(
                "auth_user_service.services.client_sessions.RedisSessionManager"
            ) as mock_mgr,
            patch(
                "auth_user_service.services.client_sessions.RedisRefreshStore"
            ) as mock_store,
        ):
            mock_mgr.return_value = manager
            mock_store.return_value = refresh_store
            SessionController.revoke_session_record(db_session, issued, MagicMock())

        assert _row_for(db_session, issued.jwt_jti) is None
        # Administrative revocation used to be DB-only: no blacklist entry meant a
        # consumer's positive cache outlived the database decision until its TTL.
        manager.blacklist_jti.assert_called_once()
        refresh_store.revoke.assert_called_once_with(issued.jwt_jti)
        await _assert_denied_with_redis_down(db_session, issued.jwt_jti, sample_user.id)

    def test_single_session_delete_emits_a_per_jti_event(
        self, db_session, sample_user, recording_hub
    ):
        issued = _issue_session(db_session, sample_user)
        jti = issued.jwt_jti

        SessionController.revoke_session_record(db_session, issued, None)

        assert [payload["jti"] for _, payload in recording_hub.events] == [jti]

    @pytest.mark.anyio
    async def test_delete_by_user_persists_with_redis_down(
        self, db_session, sample_user
    ):
        issued = _issue_session(db_session, sample_user)

        count = SessionController.revoke_all_user_sessions(
            db_session, sample_user.id, None
        )

        assert count == 1
        assert _row_for(db_session, issued.jwt_jti) is None
        await _assert_denied_with_redis_down(db_session, issued.jwt_jti, sample_user.id)


# ── refresh rotation ──────────────────────────────────────────────────────────


class TestRefreshRotation:
    @pytest.mark.anyio
    async def test_superseded_jti_is_denied_from_db_state(
        self, db_session, sample_user
    ):
        """Rotation re-stamps the authoritative row, so the old JTI matches none.

        The superseded state is persisted, not merely dropped from the Redis
        refresh store (3.5.4).
        """
        old = _issue_session(db_session, sample_user).jwt_jti
        new = _issue_session(db_session, sample_user).jwt_jti

        assert old != new
        assert _row_for(db_session, old) is None
        await _assert_denied_with_redis_down(db_session, old, sample_user.id)
        await _assert_active_with_redis_down(db_session, new, sample_user.id)


# ── refresh-token reuse response ──────────────────────────────────────────────


class TestRefreshReuseResponse:
    @pytest.mark.anyio
    async def test_reuse_response_revokes_every_session_from_db_state(
        self, db_session, sample_user
    ):
        issued = _issue_session(db_session, sample_user)

        SessionController.revoke_all_user_sessions(db_session, sample_user.id, None)

        await _assert_denied_with_redis_down(db_session, issued.jwt_jti, sample_user.id)


# ── role change, deactivation, reactivation ───────────────────────────────────


class TestRoleChangeAndActivation:
    @pytest.mark.anyio
    async def test_role_change_denies_the_prior_session_from_db_state(
        self, db_session, sample_user, superuser
    ):
        issued = _issue_session(db_session, sample_user)

        result = change_user_authorization(
            session=db_session,
            actor_id=superuser.id,
            actor_role=RoleType.SUPERADMIN,
            db_user=sample_user,
            user_in=UserUpdate(role=RoleType.ADMIN),
        )

        assert result.revocation_enqueued is True
        assert _row_for(db_session, issued.jwt_jti) is None
        await _assert_denied_with_redis_down(db_session, issued.jwt_jti, sample_user.id)

    @pytest.mark.anyio
    async def test_deactivation_then_reactivation_never_replays_a_session(
        self, db_session, sample_user, superuser
    ):
        issued = _issue_session(db_session, sample_user)

        change_user_authorization(
            session=db_session,
            actor_id=superuser.id,
            actor_role=RoleType.SUPERADMIN,
            db_user=sample_user,
            user_in=UserUpdate(is_active=False),
        )
        await _assert_denied_with_redis_down(db_session, issued.jwt_jti, sample_user.id)

        change_user_authorization(
            session=db_session,
            actor_id=superuser.id,
            actor_role=RoleType.SUPERADMIN,
            db_user=sample_user,
            user_in=UserUpdate(is_active=True),
        )
        # Reactivation bumps the generation again — the pre-deactivation session
        # is never resurrected (3.5.1).
        await _assert_denied_with_redis_down(db_session, issued.jwt_jti, sample_user.id)


# ── deletion ──────────────────────────────────────────────────────────────────


class TestDeletion:
    @pytest.mark.anyio
    async def test_deletion_denies_via_the_durable_tombstone(
        self, db_session, sample_user, superuser
    ):
        issued = _issue_session(db_session, sample_user)
        user_id = sample_user.id

        delete_user_account(
            session=db_session,
            actor_id=superuser.id,
            actor_role=RoleType.SUPERADMIN,
            db_user=sample_user,
        )

        assert _row_for(db_session, issued.jwt_jti) is None
        await _assert_denied_with_redis_down(db_session, issued.jwt_jti, user_id)


# ── security repair ───────────────────────────────────────────────────────────


class TestSecurityRepair:
    @pytest.mark.anyio
    async def test_repair_revokes_the_session_from_db_state(self, db_session):
        user_id = _raw_insert_mismatched_user(db_session)
        jti = str(uuid.uuid4())
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        db_session.add(
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
        db_session.commit()

        SecurityRepairController.repair_user(
            db_session,
            user_id=user_id,
            intended_role=RoleType.USER,
            actor="operator",
            reason="audit",
        )

        assert _row_for(db_session, jti) is None
        await _assert_denied_with_redis_down(db_session, jti, user_id)


# ── global legacy-session revocation at cutover ───────────────────────────────


class TestGlobalLegacyRevocation:
    @pytest.mark.anyio
    async def test_legacy_rows_are_revoked_not_backfilled(
        self, db_session, sample_user
    ):
        jti = str(uuid.uuid4())
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        db_session.add(
            ClientSession(
                id=str(uuid.uuid4()),
                user_id=sample_user.id,
                provider=AuthProviderType.PASSWORD,
                jwt_jti=jti,
                refresh_token_hash="l" * 64,
                jwt_expires_at=now + timedelta(hours=1),
                refresh_expires_at=now + timedelta(days=7),
                revoked=False,
                auth_generation=None,
            )
        )
        db_session.commit()

        GlobalLegacySessionRevocationController.revoke_legacy_sessions(db_session)

        assert _row_for(db_session, jti) is None
        await _assert_denied_with_redis_down(db_session, jti, sample_user.id)


# ── regression lock: no revocation primitive may be Redis-only ────────────────


class TestNoRedisOnlyRevocationPath:
    """Every Redis-writing revocation entry point must require a DB session."""

    @pytest.mark.parametrize(
        "name",
        [
            "revoke_session_jti",
            "delete_session_by_jti",
            "revoke_session_record",
            "revoke_all_user_sessions",
            "capture_and_delete_user_sessions",
        ],
    )
    def test_entry_point_requires_an_authoritative_session(self, name):
        params = signature(getattr(SessionController, name)).parameters
        assert "session" in params or "client_session" in params
        for param in params.values():
            if param.name in {"session", "client_session"}:
                assert param.default is param.empty, (
                    f"{name}: the authoritative DB session must be mandatory — "
                    "an optional one allows a Redis-only revocation"
                )

    def test_post_commit_accelerator_is_the_only_redis_only_helper(self):
        """``apply_post_commit_revocation`` is explicitly post-commit.

        It takes no DB session by design: it runs *after* the authoritative
        transaction has committed. Its targets are captured from rows that were
        already deleted, so it can never be the sole effect of a revocation.
        """
        params = signature(SessionController.apply_post_commit_revocation).parameters
        assert "session" not in params
        assert list(params)[:3] == ["targets", "user_id", "redis"]


class TestPostCommitEventScope:
    def test_user_wide_default_emits_one_flush_event(
        self, db_session, sample_user, recording_hub
    ):
        targets = [
            RevocationTarget(
                jti="a", expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
            ),
            RevocationTarget(
                jti="b", expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
            ),
        ]

        SessionController.apply_post_commit_revocation(
            targets, str(sample_user.id), None
        )

        assert [payload["jti"] for _, payload in recording_hub.events] == [None]

    def test_narrow_scope_emits_one_event_per_target(
        self, db_session, sample_user, recording_hub
    ):
        targets = [
            RevocationTarget(
                jti="a", expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
            ),
            RevocationTarget(
                jti="b", expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
            ),
        ]

        SessionController.apply_post_commit_revocation(
            targets, str(sample_user.id), None, user_wide=False
        )

        assert [payload["jti"] for _, payload in recording_hub.events] == ["a", "b"]
