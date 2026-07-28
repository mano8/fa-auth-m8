"""Layer B: revocation persistence on the real engines (``TEST-DB-01``, 3.5.4).

``REV-PATH-01`` is already proven per path in the unit suite — against the
SQLite surrogate. This module re-proves it where the transaction semantics are
real: every path enumerated in 3.5.4 persists the authoritative
``ClientSession`` state on a certified engine, and a subject-bound v2
``/private/v1/jti-status`` request **with Redis unavailable** still denies from
database state alone.

The second assertion drives the real route function (not the
``GenerationController`` primitive), so what is proven is the composed decision
an operator actually gets, including the Redis accelerator step being absent.
The outbox is deliberately never drained here: the database delete is the
authoritative revocation, so a stranded outbox must not change any answer.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta
from typing import Any, Optional
from unittest.mock import patch

import pytest
import sqlalchemy as sa
from sqlmodel import Session, col, select

from auth_sdk_m8.schemas.base import RoleType
from auth_sdk_m8.schemas.jti_status import JtiStatusInactiveResponse

from auth_user_service.db_models.api_keys import ApiKey
from auth_user_service.db_models.outbox import RevocationOutbox
from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.users import User, UserUpdate
from auth_user_service.routes.private import JtiStatusRequest, check_jti_status
from auth_user_service.services.client_sessions import SessionController
from auth_user_service.services.legacy_session_revocation import (
    GlobalLegacySessionRevocationController,
)
from auth_user_service.services.role_admin import (
    change_user_authorization,
    delete_user_account,
)
from auth_user_service.services.security_preflight import SecurityRepairController
from tests.integration.database._factories import (
    issue_session,
    jti,
    make_api_key,
    make_user,
    naive_utc,
)

pytestmark = pytest.mark.database_integration


def _jti_status(session: Session, token_jti: str, user_id: uuid.UUID) -> Any:
    """Drive the v2 route with Redis down — database state is the only input."""

    async def call() -> Any:
        with patch("auth_user_service.routes.private.settings") as mock_settings:
            mock_settings.is_stateful = True
            return await check_jti_status(
                body=JtiStatusRequest(
                    jti=token_jti, expected_user_id=user_id, schema_version="2"
                ),
                session=session,
                redis=None,
            )

    return asyncio.run(call())


def assert_denied(session: Session, token_jti: str, user_id: uuid.UUID) -> None:
    result = _jti_status(session, token_jti, user_id)
    assert isinstance(result, JtiStatusInactiveResponse)
    assert result.active is False


def assert_active(session: Session, token_jti: str, user_id: uuid.UUID) -> None:
    result = _jti_status(session, token_jti, user_id)
    assert getattr(result, "active", False) is True


def run_ddl(engine: sa.Engine, *statements: str) -> None:
    """Execute schema DDL with a bounded lock wait.

    Two tests must reproduce a pre-Enforce schema shape, which needs an
    exclusive lock. Bounding the wait turns "another connection left a
    transaction open" into an immediate, diagnosable failure rather than a
    required CI check that hangs.
    """
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            conn.execute(sa.text("SET LOCAL lock_timeout = '10s'"))
        else:
            conn.execute(sa.text("SET SESSION lock_wait_timeout = 10"))
        for statement in statements:
            conn.execute(sa.text(statement))


def drop_check_constraint(engine: sa.Engine, table: str, name: str) -> None:
    """Drop a named CHECK constraint, whichever spelling this server accepts.

    PostgreSQL and MariaDB use ``DROP CONSTRAINT``; MySQL 8 requires
    ``DROP CHECK`` for a check constraint. Both spellings are tried so the
    helper works on all three certified engines without inspecting the server
    version string (which is the *other* open item's business, 4.6).
    """
    errors: list[Exception] = []
    for clause in ("DROP CONSTRAINT", "DROP CHECK"):
        try:
            run_ddl(engine, f"ALTER TABLE {table} {clause} {name}")
            return
        except Exception as exc:  # noqa: BLE001 — the other spelling is tried
            errors.append(exc)
    raise AssertionError(f"could not drop CHECK constraint {name} on {table}: {errors}")


def _session_row(session: Session, token_jti: str) -> Optional[ClientSession]:
    return session.exec(
        select(ClientSession).where(col(ClientSession.jwt_jti) == token_jti)
    ).first()


# ── baseline ──────────────────────────────────────────────────────────────────


def test_untouched_session_is_active_from_database_state(
    it_session: Session,
) -> None:
    """Without a baseline, every "denied" assertion below could be vacuous."""
    user = make_user(it_session)
    issue_session(it_session, user, jti=jti("baseline"))
    assert_active(it_session, jti("baseline"), user.id)


# ── individual session revocation / logout ────────────────────────────────────


def test_revoke_session_jti_persists_the_delete_with_redis_down(
    it_session: Session, second_engine: sa.Engine
) -> None:
    """The former Redis-only primitive is authoritative on a real engine.

    Read back through a **separate connection**: an in-session assertion could
    be satisfied by the identity map rather than by committed state.
    """
    user = make_user(it_session)
    issued = issue_session(it_session, user, jti=jti("logout"))

    SessionController.revoke_session_jti(
        jti("logout"),
        issued.jwt_expires_at,
        None,
        session=it_session,
        user_id=str(user.id),
    )

    with Session(second_engine) as other:
        assert _session_row(other, jti("logout")) is None
        assert_denied(other, jti("logout"), user.id)


def test_delete_session_by_jti_persists_the_refresh_rotation(
    it_session: Session,
) -> None:
    """Refresh rotation supersedes the previous JTI in the database."""
    user = make_user(it_session)
    issue_session(it_session, user, jti=jti("rotated"))

    SessionController.delete_session_by_jti(
        it_session, jti("rotated"), user_id=str(user.id)
    )

    assert _session_row(it_session, jti("rotated")) is None
    assert_denied(it_session, jti("rotated"), user.id)


# ── administrative revocation ─────────────────────────────────────────────────


def test_administrative_single_session_revocation_persists(
    it_session: Session,
) -> None:
    user = make_user(it_session)
    issued = issue_session(it_session, user, jti=jti("admin-single"))

    SessionController.revoke_session_record(it_session, issued, None)

    assert _session_row(it_session, jti("admin-single")) is None
    assert_denied(it_session, jti("admin-single"), user.id)


def test_administrative_delete_by_user_persists(it_session: Session) -> None:
    user = make_user(it_session)
    issue_session(it_session, user, jti=jti("admin-bulk"))

    revoked = SessionController.revoke_all_user_sessions(it_session, user.id, None)

    assert revoked == 1
    assert_denied(it_session, jti("admin-bulk"), user.id)


def test_expired_session_purge_persists(it_session: Session) -> None:
    """The maintenance purge is a revocation path too (3.5.4)."""
    user = make_user(it_session)
    issued = issue_session(it_session, user, jti=jti("expired"))
    past = naive_utc() - timedelta(days=10)
    issued.jwt_expires_at = past
    issued.refresh_expires_at = past
    it_session.add(issued)
    it_session.commit()

    deleted = SessionController.purge_expired_sessions(it_session, user)

    assert deleted == 1
    assert _session_row(it_session, jti("expired")) is None
    assert_denied(it_session, jti("expired"), user.id)


# ── role change, deactivation, reactivation ───────────────────────────────────


def test_role_change_denies_the_prior_session_and_commits_the_outbox_atomically(
    it_session: Session, second_engine: sa.Engine
) -> None:
    """One transaction carries the revocation *and* its durable effects (3.5.2).

    The outbox rows are asserted from a separate connection precisely because
    "atomic with the commit" is a claim about what other connections can see.
    """
    user = make_user(it_session, role=RoleType.WRITER)
    issue_session(it_session, user, jti=jti("role-change"))

    result = change_user_authorization(
        session=it_session,
        actor_id=uuid.uuid4(),
        actor_role=RoleType.SUPERADMIN,
        db_user=user,
        user_in=UserUpdate(role=RoleType.READER),
    )

    assert result.revocation_enqueued is True
    with Session(second_engine) as other:
        assert _session_row(other, jti("role-change")) is None
        assert_denied(other, jti("role-change"), user.id)
        effects = other.exec(
            select(RevocationOutbox).where(RevocationOutbox.user_id == user.id)
        ).all()
        assert {row.effect_type for row in effects} == {"blacklist", "publish"}
        assert all(row.status == "pending" for row in effects), (
            "the outbox is intentionally left undrained: the database delete "
            "already denies, so propagation state must change no answer"
        )


def test_deactivation_revokes_api_keys_in_the_same_transaction(
    it_session: Session, second_engine: sa.Engine
) -> None:
    """3.11: a deactivated owner's keys are dead the moment the row commits."""
    user = make_user(it_session, role=RoleType.WRITER)
    key_id = make_api_key(it_session, user).id
    issue_session(it_session, user, jti=jti("deactivation"))

    change_user_authorization(
        session=it_session,
        actor_id=uuid.uuid4(),
        actor_role=RoleType.SUPERADMIN,
        db_user=user,
        user_in=UserUpdate(is_active=False),
    )

    with Session(second_engine) as other:
        key = other.get(ApiKey, key_id)
        assert key is not None
        assert key.revoked is True
        assert_denied(other, jti("deactivation"), user.id)


def test_reactivation_never_replays_a_revoked_session_or_key(
    it_session: Session,
) -> None:
    """Reactivation restores the account, never its old credentials."""
    user = make_user(it_session, role=RoleType.WRITER)
    key_id = make_api_key(it_session, user).id
    issue_session(it_session, user, jti=jti("reactivation"))

    for is_active in (False, True):
        change_user_authorization(
            session=it_session,
            actor_id=uuid.uuid4(),
            actor_role=RoleType.SUPERADMIN,
            db_user=user,
            user_in=UserUpdate(is_active=is_active),
        )

    assert user.is_active is True
    assert user.auth_generation == 3
    key = it_session.get(ApiKey, key_id)
    assert key is not None
    assert key.revoked is True, "reactivation must never un-revoke an API key"
    assert_denied(it_session, jti("reactivation"), user.id)


# ── deletion ──────────────────────────────────────────────────────────────────


def test_deletion_denies_through_the_durable_tombstone(
    it_session: Session, second_engine: sa.Engine
) -> None:
    """The user row is gone, so only the tombstone can carry the denial."""
    user = make_user(it_session, role=RoleType.WRITER)
    user_id = user.id
    issue_session(it_session, user, jti=jti("deleted"))

    delete_user_account(
        session=it_session,
        actor_id=uuid.uuid4(),
        actor_role=RoleType.SUPERADMIN,
        db_user=user,
    )

    with Session(second_engine) as other:
        assert other.get(User, user_id) is None
        assert_denied(other, jti("deleted"), user_id)


# ── audited repair ────────────────────────────────────────────────────────────


def test_repair_revokes_the_session_from_database_state(
    clean_database: sa.Engine,
) -> None:
    """A repaired mismatch propagates exactly like a runtime change (4.1).

    The mismatched row can only be created with raw SQL — the ORM validator and
    the equivalence CHECK both refuse it — so the CHECK is dropped for the
    insert and immediately restored, leaving the schema exactly as found.
    """
    user_id = uuid.uuid4()
    dialect = clean_database.dialect.name
    id_value = str(user_id) if dialect == "postgresql" else user_id.hex
    drop_check_constraint(
        clean_database, "auth_user", "ck_user_superuser_role_consistency"
    )
    with clean_database.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO auth_user (created_at, updated_at, provider, email, "
                "is_active, email_verified, is_superuser, role, auth_generation, id) "
                "VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'PASSWORD', "
                "'mismatched@example.com', true, true, true, 'USER', 1, :id)"
            ),
            {"id": id_value},
        )
    try:
        with Session(clean_database) as session:
            owner = session.get(User, user_id)
            assert owner is not None
            issue_session(session, owner, jti=jti("repair"))

        with Session(clean_database) as session:
            SecurityRepairController.repair_user(
                session,
                user_id=user_id,
                intended_role=RoleType.USER,
                actor="layer-b",
                reason="integration",
            )

        with Session(clean_database) as session:
            assert_denied(session, jti("repair"), user_id)
    finally:
        with clean_database.begin() as conn:
            conn.execute(
                sa.text("DELETE FROM auth_client_session WHERE user_id = :id"),
                {"id": id_value},
            )
            conn.execute(
                sa.text("DELETE FROM auth_user WHERE id = :id"), {"id": id_value}
            )
        run_ddl(
            clean_database,
            "ALTER TABLE auth_user ADD CONSTRAINT "
            "ck_user_superuser_role_consistency CHECK "
            "(is_superuser = (role = 'SUPERADMIN'))",
        )


# ── global legacy-session revocation (4.1 step 5) ─────────────────────────────


def test_global_legacy_revocation_denies_every_pre_cutover_session(
    clean_database: sa.Engine,
) -> None:
    """The cutover sweep is a revocation path, not a data migration.

    ``auth_generation`` is ``NOT NULL`` after Enforce, so the pre-cutover shape
    is reproduced by relaxing the column for the insert and restoring it — the
    sweep must then delete the row rather than backfill it, while a session that
    already carries a generation survives untouched.

    Every ORM session is closed before the DDL runs: an open transaction would
    hold a lock the ``ALTER`` needs, which is what ``run_ddl``'s bounded lock
    wait would surface.
    """
    with Session(clean_database) as setup:
        user = make_user(setup)
        user_id = user.id
        issue_session(setup, user, jti=jti("modern"))

    dialect = clean_database.dialect.name
    run_ddl(
        clean_database,
        "ALTER TABLE auth_client_session ALTER COLUMN auth_generation DROP NOT NULL"
        if dialect == "postgresql"
        else "ALTER TABLE auth_client_session MODIFY auth_generation BIGINT NULL",
    )
    with clean_database.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO auth_client_session (created_at, updated_at, provider, "
                "jwt_jti, refresh_token_hash, jwt_expires_at, refresh_expires_at, "
                "revoked, id, user_id, auth_generation) VALUES (CURRENT_TIMESTAMP, "
                "CURRENT_TIMESTAMP, 'PASSWORD', :jti, 'h', CURRENT_TIMESTAMP, "
                "CURRENT_TIMESTAMP, false, 'legacy-session', :user_id, NULL)"
            ),
            {
                "jti": jti("legacy"),
                "user_id": str(user_id) if dialect == "postgresql" else user_id.hex,
            },
        )
    try:
        with Session(clean_database) as session:
            result = GlobalLegacySessionRevocationController.revoke_legacy_sessions(
                session
            )
            assert result.revoked_count == 1
            assert _session_row(session, jti("legacy")) is None
            assert _session_row(session, jti("modern")) is not None
            assert_denied(session, jti("legacy"), user_id)
    finally:
        with clean_database.begin() as conn:
            conn.execute(sa.text("DELETE FROM auth_client_session"))
        run_ddl(
            clean_database,
            "ALTER TABLE auth_client_session ALTER COLUMN auth_generation SET NOT NULL"
            if dialect == "postgresql"
            else "ALTER TABLE auth_client_session MODIFY auth_generation BIGINT NOT NULL",
        )
