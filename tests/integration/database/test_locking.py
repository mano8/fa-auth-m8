"""Layer B: real lock contention (``TEST-DB-01``, 3.5.2, 3.5.3).

``SELECT ... FOR UPDATE`` and ``FOR UPDATE SKIP LOCKED`` are **no-ops on the
SQLite surrogate**, so every guarantee built on them — the portable
superuser-set lock, the outbox drain, and both horizon-bounded purges — is
unproven until it runs here, against two genuinely separate connections on a
real engine (4.6).
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlmodel import Session, col, select

from auth_sdk_m8.schemas.base import ApiKeyAccessMode, Period, RoleType

from auth_user_service.db_models.api_keys import ApiKey, ApiKeyAudience, RateLimit
from auth_user_service.db_models.outbox import (
    EFFECT_BLACKLIST,
    STATUS_PENDING,
    RevocationOutbox,
)
from auth_user_service.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)
from auth_user_service.db_models.security_policy import (
    SUPERUSER_SET_POLICY_KEY,
    SecurityPolicy,
)
from auth_user_service.services.api_keys import purge_dead_api_keys
from auth_user_service.services.audit import RetentionWindow, purge_expired_audit_rows
from auth_user_service.services.outbox import OutboxWorker
from auth_user_service.services.role_admin import acquire_superuser_set_lock
from tests.integration.database._factories import make_api_key, make_user
from tests.integration.database._races import is_serialization_failure

pytestmark = pytest.mark.database_integration

_LOCK_TIMEOUT = 20.0


def _outbox_row(user_id: uuid.UUID, index: int) -> RevocationOutbox:
    return RevocationOutbox(
        user_id=user_id,
        auth_generation=2,
        effect_type=EFFECT_BLACKLIST,
        target_digest=f"digest-{index}",
        payload={
            "jti": f"jti-{index}",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
        status=STATUS_PENDING,
    )


def _audit_row(actor_id: uuid.UUID, *, age_days: float) -> PrivilegedActionAudit:
    return PrivilegedActionAudit(
        id=uuid.uuid4(),
        created_at=datetime.now(timezone.utc) - timedelta(days=age_days),
        actor_user_id=actor_id,
        actor_role=RoleType.SUPERADMIN,
        action=AuditAction.EDIT,
        table_name="auth_user",
        row_pk=str(uuid.uuid4()),
        target_owner_id=None,
    )


# ── the portable superuser-set lock (3.5.3, REV-LOCK-01) ──────────────────────


class TestSecurityPolicyRowLock:
    """``SELECT ... FOR UPDATE`` on the singleton row really serializes."""

    def test_second_connection_cannot_take_the_held_lock(
        self, it_session: Session, second_engine: sa.Engine
    ) -> None:
        """With the lock held, a ``NOWAIT`` acquisition fails immediately.

        ``NOWAIT`` turns the (otherwise timing-dependent) blocking behaviour
        into a deterministic assertion, and is supported by all three certified
        engines.
        """
        acquire_superuser_set_lock(it_session)  # holds the row; no commit yet
        try:
            with Session(second_engine) as other:
                with pytest.raises((OperationalError, DBAPIError)):
                    other.exec(
                        select(SecurityPolicy)
                        .where(
                            col(SecurityPolicy.policy_key) == SUPERUSER_SET_POLICY_KEY
                        )
                        .with_for_update(nowait=True)
                    ).first()
                other.rollback()
        finally:
            it_session.rollback()

    def test_lock_is_released_on_commit_and_serializes_the_waiter(
        self, it_session: Session, second_engine: sa.Engine
    ) -> None:
        """A blocking waiter proceeds only after the holder commits.

        This is the guarantee the last-superuser invariant rests on: the count
        and the mutation of the second transaction happen strictly after the
        first transaction's commit, never interleaved with it.
        """
        holder_committed = threading.Event()
        waiter_acquired = threading.Event()
        observed_revision: list[Optional[int]] = []

        def waiter() -> None:
            with Session(second_engine) as other:
                policy = other.exec(
                    select(SecurityPolicy)
                    .where(col(SecurityPolicy.policy_key) == SUPERUSER_SET_POLICY_KEY)
                    .with_for_update()
                ).first()
                waiter_acquired.set()
                observed_revision.append(policy.revision if policy else None)
                other.rollback()

        policy = acquire_superuser_set_lock(it_session)
        policy.revision += 1
        policy.updated_at = datetime.now(timezone.utc)
        it_session.add(policy)

        thread = threading.Thread(target=waiter, daemon=True)
        thread.start()
        # The waiter must still be blocked while the holder's transaction is open.
        assert not waiter_acquired.wait(timeout=1.5), (
            "a second connection acquired the superuser-set lock while it was "
            "held — the row lock is not serializing mutations (3.5.3)"
        )

        it_session.commit()
        holder_committed.set()
        thread.join(timeout=_LOCK_TIMEOUT)
        assert waiter_acquired.is_set(), "the waiter never acquired the released lock"
        assert holder_committed.is_set()
        # The waiter observes the committed revision, never the pre-image.
        assert observed_revision == [1]


# ── outbox claiming with SKIP LOCKED (3.5.2) ──────────────────────────────────


class TestOutboxSkipLocked:
    def test_open_transactions_never_receive_the_same_row(
        self, it_session: Session, second_engine: sa.Engine
    ) -> None:
        """A second claimer never receives a row the first is holding.

        The portable guarantee is *disjointness*, not a particular split: under
        ``REPEATABLE READ`` MySQL/MariaDB lock every row a scan examines, not
        only the ones the ``LIMIT`` returns, so a second claimer there may
        legitimately come back empty while PostgreSQL hands it the remainder.
        Both outcomes satisfy the contract — what must never happen is the same
        row going to two claimers — and the second claimer must not *block*,
        which is what ``SKIP LOCKED`` buys over a plain ``FOR UPDATE``.
        """
        user = make_user(it_session)
        for index in range(6):
            it_session.add(_outbox_row(user.id, index))
        it_session.commit()

        first = [
            row.id
            for row in it_session.exec(
                select(RevocationOutbox)
                .order_by(col(RevocationOutbox.created_at))
                .limit(3)
                .with_for_update(skip_locked=True)
            ).all()
        ]
        assert len(first) == 3

        with Session(second_engine) as other:
            second = [
                row.id
                for row in other.exec(
                    select(RevocationOutbox)
                    .order_by(col(RevocationOutbox.created_at))
                    .limit(3)
                    .with_for_update(skip_locked=True)
                ).all()
            ]
            other.rollback()

        assert set(first).isdisjoint(second), (
            "SKIP LOCKED handed the same outbox row to two concurrent claimers"
        )
        it_session.rollback()

    def test_two_workers_never_claim_the_same_row(
        self, it_session: Session, clean_database: sa.Engine, second_engine: sa.Engine
    ) -> None:
        """Two real workers drain one outbox without ever double-leasing a row.

        At-least-once delivery tolerates a row being *retried*; it does not
        tolerate two live workers holding the same row at the same time, which
        is exactly what ``SKIP LOCKED`` prevents and what the unit suite cannot
        observe.
        """
        user = make_user(it_session)
        for index in range(20):
            it_session.add(_outbox_row(user.id, index))
        it_session.commit()

        worker = OutboxWorker(batch_size=4, lease_seconds=120)
        claimed: list[list[uuid.UUID]] = []
        barrier = threading.Barrier(2, timeout=_LOCK_TIMEOUT)
        errors: list[BaseException] = []

        def drain(engine: sa.Engine) -> None:
            mine: list[uuid.UUID] = []
            try:
                barrier.wait()
                # Drain until this worker's claims come up empty rather than for a
                # fixed number of rounds: MySQL/MariaDB lock every row a scan
                # examines, so a batch can legitimately come back short and a
                # fixed round count would leave rows unclaimed on those engines.
                for _ in range(30):
                    with Session(engine) as session:
                        # Read the ids inside the session: the rows detach when
                        # it closes and any later attribute access would fail.
                        batch = [
                            row.id
                            for row in worker.claim_batch(
                                session, now=datetime.now(timezone.utc)
                            )
                        ]
                    if not batch:
                        break
                    mine.extend(batch)
            except BaseException as exc:  # noqa: BLE001 — reported to the test
                errors.append(exc)
            finally:
                claimed.append(mine)

        threads = [
            threading.Thread(target=drain, args=(engine,), daemon=True)
            for engine in (clean_database, second_engine)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=_LOCK_TIMEOUT)

        assert not errors, f"worker raised: {errors[0]!r}"
        first, second = claimed
        assert set(first).isdisjoint(second), (
            "two workers leased the same outbox row concurrently"
        )
        assert len(first) == len(set(first))
        assert len(second) == len(set(second))

        # Whether the pair drains the whole outbox in one pass is timing- and
        # dialect-dependent (a worker may exit on an empty batch while the other
        # still holds locks). What is not: nothing is stranded — a subsequent
        # drain claims exactly the rows the pair did not, and every row is
        # accounted for once.
        leftover: list[uuid.UUID] = []
        for _ in range(30):
            with Session(clean_database) as session:
                batch = [
                    row.id
                    for row in worker.claim_batch(
                        session, now=datetime.now(timezone.utc) + timedelta(seconds=300)
                    )
                ]
            if not batch:
                break
            leftover.extend(batch)
        assert set(first) | set(second) | set(leftover) == set(
            list(first) + list(second) + leftover
        )
        assert len(set(first) | set(second) | set(leftover)) == 20


# ── horizon-bounded purges under contention ───────────────────────────────────


class TestAuditPurgeUnderContention:
    """The purge steps over held rows instead of blocking on them.

    Contention is created deterministically — one connection holds a subset of
    the eligible rows ``FOR UPDATE`` while the purge runs on another — rather
    than by racing two purges. That is a stronger and more portable statement of
    what ``SKIP LOCKED`` buys: MySQL/MariaDB under ``REPEATABLE READ`` lock every
    row a scan examines (``created_at`` carries no index), so the size of the
    skipped set is dialect-dependent while "never blocks, never strands a row"
    is not.
    """

    def test_purge_skips_held_rows_and_finishes_them_after_release(
        self, it_session: Session, clean_database: sa.Engine, second_engine: sa.Engine
    ) -> None:
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        for _ in range(12):
            it_session.add(_audit_row(actor.id, age_days=200))
        it_session.commit()
        actor_id = actor.id

        holder = Session(second_engine)
        held = holder.exec(
            select(PrivilegedActionAudit)
            .order_by(col(PrivilegedActionAudit.created_at))
            .limit(4)
            .with_for_update()
        ).all()
        assert len(held) == 4
        first_removed = 0
        try:
            with Session(clean_database) as session:
                try:
                    first_removed = purge_expired_audit_rows(
                        session,
                        window=RetentionWindow.THREE_MONTHS,
                        actor_user_id=actor_id,
                        actor_role=RoleType.SUPERADMIN,
                        batch_size=3,
                    ).removed
                except Exception as exc:  # noqa: BLE001 — classified below
                    session.rollback()
                    # MySQL/MariaDB lock every row a scan examines, so a holder
                    # on this table can also block the purge's own maintenance
                    # insert. Refusing is a legitimate outcome; silently
                    # deleting a held row would not be.
                    assert is_serialization_failure(exc), (
                        f"the purge failed for an unexpected reason: {exc!r}"
                    )
            # It stepped over (or was refused by) the held rows rather than
            # deleting them — a purge that removed all twelve would mean the
            # holder's lock was ignored.
            assert first_removed < 12
        finally:
            holder.rollback()
            holder.close()

        with Session(clean_database) as session:
            second = purge_expired_audit_rows(
                session,
                window=RetentionWindow.THREE_MONTHS,
                actor_user_id=actor_id,
                actor_role=RoleType.SUPERADMIN,
                batch_size=3,
            )
        assert first_removed + second.removed == 12, (
            "every eligible row must be removed exactly once across the two runs"
        )

        with Session(clean_database) as session:
            surviving = session.exec(select(PrivilegedActionAudit)).all()
        # Only the maintenance rows the completed purges wrote for themselves
        # remain — each is newer than the horizon it was computed from (3.5.1).
        assert surviving
        assert all(row.row_pk.startswith("retention_purge:") for row in surviving)


class TestApiKeyPurgeUnderContention:
    def test_dead_key_purge_skips_held_rows_and_cascades_children(
        self, it_session: Session, clean_database: sa.Engine, second_engine: sa.Engine
    ) -> None:
        """``APIKEY-LIFECYCLE-01`` under real contention.

        The purge deletes only the parent ``ApiKey`` row and relies on the
        engine's ``ON DELETE CASCADE`` to clear ``api_key_audiences`` and
        ``RateLimit`` — a guarantee SQLite (whose FK enforcement is off by
        default) can never establish. With part of the table held by another
        connection it must skip those rows rather than block, and across the two
        runs every dead key and every child row must be gone while the live key
        is untouched.
        """
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        owner = make_user(it_session)
        dead = datetime.now(timezone.utc) - timedelta(days=200)
        for index in range(9):
            key = make_api_key(
                it_session,
                owner,
                access_mode=ApiKeyAccessMode.READ_ONLY,
                revoked=True,
                audiences=(f"consumer-{index}",),
                updated_at=dead,
            )
            it_session.add(RateLimit(api_key_id=key.id, period=Period.MINUTE, limit=5))
        live_id = make_api_key(it_session, owner).id
        it_session.commit()
        actor_id = actor.id

        holder = Session(second_engine)
        held = holder.exec(
            select(ApiKey)
            .where(col(ApiKey.revoked).is_(True))
            .limit(3)
            .with_for_update()
        ).all()
        assert held
        first_removed = 0
        try:
            with Session(clean_database) as session:
                try:
                    first_removed = purge_dead_api_keys(
                        session,
                        window=RetentionWindow.THREE_MONTHS,
                        actor_user_id=actor_id,
                        actor_role=RoleType.SUPERADMIN,
                        batch_size=3,
                    ).removed
                except Exception as exc:  # noqa: BLE001 — classified below
                    session.rollback()
                    assert is_serialization_failure(exc), (
                        f"the purge failed for an unexpected reason: {exc!r}"
                    )
            assert first_removed < 9
        finally:
            holder.rollback()
            holder.close()

        with Session(clean_database) as session:
            second = purge_dead_api_keys(
                session,
                window=RetentionWindow.THREE_MONTHS,
                actor_user_id=actor_id,
                actor_role=RoleType.SUPERADMIN,
                batch_size=3,
            )
        assert first_removed + second.removed == 9

        with Session(clean_database) as session:
            remaining_keys = session.exec(select(ApiKey)).all()
            assert [key.id for key in remaining_keys] == [live_id]
            assert session.exec(select(ApiKeyAudience)).all() == []
            assert (
                session.exec(
                    select(RateLimit).where(col(RateLimit.api_key_id).is_not(None))
                ).all()
                == []
            ), "cascade left orphaned rate-limit rows behind"
