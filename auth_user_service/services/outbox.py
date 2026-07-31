"""Transactional revocation-outbox: enqueue + at-least-once drain worker (3.5.2).

The role-change transaction (:mod:`auth_user_service.services.role_admin`) calls
:meth:`OutboxController.enqueue_role_change_effects` to record the revocation side
effects — one ``blacklist`` row per captured access JTI plus one user-wide
``publish`` row — as durable :class:`~auth_user_service.db_models.outbox.RevocationOutbox`
rows **in the same transaction** as the DB revocation, so they commit atomically
with the authorization change and can never be lost by a post-commit crash.

A post-commit :class:`OutboxWorker` then drains the table:

* claim a batch with ``FOR UPDATE SKIP LOCKED`` + a time-bounded lease (the only
  claim mechanism; an expired lease is how a crashed worker's rows are recovered,
  never an alternative claim path);
* apply each effect idempotently — Redis blacklist writes with a TTL **derived
  from the captured per-target token expiry**, and the durable **v2**
  session-revoked publication;
* on success mark ``completed``; on a retryable failure reschedule with bounded
  exponential backoff; on exhausted retries mark ``dead`` (dead-letter).

The database delete performed by the role-change transaction is already the
authoritative revocation (3.5.4); this worker only accelerates consumer cache
eviction and Redis blacklisting, so outbox exhaustion never changes the
authoritative result.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional, Union
from uuid import UUID

from sqlmodel import Session, col, delete, or_, select

from auth_sdk_m8.schemas.user_events import SessionRevokedEvent

from auth_user_service.core.client import RedisRefreshStore, RedisSessionManager
from auth_user_service.db_models.outbox import (
    EFFECT_BLACKLIST,
    EFFECT_PUBLISH,
    STATUS_COMPLETED,
    STATUS_DEAD,
    STATUS_LEASED,
    STATUS_PENDING,
    USER_WIDE_TARGET,
    RevocationOutbox,
)
from auth_user_service.events import EVENT_SESSION_REVOKED, emit
from auth_user_service.services import outbox_metrics
from auth_user_service.services.client_sessions import RevocationTarget

if TYPE_CHECKING:  # pragma: no cover - typing only
    from redis import Redis

    from auth_user_service.core.config import Settings

logger = logging.getLogger(__name__)

# v2 session-revoked event schema version emitted by the durable publish effect
# (additive over v1; consumers dedup on the durable ``event_id``, 3.5.2).
EVENT_SCHEMA_V2 = "v2"


class OutboxDeliveryError(RuntimeError):
    """A retryable failure while delivering an outbox effect.

    Raised for a transient condition (e.g. Redis unavailable) or an
    unrecognised effect; the worker increments ``attempts`` and reschedules with
    backoff, dead-lettering only once retries are exhausted.
    """


def _as_aware_utc(value: datetime) -> datetime:
    """Normalise a possibly-naive timestamp to timezone-aware UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _digest_jti(jti: str) -> str:
    """Opaque, deterministic per-JTI target key.

    Hashing keeps the raw JTI out of the ``target_digest`` column and out of the
    derived ``event_id`` (JTIs are unguessable secrets kept to the payload and
    banned from logs/metrics, 3.5.2), while staying stable so a duplicate enqueue
    collapses onto the same unique row.
    """
    return hashlib.sha256(jti.encode("utf-8")).hexdigest()


def _event_id(
    user_id: object, auth_generation: int, effect_type: str, digest: str
) -> str:
    """Durable dedup key: the deterministic outbox 4-tuple (3.5.2).

    Distinct from the SSE transport id (``epoch-seq``), which resets on issuer
    restart and is never used for durable deduplication.
    """
    return f"{user_id}:{auth_generation}:{effect_type}:{digest}"


class OutboxController:
    """Enqueue revocation side effects as durable, transaction-neutral rows."""

    @staticmethod
    def enqueue_role_change_effects(
        session: Session,
        *,
        user_id: Union[UUID, str],
        auth_generation: int,
        targets: list[RevocationTarget],
    ) -> list[RevocationOutbox]:
        """Add the outbox rows for one role-change revocation (3.5.2).

        Emits **one ``blacklist`` row per captured ``(jti, expires_at)`` target**
        (its payload carries both, so no expiry is ever lost to aggregation) and
        **one user-wide ``publish`` row** carrying the durable v2 session-revoked
        event. Transaction-neutral: rows are added to *session* but **not**
        committed — the caller's role-change transaction owns the commit, so the
        effects persist atomically with the DB revocation. Returns the rows added
        (their ``target_digest`` unique key makes a duplicate enqueue harmless).
        """
        uid = str(user_id)
        rows: list[RevocationOutbox] = []

        for target in targets:
            digest = _digest_jti(target.jti)
            rows.append(
                RevocationOutbox(
                    user_id=UUID(uid),
                    auth_generation=auth_generation,
                    effect_type=EFFECT_BLACKLIST,
                    target_digest=digest,
                    payload={
                        "jti": target.jti,
                        "expires_at": _as_aware_utc(target.expires_at).isoformat(),
                    },
                    status=STATUS_PENDING,
                )
            )

        publish_event_id = _event_id(
            uid, auth_generation, EFFECT_PUBLISH, USER_WIDE_TARGET
        )
        publish_payload = SessionRevokedEvent(
            user_id=uid,
            jti=None,
            auth_generation=auth_generation,
            event_id=publish_event_id,
            version=EVENT_SCHEMA_V2,
        ).model_dump()
        rows.append(
            RevocationOutbox(
                user_id=UUID(uid),
                auth_generation=auth_generation,
                effect_type=EFFECT_PUBLISH,
                target_digest=USER_WIDE_TARGET,
                payload=publish_payload,
                status=STATUS_PENDING,
            )
        )

        for row in rows:
            session.add(row)
        return rows


@dataclass(frozen=True)
class DrainStats:
    """Per-drain counters (test/observability aid)."""

    claimed: int = 0
    completed: int = 0
    retried: int = 0
    dead: int = 0


class OutboxWorker:
    """At-least-once drain worker for the revocation outbox (3.5.2)."""

    def __init__(
        self,
        *,
        batch_size: int = 50,
        lease_seconds: int = 30,
        max_attempts: int = 5,
        backoff_base_seconds: float = 2.0,
        backoff_cap_seconds: float = 300.0,
        completed_retention_seconds: int = 3600,
    ) -> None:
        self.batch_size = batch_size
        self.lease_seconds = lease_seconds
        self.max_attempts = max_attempts
        self.backoff_base_seconds = backoff_base_seconds
        self.backoff_cap_seconds = backoff_cap_seconds
        self.completed_retention_seconds = completed_retention_seconds

    @classmethod
    def from_settings(cls, settings: "Settings") -> "OutboxWorker":
        """Build a worker from the issuer settings."""
        return cls(
            batch_size=settings.OUTBOX_BATCH_SIZE,
            lease_seconds=settings.OUTBOX_LEASE_SECONDS,
            max_attempts=settings.OUTBOX_MAX_ATTEMPTS,
            backoff_base_seconds=settings.OUTBOX_BACKOFF_BASE_SECONDS,
            backoff_cap_seconds=settings.OUTBOX_BACKOFF_CAP_SECONDS,
            completed_retention_seconds=settings.OUTBOX_COMPLETED_RETENTION_SECONDS,
        )

    def _backoff(self, attempts: int) -> timedelta:
        """Exponential backoff (capped) for the *attempts*-th retry."""
        seconds = self.backoff_base_seconds * (2 ** max(attempts - 1, 0))
        return timedelta(seconds=min(seconds, self.backoff_cap_seconds))

    def claim_batch(self, session: Session, *, now: datetime) -> list[RevocationOutbox]:
        """Claim up to ``batch_size`` due rows with ``FOR UPDATE SKIP LOCKED``.

        Eligible rows are ``pending`` **or** ``leased`` with an expired lease
        (abandoned-lease recovery), whose ``next_attempt_at`` is due. Claimed
        rows are marked ``leased`` with a fresh ``lease_until`` and committed so
        the lease is visible to other workers before delivery begins.
        """
        eligible_status = or_(
            col(RevocationOutbox.status) == STATUS_PENDING,
            (col(RevocationOutbox.status) == STATUS_LEASED)
            & (col(RevocationOutbox.lease_until) < now),
        )
        due = or_(
            col(RevocationOutbox.next_attempt_at).is_(None),
            col(RevocationOutbox.next_attempt_at) <= now,
        )
        rows = list(
            session.exec(
                select(RevocationOutbox)
                .where(eligible_status, due)
                .order_by(col(RevocationOutbox.created_at))
                .limit(self.batch_size)
                .with_for_update(skip_locked=True)
            ).all()
        )
        lease_until = now + timedelta(seconds=self.lease_seconds)
        for row in rows:
            row.status = STATUS_LEASED
            row.lease_until = lease_until
            session.add(row)
        session.commit()
        return rows

    def _apply_effect(
        self, row: RevocationOutbox, redis: Optional["Redis"], *, now: datetime
    ) -> None:
        """Apply one effect; raise :class:`OutboxDeliveryError` to retry."""
        if row.effect_type == EFFECT_BLACKLIST:
            jti = row.payload["jti"]
            expires_at = _as_aware_utc(
                datetime.fromisoformat(row.payload["expires_at"])
            )
            ttl = int((expires_at - now).total_seconds())
            if ttl <= 0:
                # Token already expired — nothing to blacklist, effect satisfied.
                return
            if redis is None:
                raise OutboxDeliveryError("redis unavailable for blacklist effect")
            RedisSessionManager(redis).blacklist_jti(jti, ttl)
            RedisRefreshStore(redis).revoke(jti)
        elif row.effect_type == EFFECT_PUBLISH:
            # Best-effort in-memory fan-out; durability comes from this row, so a
            # crash before emit re-drains it. ``emit`` never raises.
            emit(EVENT_SESSION_REVOKED, row.payload)
        else:  # pragma: no cover - defensive; enqueue only writes known kinds
            raise OutboxDeliveryError(f"unknown effect_type {row.effect_type!r}")

    def process_row(
        self,
        session: Session,
        row: RevocationOutbox,
        redis: Optional["Redis"],
        *,
        now: datetime,
    ) -> str:
        """Deliver one claimed row; return its resulting status.

        On success: ``completed`` (+ propagation-latency metric). On a retryable
        failure: ``pending`` with backoff, or ``dead`` once ``max_attempts`` is
        reached. Commits the outcome so the lease is released either way.
        """
        effect_type = row.effect_type
        try:
            self._apply_effect(row, redis, now=now)
        except Exception:  # noqa: BLE001 — every delivery failure is retryable
            row.attempts += 1
            row.lease_until = None
            if row.attempts >= self.max_attempts:
                row.status = STATUS_DEAD
                outcome = STATUS_DEAD
                outbox_metrics.record_dead(effect_type)
                logger.error(
                    "outbox.dead effect_type=%s attempts=%d id=%s",
                    effect_type,
                    row.attempts,
                    row.id,
                )
            else:
                row.status = STATUS_PENDING
                row.next_attempt_at = now + self._backoff(row.attempts)
                outcome = STATUS_PENDING
                outbox_metrics.record_retried(effect_type)
                logger.warning(
                    "outbox.retry effect_type=%s attempts=%d id=%s",
                    effect_type,
                    row.attempts,
                    row.id,
                )
            session.add(row)
            session.commit()
            return outcome

        row.status = STATUS_COMPLETED
        row.completed_at = now
        row.lease_until = None
        session.add(row)
        session.commit()
        propagation = (now - _as_aware_utc(row.created_at)).total_seconds()
        outbox_metrics.record_completed(effect_type, propagation)
        return STATUS_COMPLETED

    def drain_once(
        self,
        session: Session,
        redis: Optional["Redis"],
        *,
        now: Optional[datetime] = None,
    ) -> DrainStats:
        """Claim and deliver one batch; return per-drain counters."""
        current = _as_aware_utc(now or datetime.now(timezone.utc))
        rows = self.claim_batch(session, now=current)
        completed = retried = dead = 0
        for row in rows:
            outcome = self.process_row(session, row, redis, now=current)
            if outcome == STATUS_COMPLETED:
                completed += 1
            elif outcome == STATUS_DEAD:
                dead += 1
            else:
                retried += 1
        return DrainStats(
            claimed=len(rows), completed=completed, retried=retried, dead=dead
        )

    def reap_completed(
        self, session: Session, *, now: Optional[datetime] = None
    ) -> int:
        """Delete ``completed`` rows past the retention horizon; return the count.

        Completed rows are retained briefly so a duplicate drain stays a no-op,
        then reaped (3.5.2). ``dead`` rows are never reaped here — they await
        explicit operator replay/acknowledgement.
        """
        current = _as_aware_utc(now or datetime.now(timezone.utc))
        horizon = current - timedelta(seconds=self.completed_retention_seconds)
        # ``synchronize_session=False`` emits a pure SQL DELETE — the default
        # in-Python ``evaluate`` strategy would compare the loaded naive
        # ``completed_at`` against the aware ``horizon`` and raise.
        result = session.exec(
            delete(RevocationOutbox)
            .where(
                col(RevocationOutbox.status) == STATUS_COMPLETED,
                col(RevocationOutbox.completed_at) < horizon,
            )
            .execution_options(synchronize_session=False)
        )
        reaped = result.rowcount or 0
        if reaped:
            session.commit()
        return reaped
