"""Per-user authorization generation primitives and durable tombstones.

The authorization generation is a monotonic, per-user ``BIGINT`` counter that
makes "every session issued before time T is invalid" race-proof: instead of
relying on having enumerated the exact session JTIs visible during a role change,
the issuer increments the owner's generation, and any session stamped with an
older generation is treated as revoked (3.5.1 ``REV-GEN-01``).

This module owns the framework-neutral primitives (start value, ceiling,
fail-closed increment, staleness predicate) plus the DB-facing
:class:`GenerationController` that reads/writes the generation and the durable
deletion tombstone. The route-owned role-change transaction, the transactional
outbox, and the v2 ``/private/v1/jti-status`` decision endpoint are separate plan
items that *compose* these primitives; nothing here acquires the superuser-set
lock, drains an outbox, or changes the introspection wire contract.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Final, Optional

from sqlmodel import Session, col, select

from auth_user_service.core.config import settings
from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.tombstones import AuthTombstone
from auth_user_service.db_models.users import GENERATION_START as _GENERATION_START
from auth_user_service.db_models.users import User

# First generation stamped on a brand-new user; the counter only ever increases.
# Canonical name for callers; defined in db_models.users to keep that layer free
# of a services dependency.
GENERATION_START: Final[int] = _GENERATION_START
# Signed 64-bit ceiling (``BIGINT``). Wraparound is prohibited — an increment that
# would exceed this fails closed rather than resetting the counter (3.5.1).
GENERATION_MAX: Final[int] = 2**63 - 1


class GenerationOverflowError(RuntimeError):
    """Raised when the generation cannot increment without wrapping around.

    Wraparound would let an old generation become valid again, so the mutation
    fails closed: the authorization change does not commit without its new
    generation (3.5.1).
    """


def next_generation(current: int) -> int:
    """Return the next authorization generation, failing closed on overflow."""
    if current >= GENERATION_MAX:
        raise GenerationOverflowError(
            "authorization generation exhausted; refusing to wrap around"
        )
    return current + 1


def is_session_generation_stale(
    session_generation: Optional[int], owner_generation: int
) -> bool:
    """Whether a session's stamped generation is stale (i.e. revoked).

    A ``None``/absent stamp is a legacy session predating this mechanism and is
    treated as older than any current value — revoked. Otherwise the session is
    current only when its stamp equals the owner's current generation; any other
    value (necessarily lower, since the owner's counter only increases) is stale.
    """
    if session_generation is None:
        return True
    return session_generation != owner_generation


def tombstone_retention_seconds() -> int:
    """Minimum seconds a deletion tombstone must be retained before cleanup.

    The tombstone must outlive every artefact that could still replay the deleted
    subject's authorization: the access-token TTL and the refresh-session lifetime
    (3.5.1). The consumer cache horizon, event-replay window, and outbox retention
    fold in here once those systems land (later plan items); until then the token
    lifetimes are the authoritative floor.
    """
    access_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    refresh_seconds = settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60
    return max(access_seconds, refresh_seconds)


def _as_aware_utc(value: datetime) -> datetime:
    """Normalise a possibly-naive timestamp to timezone-aware UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class GenerationController:
    """DB-facing operations over the authorization generation and tombstones.

    Every method leaves the surrounding transaction and commit to its caller
    unless documented otherwise, so a generation bump or tombstone write is
    flushed atomically with the authorization change that triggered it (3.5.1).
    """

    @staticmethod
    def bump_user_generation(user: User) -> int:
        """Increment *user*'s authorization generation in place, failing closed.

        Returns the new generation. Only the in-memory attribute is advanced so
        it flushes with the rest of the authorization change; the caller owns the
        commit. Raises :class:`GenerationOverflowError` rather than wrapping.
        """
        user.auth_generation = next_generation(user.auth_generation)
        return user.auth_generation

    @staticmethod
    def write_deletion_tombstone(session: Session, user: User) -> AuthTombstone:
        """Durably record a terminal generation for a user about to be deleted.

        Idempotent max-generation upsert keyed by ``user_id``: a first delete
        inserts the tombstone, a replayed delete can only raise the terminal
        generation, never lower it. The caller owns the commit (the tombstone
        must commit atomically with the ``User`` deletion).
        """
        terminal = next_generation(user.auth_generation)
        existing = session.get(AuthTombstone, user.id)
        if existing is None:
            tombstone = AuthTombstone(user_id=user.id, terminal_generation=terminal)
            session.add(tombstone)
            return tombstone
        if terminal > existing.terminal_generation:
            existing.terminal_generation = terminal
        return existing

    @staticmethod
    def subject_is_tombstoned(session: Session, user_id: uuid.UUID) -> bool:
        """Whether a durable deletion tombstone exists for *user_id*."""
        return session.get(AuthTombstone, user_id) is not None

    @staticmethod
    def session_generation_is_stale(
        session: Session, jti: str, expected_user_id: uuid.UUID
    ) -> bool:
        """DB-authoritative stale-generation check for the introspection path.

        Returns ``True`` (revoked) when the subject is tombstoned, the session
        row is missing, its owner differs from *expected_user_id*, the owner is
        missing/inactive, or the session's stamped generation is stale relative
        to the owner's current generation (3.5.1). This is the stale-generation
        rejection primitive only; the ordered v2 ``/private/v1/jti-status``
        decision and its Redis-blacklist step compose it (separate plan item).
        """
        if GenerationController.subject_is_tombstoned(session, expected_user_id):
            return True
        client_session = session.exec(
            select(ClientSession).where(col(ClientSession.jwt_jti) == jti)
        ).first()
        if client_session is None or client_session.user_id != expected_user_id:
            return True
        owner = session.get(User, client_session.user_id)
        if owner is None or not owner.is_active:
            return True
        return is_session_generation_stale(
            client_session.auth_generation, owner.auth_generation
        )

    @staticmethod
    def cleanup_expired_tombstones(
        session: Session, *, now: Optional[datetime] = None
    ) -> int:
        """Delete tombstones older than the retention horizon; return the count.

        Guarded cleanup: only rows last written before
        ``now - tombstone_retention_seconds()`` are eligible (3.5.1). The further
        guard "no pending/dead-letter outbox effect still references the subject"
        is wired in when the transactional outbox lands (later plan item); until
        then no outbox exists to reference a subject, so the retention horizon is
        the only guard.
        """
        current = _as_aware_utc(now or datetime.now(timezone.utc))
        horizon = timedelta(seconds=tombstone_retention_seconds())
        deleted = 0
        for row in session.exec(select(AuthTombstone)).all():
            if current - _as_aware_utc(row.updated_at) >= horizon:
                session.delete(row)
                deleted += 1
        if deleted:
            session.commit()
        return deleted
