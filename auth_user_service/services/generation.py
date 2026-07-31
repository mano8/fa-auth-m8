"""Per-user authorization generation primitives and durable tombstones.

The authorization generation is a monotonic, per-user ``BIGINT`` counter that
makes "every session issued before time T is invalid" race-proof: instead of
relying on having enumerated the exact session JTIs visible during a role change,
the issuer increments the owner's generation, and any session stamped with an
older generation is treated as revoked (3.5.1 ``REV-GEN-01``).

This module owns the framework-neutral primitives (start value, ceiling,
fail-closed increment, staleness predicate) plus the DB-facing
:class:`GenerationController` that reads/writes the generation, the durable
deletion tombstone, and the DB-authoritative subject-bound v2
``/private/v1/jti-status`` decision (3.5.2). The route composes that decision with
the Redis-blacklist accelerator and the ``503``-on-DB-unavailable rule and owns
the wire contract; the route-owned role-change transaction/lock
(:mod:`auth_user_service.services.role_admin`) *composes* these primitives.
Tombstone cleanup reads the revocation outbox to honour the "no undelivered
effect references this subject" guard, but nothing here acquires the
superuser-set lock, enqueues an effect, or drains an outbox.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Final, Optional

from sqlmodel import Session, col, select

from auth_sdk_m8.authorization import privilege_claims_are_consistent

from auth_user_service.core.config import settings
from auth_user_service.db_models.outbox import (
    STATUS_DEAD,
    STATUS_LEASED,
    STATUS_PENDING,
    RevocationOutbox,
)
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
# Outbox row states whose revocation effect has not been delivered yet. A
# ``leased`` row is a ``pending`` row a worker currently holds, and a ``dead``
# row awaits operator replay, so both still *reference* their subject exactly as
# ``pending`` does; only ``completed`` rows are finished. A tombstone whose
# subject is named by any of these must survive the retention horizon (3.5.1).
UNDELIVERED_OUTBOX_STATUSES: Final[tuple[str, ...]] = (
    STATUS_PENDING,
    STATUS_LEASED,
    STATUS_DEAD,
)


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
    subject's authorization, so the horizon is the maximum of all four (3.5.1):

    * the access-token TTL and the refresh-session lifetime — a token minted
      before the delete stays parseable until it expires;
    * the completed-outbox retention — a ``completed`` row is kept as the
      idempotency window in which a duplicate delivery may still be replayed
      against the subject (rows that have *not* been delivered are handled by
      the reference guard in :meth:`GenerationController.cleanup_expired_tombstones`
      rather than by this horizon);
    * the operator-declared consumer cache / event-replay horizon, which the
      issuer cannot observe from its own state.
    """
    return max(
        settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60,
        settings.OUTBOX_COMPLETED_RETENTION_SECONDS,
        settings.TOMBSTONE_CONSUMER_HORIZON_SECONDS,
    )


def _as_aware_utc(value: datetime) -> datetime:
    """Normalise a possibly-naive timestamp to timezone-aware UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


@dataclass(frozen=True)
class JtiStatusDecision:
    """Outcome of the DB-authoritative subject-bound v2 JTI-status decision.

    A generic inactive result carries only ``active=False``; an active result
    additionally carries the ``user_id`` the caller asserted and the owner's
    current ``auth_generation`` so the consumer can tag its cache entry (3.5.2).
    """

    active: bool
    user_id: Optional[uuid.UUID] = None
    auth_generation: Optional[int] = None


#: Shared singleton returned for every inactive cause, so the endpoint answers
#: one indistinguishable generic result (no enumeration oracle, 3.5.2).
_INACTIVE_JTI_STATUS: Final[JtiStatusDecision] = JtiStatusDecision(active=False)


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
    def decide_jti_status(
        session: Session, jti: str, expected_user_id: uuid.UUID
    ) -> JtiStatusDecision:
        """DB-authoritative subject-bound v2 JTI-status decision (3.5.2).

        Evaluates the ordered algorithm and returns one generic inactive result
        for every failing cause — deletion tombstone, missing/revoked session,
        subject mismatch, missing/inactive/claim-inconsistent owner, and stale
        generation. Only a current session owned by *expected_user_id* behind a
        canonical, active, current-generation owner is active; that result
        carries the owner id and current generation for cache tagging. The Redis
        blacklist step and the ``503``-on-DB-unavailable rule are the route's,
        composed around this database-authoritative decision — the generation
        decision itself never falls open.
        """
        # 1. Durable deletion tombstone → every token for the subject is revoked.
        if GenerationController.subject_is_tombstoned(session, expected_user_id):
            return _INACTIVE_JTI_STATUS
        # 2. Session row missing or explicitly revoked.
        client_session = session.exec(
            select(ClientSession).where(col(ClientSession.jwt_jti) == jti)
        ).first()
        if client_session is None or client_session.revoked:
            return _INACTIVE_JTI_STATUS
        # 3. Session owner differs from the asserted subject.
        if client_session.user_id != expected_user_id:
            return _INACTIVE_JTI_STATUS
        # 4. Owner missing, inactive, or holding a claim-inconsistent pair.
        owner = session.get(User, client_session.user_id)
        if owner is None or not owner.is_active:
            return _INACTIVE_JTI_STATUS
        if not privilege_claims_are_consistent(owner.role, owner.is_superuser):
            return _INACTIVE_JTI_STATUS
        # 5. Session generation stale relative to the owner's current generation.
        if is_session_generation_stale(
            client_session.auth_generation, owner.auth_generation
        ):
            return _INACTIVE_JTI_STATUS
        return JtiStatusDecision(
            active=True,
            user_id=owner.id,
            auth_generation=owner.auth_generation,
        )

    @staticmethod
    def subjects_with_undelivered_effects(session: Session) -> set[uuid.UUID]:
        """User ids named by an outbox effect that has not been delivered.

        A ``pending``, ``leased``, or ``dead`` row is a revocation side effect the
        worker (or an operator replaying a dead letter) may still apply, and it
        carries the subject in its own columns, so that subject's tombstone must
        outlive it (3.5.1). Returns an empty set when every effect is completed.
        """
        return set(
            session.exec(
                select(RevocationOutbox.user_id).where(
                    col(RevocationOutbox.status).in_(UNDELIVERED_OUTBOX_STATUSES)
                )
            ).all()
        )

    @staticmethod
    def cleanup_expired_tombstones(
        session: Session, *, now: Optional[datetime] = None
    ) -> int:
        """Delete eligible deletion tombstones; return the count.

        Guarded cleanup with **both** normative guards (3.5.1): a row is eligible
        only when it was last written before ``now - tombstone_retention_seconds()``
        **and** no undelivered outbox effect still references its subject. The two
        are independent — an outbox row that is dead-lettered indefinitely holds
        its subject's tombstone indefinitely, however long the horizon is — so a
        referenced subject is skipped rather than deleted, and the tombstone keeps
        denying every token minted for it.
        """
        current = _as_aware_utc(now or datetime.now(timezone.utc))
        horizon = timedelta(seconds=tombstone_retention_seconds())
        referenced = GenerationController.subjects_with_undelivered_effects(session)
        deleted = 0
        for row in session.exec(select(AuthTombstone)).all():
            if row.user_id in referenced:
                continue
            if current - _as_aware_utc(row.updated_at) >= horizon:
                session.delete(row)
                deleted += 1
        if deleted:
            session.commit()
        return deleted
