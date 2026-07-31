"""Read-only mismatch preflight and audited repair (4.1 ``MIG-PREFLIGHT-01``).

Ahead of the Expand -> repair -> Enforce migration sequence (4.1), SDK 3
models and the strict issuer ``User`` model reject an inconsistent
``role``/``is_superuser`` pair (mirroring the DB check constraint that is only
added in Enforce), so scanning for and fixing exactly the rows that need
repair must never construct a ``User``/validating ORM entity for one of them.
Every query and update here touches individual scalar columns only.

:class:`SecurityPreflightController` is read-only. :class:`SecurityRepairController`
performs the operator-audited write that resolves a reported mismatch: it never
auto-promotes/demotes (the operator supplies the intended role explicitly), and
on a real change it propagates exactly like the runtime role-change transaction
-- bumping ``auth_generation``, revoking sessions, and enqueueing the same
durable outbox effects (3.5.1, 3.5.2). A row eligible for repair is, by
definition, never counted as an active canonical superuser today (the
dual-evidence predicate 3.5.3 requires ``role == SUPERADMIN and is_superuser``
together, and a mismatched row fails exactly one side of that), so repair can
only ever add a row to that set, never remove one -- the last-superuser
invariant cannot be violated by this command, and it does not acquire the
singleton ``security_policy`` set-mutation lock (3.5.3) that guards removals;
it takes only the target row's own lock to serialize concurrent repairs of
that one id. API-key authorization needs no separate revocation step because
it is evaluated live against the owner's current row (3.11).
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Tuple

from sqlmodel import Session, col, func, select, update

from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.users import User
from auth_user_service.services.client_sessions import SessionController
from auth_user_service.services.generation import next_generation
from auth_user_service.services.outbox import OutboxController
from auth_user_service.services.users import _derive_is_superuser

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SecurityPreflightReport:
    """Read-only mismatch/last-superuser preflight result (4.1).

    Carries only user ids and counts -- never email, token, JTI,
    password/provider secret, or session-payload data, per 4.1's
    no-sensitive-output rule.
    """

    flagged_not_superadmin_ids: Tuple[uuid.UUID, ...]
    superadmin_not_flagged_ids: Tuple[uuid.UUID, ...]
    active_canonical_superuser_count: int
    inconsistent_ids_with_active_sessions: Tuple[uuid.UUID, ...]

    @property
    def flagged_not_superadmin_count(self) -> int:
        """Count where ``is_superuser=true`` and ``role`` is not SUPERADMIN."""
        return len(self.flagged_not_superadmin_ids)

    @property
    def superadmin_not_flagged_count(self) -> int:
        """Count where ``role`` is SUPERADMIN and ``is_superuser=false``."""
        return len(self.superadmin_not_flagged_ids)

    @property
    def clean(self) -> bool:
        """Whether zero mismatches were found (migration may proceed, 4.1)."""
        return (
            not self.flagged_not_superadmin_ids and not self.superadmin_not_flagged_ids
        )


class SecurityPreflightController:
    """Raw-column read-only mismatch/last-superuser preflight (4.1)."""

    @staticmethod
    def run(session: Session) -> SecurityPreflightReport:
        """Scan existing rows and report mismatches; performs no writes.

        Every ``User``-touching query selects individual scalar columns (never
        ``select(User)`` or ``User.model_validate``), so a row this preflight
        exists to find can never itself raise while being found.
        """
        flagged_not_superadmin = tuple(
            session.exec(
                select(User.id).where(
                    col(User.is_superuser) == True,  # noqa: E712
                    col(User.role) != RoleType.SUPERADMIN,
                )
            ).all()
        )
        superadmin_not_flagged = tuple(
            session.exec(
                select(User.id).where(
                    col(User.role) == RoleType.SUPERADMIN,
                    col(User.is_superuser) == False,  # noqa: E712
                )
            ).all()
        )
        active_superuser_count = session.exec(
            select(func.count())  # pylint: disable=not-callable
            .select_from(User)
            .where(
                col(User.role) == RoleType.SUPERADMIN,
                col(User.is_superuser) == True,  # noqa: E712
                col(User.is_active) == True,  # noqa: E712
            )
        ).one()
        inconsistent_ids = flagged_not_superadmin + superadmin_not_flagged
        with_active_sessions = SecurityPreflightController._ids_with_active_sessions(
            session, inconsistent_ids
        )
        return SecurityPreflightReport(
            flagged_not_superadmin_ids=flagged_not_superadmin,
            superadmin_not_flagged_ids=superadmin_not_flagged,
            active_canonical_superuser_count=active_superuser_count,
            inconsistent_ids_with_active_sessions=with_active_sessions,
        )

    @staticmethod
    def _ids_with_active_sessions(
        session: Session, user_ids: Tuple[uuid.UUID, ...]
    ) -> Tuple[uuid.UUID, ...]:
        """Distinct owner ids among *user_ids* holding an active session.

        "Active" matches ``SessionController.get_user_active_sessions``:
        non-revoked and not yet past ``refresh_expires_at``.
        """
        if not user_ids:
            return ()
        now = datetime.now(timezone.utc)
        rows = session.exec(
            select(ClientSession.user_id)
            .where(
                col(ClientSession.user_id).in_(user_ids),
                col(ClientSession.revoked) == False,  # noqa: E712
                col(ClientSession.refresh_expires_at) > now,
            )
            .distinct()
        ).all()
        return tuple(rows)


class SecurityRepairError(Exception):
    """Base class for audited repair failures."""


class UserNotFoundError(SecurityRepairError):
    """No user exists for the given id."""


class NotMismatchedError(SecurityRepairError):
    """The target row is already role/flag-consistent.

    This command exists to resolve exactly the mismatches the preflight
    reports; a consistent row that merely needs a different role is a plain
    role change and must go through the route-owned superuser-set transaction
    (``services.role_admin.change_user_authorization``), which carries the
    last-superuser and self-promotion protections this command deliberately
    does not reimplement.
    """


@dataclass(frozen=True)
class RepairResult:
    """Outcome of one audited repair (4.1).

    ``already_repaired`` is ``True`` when the row was already consistent with
    *intended_role* -- a safe repeat of a previous repair call; no generation
    bump or revocation is enqueued for an already-repaired row.
    """

    user_id: uuid.UUID
    previous_role: RoleType
    previous_is_superuser: bool
    intended_role: RoleType
    auth_generation: int
    revocation_enqueued: bool
    already_repaired: bool


def _load_repair_target(
    session: Session, *, user_id: uuid.UUID, actor: str, reason: str
) -> Tuple[RoleType, bool, int]:
    """Lock and read the target's raw role/flag/generation columns.

    Individual scalar columns only -- never ``select(User)`` -- because a
    mismatched row cannot be materialized as a validating ORM entity (4.1). The
    row lock serializes concurrent repairs of the same id.
    """
    current = session.exec(
        select(
            User.id,
            User.role,
            User.is_superuser,
            User.auth_generation,
        )
        .where(col(User.id) == user_id)
        .with_for_update()
    ).first()
    if current is None:
        logger.warning(
            "security.repair outcome=not_found actor=%s reason=%s user_id=%s",
            actor,
            reason,
            user_id,
        )
        raise UserNotFoundError(f"user {user_id} not found")
    _, previous_role, previous_is_superuser, current_generation = current
    return previous_role, previous_is_superuser, current_generation


def _resolve_already_consistent_row(
    *,
    user_id: uuid.UUID,
    actor: str,
    reason: str,
    previous_role: RoleType,
    previous_is_superuser: bool,
    intended_role: RoleType,
    current_generation: int,
) -> RepairResult:
    """Decide the outcome for a row that is already role/flag-consistent.

    Two cases, and the distinction is the whole point of this command's scope: a
    different role means the caller is trying to re-target a row that needs no
    repair (rejected -- that is an ordinary role change, which must go through
    the superuser-set transaction), while the same role is a safe repeat of a
    previous repair and returns without bumping the generation.
    """
    if previous_role != intended_role:
        logger.warning(
            "security.repair outcome=not_mismatched actor=%s reason=%s "
            "user_id=%s previous_role=%s intended_role=%s",
            actor,
            reason,
            user_id,
            previous_role,
            intended_role,
        )
        raise NotMismatchedError(
            f"user {user_id} is already role/flag-consistent under a "
            "different role; use the role-change transaction instead"
        )
    logger.info(
        "security.repair outcome=already_repaired actor=%s reason=%s "
        "user_id=%s intended_role=%s auth_generation=%d",
        actor,
        reason,
        user_id,
        intended_role,
        current_generation,
    )
    return RepairResult(
        user_id=user_id,
        previous_role=previous_role,
        previous_is_superuser=previous_is_superuser,
        intended_role=intended_role,
        auth_generation=current_generation,
        revocation_enqueued=False,
        already_repaired=True,
    )


def _apply_repair(
    session: Session,
    *,
    user_id: uuid.UUID,
    intended_role: RoleType,
    current_generation: int,
) -> int:
    """Write the repaired columns and propagate exactly like a role change.

    Bumps ``auth_generation``, revokes the target's sessions, and enqueues the
    same durable outbox effects the runtime role-change transaction does (3.5.1,
    3.5.2), then commits. Returns the new generation.
    """
    new_generation = next_generation(current_generation)
    session.exec(
        update(User)
        .where(col(User.id) == user_id)
        .values(
            role=intended_role,
            is_superuser=_derive_is_superuser(intended_role),
            auth_generation=new_generation,
        )
    )
    targets, _ = SessionController.capture_and_delete_user_sessions(session, user_id)
    OutboxController.enqueue_role_change_effects(
        session,
        user_id=user_id,
        auth_generation=new_generation,
        targets=targets,
    )
    session.commit()
    return new_generation


class SecurityRepairController:
    """Raw-column audited repair for one role/flag-mismatched row (4.1)."""

    @staticmethod
    def repair_user(
        session: Session,
        *,
        user_id: uuid.UUID,
        intended_role: RoleType,
        actor: str,
        reason: str,
    ) -> RepairResult:
        """Resolve *user_id*'s mismatch to *intended_role*, committing on success.

        Reads and writes individual columns only (never ``select(User)`` or a
        ``User`` write), locking the target row so a concurrent repair of the
        same id cannot race. Raises :class:`UserNotFoundError` when the id
        does not exist and :class:`NotMismatchedError` when the row is already
        consistent under a *different* role than *intended_role* (repair
        cannot re-target an already-repaired or never-mismatched row -- use
        the ordinary role-change transaction instead). A repeat call with the
        same *intended_role* the row already carries is a no-op
        (``already_repaired=True``). Every outcome is logged with the actor,
        reason, previous state, intended role, and completion status -- never
        email, token, JTI, or session-payload data.
        """
        previous_role, previous_is_superuser, current_generation = _load_repair_target(
            session, user_id=user_id, actor=actor, reason=reason
        )
        if previous_is_superuser == _derive_is_superuser(previous_role):
            return _resolve_already_consistent_row(
                user_id=user_id,
                actor=actor,
                reason=reason,
                previous_role=previous_role,
                previous_is_superuser=previous_is_superuser,
                intended_role=intended_role,
                current_generation=current_generation,
            )

        new_generation = _apply_repair(
            session,
            user_id=user_id,
            intended_role=intended_role,
            current_generation=current_generation,
        )
        logger.info(
            "security.repair outcome=repaired actor=%s reason=%s user_id=%s "
            "previous_role=%s intended_role=%s auth_generation=%d",
            actor,
            reason,
            user_id,
            previous_role,
            intended_role,
            new_generation,
        )
        return RepairResult(
            user_id=user_id,
            previous_role=previous_role,
            previous_is_superuser=previous_is_superuser,
            intended_role=intended_role,
            auth_generation=new_generation,
            revocation_enqueued=True,
            already_repaired=False,
        )
