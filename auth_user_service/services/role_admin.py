"""Route-owned role/activation transaction, superuser-set lock, and the
centralized last-superuser predicate (3.5, 3.5.3, 3.10, 3.11).

Every mutation that can add an account to, or remove one from, the **active
canonical-superuser set** — role demotion, deactivation, and hard deletion,
including the self- variants — is serialized here through one transaction owner
so the invariant holds under real concurrency:

1. ``SELECT ... FOR UPDATE`` the singleton ``security_policy`` row — the
   portable lock that serializes superuser-set mutations on every supported
   engine (3.5.3; advisory locks are prohibited because MySQL/MariaDB lack
   ``pg_advisory_xact_lock``).
2. Lock the target user row ``FOR UPDATE`` (fixed order: policy → user →
   session/API-key rows → outbox; never reversed).
3. Count the active canonical superusers under the lock.
4. Enforce the last-superuser invariant (409 ``last_superuser_required``).
5. Apply the mutation with the server-derived flag and the ``auth_generation``
   increment (3.5.1).
6. Revoke the affected sessions in the same transaction; on **deactivation**
   revoke the owner's API keys too (3.11).
7. Enqueue the revocation side effects (Redis blacklist + user-wide v2 event) as
   durable outbox rows in the same transaction (3.5.2).
8. Bump ``security_policy.revision`` and commit once.

A post-commit :class:`~auth_user_service.services.outbox.OutboxWorker` drains the
outbox and applies the Redis blacklist + event publication with at-least-once
delivery; the database delete is already the authoritative revocation (3.5.4), so
the endpoint returns ``200`` with ``revocation_enqueued: true`` as soon as the
transaction commits, never implying downstream propagation has completed.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Session, col, select

from auth_sdk_m8.authorization import has_minimum_role, has_superuser_privileges
from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.db_models.outbox import (
    EFFECT_BLACKLIST,
    EFFECT_PUBLISH,
    RevocationOutbox,
)
from auth_user_service.db_models.privileged_action_audit import AuditAction
from auth_user_service.services.audit import record_privileged_action
from auth_user_service.db_models.security_policy import (
    SUPERUSER_SET_POLICY_KEY,
    SecurityPolicy,
)
from auth_user_service.db_models.users import User, UserUpdate
from auth_user_service.services import outbox_metrics
from auth_user_service.services.api_keys import ApiKeyService
from auth_user_service.services.client_sessions import (
    RevocationTarget,
    SessionController,
)
from auth_user_service.services.generation import GenerationController
from auth_user_service.services.outbox import OutboxController
from auth_user_service.services.users import UserController, _derive_is_superuser


@dataclass(frozen=True)
class AuthorizationChangeResult:
    """Outcome of a role/activation change (3.5.2 endpoint contract).

    Carries the refreshed user plus the two fields the role-change response must
    surface: the post-change ``auth_generation`` and whether revocation side
    effects were durably enqueued to the outbox. ``revocation_enqueued`` is
    ``False`` for a pure profile update (no authorization transition, nothing
    enqueued).
    """

    user: User
    auth_generation: int
    revocation_enqueued: bool


class RoleAdminError(Exception):
    """Base class for role-administration authorization failures."""


class LastSuperuserError(RoleAdminError):
    """An otherwise authorized mutation would remove the last active superuser.

    Mapped by the route to ``409 last_superuser_required`` (3.7).
    """


class SelfPromotionError(RoleAdminError):
    """An actor attempted to raise their own role. Always forbidden (3.10).

    Mapped by the route to ``403``.
    """


def is_active_canonical_superuser(user: User) -> bool:
    """The centralized "active canonical superuser" predicate (3.5.3).

    Defined once over fields that exist today — ``role == SUPERADMIN and
    is_superuser and is_active`` — and expressed through the shared dual-evidence
    SDK predicate so an inconsistent ``role``/``is_superuser`` pair is never
    counted as a superuser. Every last-superuser guard routes through this.
    """
    return has_superuser_privileges(user.role, user.is_superuser) and user.is_active


def _would_be_active_canonical_superuser(role: RoleType, is_active: bool) -> bool:
    """Whether the *intended* post-mutation state is an active canonical superuser."""
    return has_superuser_privileges(role, _derive_is_superuser(role)) and is_active


def count_active_canonical_superusers(
    session: Session, *, exclude_user_id: Optional[object] = None
) -> int:
    """Count active canonical superusers, optionally excluding one user id.

    Evaluated under the superuser-set lock so a concurrent transaction cannot
    change set membership between the count and the mutation (3.5.3).
    """
    stmt = select(User).where(
        col(User.role) == RoleType.SUPERADMIN,
        User.is_superuser == True,  # noqa: E712
        User.is_active == True,  # noqa: E712
    )
    if exclude_user_id is not None:
        stmt = stmt.where(col(User.id) != exclude_user_id)
    return len(session.exec(stmt).all())


def acquire_superuser_set_lock(session: Session) -> SecurityPolicy:
    """Acquire the portable superuser-set mutation lock (3.5.3, step 1).

    ``SELECT ... FOR UPDATE`` on the singleton ``security_policy`` row. In
    production the Expand migration seeds that row; this defensively seeds it if
    absent (first run / unit-test metadata schema) and re-locks it, so the lock
    is always held on return. On SQLite ``FOR UPDATE`` is a no-op — the real
    contention behavior is certified on the engine matrix (later plan item).
    """
    policy = session.exec(
        select(SecurityPolicy)
        .where(col(SecurityPolicy.policy_key) == SUPERUSER_SET_POLICY_KEY)
        .with_for_update()
    ).first()
    if policy is None:
        policy = SecurityPolicy(
            policy_key=SUPERUSER_SET_POLICY_KEY,
            revision=0,
            updated_at=datetime.now(timezone.utc),
        )
        session.add(policy)
        session.flush()
        policy = session.exec(
            select(SecurityPolicy)
            .where(col(SecurityPolicy.policy_key) == SUPERUSER_SET_POLICY_KEY)
            .with_for_update()
        ).first()
    return policy  # type: ignore[return-value]


def _bump_policy_revision(policy: SecurityPolicy) -> None:
    """Advance the monotonic set-mutation revision under the held lock."""
    policy.revision += 1
    policy.updated_at = datetime.now(timezone.utc)


def _is_promotion(previous_role: RoleType, intended_role: RoleType) -> bool:
    """Whether *intended_role* is strictly higher than *previous_role*."""
    return intended_role != previous_role and has_minimum_role(
        intended_role, previous_role
    )


def _lock_user_row(session: Session, user: User) -> None:
    """Lock the target user row ``FOR UPDATE`` (fixed order: policy → user)."""
    session.exec(select(User).where(col(User.id) == user.id).with_for_update()).first()


def _record_enqueued_metrics(rows: list[RevocationOutbox]) -> None:
    """Count the enqueued effects by type after the transaction commits."""
    blacklist = sum(1 for row in rows if row.effect_type == EFFECT_BLACKLIST)
    outbox_metrics.record_enqueued(EFFECT_BLACKLIST, blacklist)
    outbox_metrics.record_enqueued(EFFECT_PUBLISH, len(rows) - blacklist)


def change_user_authorization(
    *,
    session: Session,
    actor_id: object,
    actor_role: RoleType,
    db_user: User,
    user_in: UserUpdate,
) -> AuthorizationChangeResult:
    """Apply an admin user update as the route-owned superuser-set transaction.

    Handles role and/or ``is_active`` changes (plus any allowlisted profile
    fields) atomically: the last-superuser invariant and the role-administration
    matrix are enforced under the lock, the generation is bumped, sessions
    revoked, and the revocation side effects enqueued to the durable outbox on any
    authorization transition, and the owner's API keys are revoked on
    deactivation — all committed once. A pure profile update takes no lock and
    revokes nothing. Returns an :class:`AuthorizationChangeResult` carrying the
    refreshed user, its current generation, and whether revocation was enqueued.

    A single ``edit`` privileged-action audit row is written **in this
    transaction** for the mutated (non-owned) user record — ``actor_role`` comes
    from the authenticated principal, never client input — so the mutation can
    never commit without its forensic record (Phase 7).
    """
    fields = user_in.model_dump(exclude_unset=True)
    role_requested = fields.get("role") is not None
    active_requested = "is_active" in fields and fields["is_active"] is not None
    affects_set = role_requested or active_requested

    previous_role = db_user.role
    previous_active = db_user.is_active
    intended_role = fields["role"] if role_requested else previous_role
    intended_active = fields["is_active"] if active_requested else previous_active

    # Role-administration matrix: an actor may never raise their own role (3.10).
    if (
        role_requested
        and actor_id == db_user.id
        and _is_promotion(previous_role, intended_role)
    ):
        raise SelfPromotionError("self_promotion_forbidden")

    policy: Optional[SecurityPolicy] = None
    if affects_set:
        policy = acquire_superuser_set_lock(session)
        _lock_user_row(session, db_user)
        # Last-superuser invariant, evaluated under the lock (3.5.3).
        if is_active_canonical_superuser(db_user) and not (
            _would_be_active_canonical_superuser(intended_role, intended_active)
        ):
            if (
                count_active_canonical_superusers(session, exclude_user_id=db_user.id)
                == 0
            ):
                raise LastSuperuserError("last_superuser_required")

    outcome = UserController.apply_user_update(db_user=db_user, user_in=user_in)
    if active_requested:
        db_user.is_active = intended_active

    activation_changed = active_requested and intended_active != previous_active
    deactivated = active_requested and previous_active and not intended_active
    authorization_changed = outcome.role_changed or activation_changed

    enqueued: list[RevocationOutbox] = []
    if authorization_changed:
        new_generation = GenerationController.bump_user_generation(db_user)
        targets: list[RevocationTarget]
        targets, _ = SessionController.capture_and_delete_user_sessions(
            session, db_user.id
        )
        # Record the Redis blacklist + user-wide v2 event as durable outbox rows
        # committed atomically with the DB revocation; a post-commit worker drains
        # them (3.5.2). This replaces the best-effort post-commit push on the
        # role-change path — the database delete is already authoritative (3.5.4).
        enqueued = OutboxController.enqueue_role_change_effects(
            session,
            user_id=db_user.id,
            auth_generation=new_generation,
            targets=targets,
        )
    if deactivated:
        ApiKeyService.revoke_all_user_keys_in_tx(session, db_user.id)

    session.add(db_user)
    if policy is not None and authorization_changed:
        _bump_policy_revision(policy)
    # One durable edit audit row, atomic with the mutation (Phase 7). The actor's
    # role is the authenticated principal's, and the user is its own owner.
    record_privileged_action(
        session,
        actor_user_id=actor_id,  # type: ignore[arg-type]
        actor_role=actor_role,
        action=AuditAction.EDIT,
        table_name=User.__tablename__,
        row_pk=db_user.id,
        target_owner_id=db_user.id,
    )
    session.commit()
    session.refresh(db_user)

    if authorization_changed:
        _record_enqueued_metrics(enqueued)
    return AuthorizationChangeResult(
        user=db_user,
        auth_generation=db_user.auth_generation,
        revocation_enqueued=authorization_changed,
    )


def delete_user_account(
    *,
    session: Session,
    actor_id: object,
    actor_role: RoleType,
    db_user: User,
) -> None:
    """Hard-delete a user as the route-owned superuser-set transaction (3.5.3).

    Acquires the lock, enforces the last-superuser invariant, writes the durable
    deletion tombstone, revokes the user's sessions, deletes the row (cascading
    its API keys and remaining sessions), bumps the policy revision, and commits
    once. Self-deletion is permitted subject only to the last-superuser rule
    (3.10); the durable tombstone makes every token ever minted for the subject
    revoked (3.5.1).

    A single ``delete`` privileged-action audit row is written **in this
    transaction**, capturing the target's id/owner **before** the row is removed
    (the audit has no FK to the user, so it outlives the deletion, 3.5.1). The
    ``actor_role`` comes from the authenticated principal, never client input.
    """
    policy = acquire_superuser_set_lock(session)
    _lock_user_row(session, db_user)
    if is_active_canonical_superuser(db_user):
        if count_active_canonical_superusers(session, exclude_user_id=db_user.id) == 0:
            raise LastSuperuserError("last_superuser_required")

    # Capture the target identifiers before the row is removed, then record the
    # audit row in the same transaction as the delete (Phase 7).
    record_privileged_action(
        session,
        actor_user_id=actor_id,  # type: ignore[arg-type]
        actor_role=actor_role,
        action=AuditAction.DELETE,
        table_name=User.__tablename__,
        row_pk=db_user.id,
        target_owner_id=db_user.id,
    )
    GenerationController.write_deletion_tombstone(session=session, user=db_user)
    SessionController.capture_and_delete_user_sessions(session, db_user.id)
    session.delete(db_user)
    _bump_policy_revision(policy)
    session.commit()
