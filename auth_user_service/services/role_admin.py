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
7. Bump ``security_policy.revision`` and commit once.

The durable transactional outbox (step 7 of 3.5) is a later plan item; until it
lands the post-commit Redis blacklist + user-wide event stays the best-effort
accelerator, and the database delete is the authoritative revocation (3.5.4).
"""

from datetime import datetime, timezone
from typing import Optional

from redis import Redis
from sqlmodel import Session, col, select

from auth_sdk_m8.authorization import has_minimum_role, has_superuser_privileges
from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.db_models.security_policy import (
    SUPERUSER_SET_POLICY_KEY,
    SecurityPolicy,
)
from auth_user_service.db_models.users import User, UserUpdate
from auth_user_service.services.api_keys import ApiKeyService
from auth_user_service.services.client_sessions import (
    RevocationTarget,
    SessionController,
)
from auth_user_service.services.generation import GenerationController
from auth_user_service.services.users import UserController, _derive_is_superuser


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


def change_user_authorization(
    *,
    session: Session,
    actor_id: object,
    db_user: User,
    user_in: UserUpdate,
    redis: Optional[Redis] = None,
) -> User:
    """Apply an admin user update as the route-owned superuser-set transaction.

    Handles role and/or ``is_active`` changes (plus any allowlisted profile
    fields) atomically: the last-superuser invariant and the role-administration
    matrix are enforced under the lock, the generation is bumped and sessions
    revoked on any authorization transition, and the owner's API keys are revoked
    on deactivation — all committed once. A pure profile update takes no lock and
    revokes nothing. Returns the refreshed user.
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

    targets: list[RevocationTarget] = []
    if authorization_changed:
        GenerationController.bump_user_generation(db_user)
        targets, _ = SessionController.capture_and_delete_user_sessions(
            session, db_user.id
        )
    if deactivated:
        ApiKeyService.revoke_all_user_keys_in_tx(session, db_user.id)

    session.add(db_user)
    if policy is not None and authorization_changed:
        _bump_policy_revision(policy)
    session.commit()
    session.refresh(db_user)

    if authorization_changed:
        SessionController.apply_post_commit_revocation(targets, db_user.id, redis)
    return db_user


def delete_user_account(
    *,
    session: Session,
    actor_id: object,  # noqa: ARG001 - reserved for cross-domain/audit checks
    db_user: User,
) -> None:
    """Hard-delete a user as the route-owned superuser-set transaction (3.5.3).

    Acquires the lock, enforces the last-superuser invariant, writes the durable
    deletion tombstone, revokes the user's sessions, deletes the row (cascading
    its API keys and remaining sessions), bumps the policy revision, and commits
    once. Self-deletion is permitted subject only to the last-superuser rule
    (3.10); the durable tombstone makes every token ever minted for the subject
    revoked (3.5.1).
    """
    policy = acquire_superuser_set_lock(session)
    _lock_user_row(session, db_user)
    if is_active_canonical_superuser(db_user):
        if count_active_canonical_superusers(session, exclude_user_id=db_user.id) == 0:
            raise LastSuperuserError("last_superuser_required")

    GenerationController.write_deletion_tombstone(session=session, user=db_user)
    SessionController.capture_and_delete_user_sessions(session, db_user.id)
    session.delete(db_user)
    _bump_policy_revision(policy)
    session.commit()
