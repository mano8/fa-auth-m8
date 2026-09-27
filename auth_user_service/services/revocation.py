"""Account-wide revocation shared by every authorization-state mutation.

A role or activation change, an email change, and a password mutation all end
the same way: the user's ``auth_generation`` is bumped, every session row is
deleted, and the Redis blacklist + user-wide v2 event are enqueued as durable
outbox rows in the caller's transaction (3.5.1, 3.5.2). The caller owns the
commit, then counts the enqueued effects.

This module depends only on the generation, session, and outbox primitives, so
both the route-owned superuser-set transaction (``services.role_admin``) and
the password mutation service (``services.password``) can compose it without an
import cycle.
"""

from sqlmodel import Session

from auth_user_service.db_models.outbox import (
    EFFECT_BLACKLIST,
    EFFECT_PUBLISH,
    RevocationOutbox,
)
from auth_user_service.db_models.users import User
from auth_user_service.services import outbox_metrics
from auth_user_service.services.client_sessions import (
    RevocationTarget,
    SessionController,
)
from auth_user_service.services.generation import GenerationController
from auth_user_service.services.outbox import OutboxController


def record_enqueued_metrics(rows: list[RevocationOutbox]) -> None:
    """Count the enqueued effects by type after the transaction commits."""
    blacklist = sum(1 for row in rows if row.effect_type == EFFECT_BLACKLIST)
    outbox_metrics.record_enqueued(EFFECT_BLACKLIST, blacklist)
    outbox_metrics.record_enqueued(EFFECT_PUBLISH, len(rows) - blacklist)


def revoke_and_enqueue_authorization_change(
    session: Session, db_user: User
) -> list[RevocationOutbox]:
    """Bump the generation, drop the user's sessions, and enqueue the side effects.

    Records the Redis blacklist + user-wide v2 event as durable outbox rows
    committed atomically with the DB revocation; a post-commit worker drains them
    (3.5.2). This replaces the best-effort post-commit push on the role-change
    path — the database delete is already authoritative (3.5.4).
    """
    new_generation = GenerationController.bump_user_generation(db_user)
    targets: list[RevocationTarget]
    targets, _ = SessionController.capture_and_delete_user_sessions(session, db_user.id)
    return OutboxController.enqueue_role_change_effects(
        session,
        user_id=db_user.id,
        auth_generation=new_generation,
        targets=targets,
    )
