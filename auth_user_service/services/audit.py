"""Transaction-bound privileged-action recorder (Phase 7 audit trail).

:func:`record_privileged_action` writes **exactly one**
:class:`~auth_user_service.db_models.privileged_action_audit.PrivilegedActionAudit`
row **in the caller's session/transaction**, so an audited mutation can never
commit without its audit row (outbox discipline, 3.5.2). It never commits — the
caller owns the commit boundary — and it flushes the pending INSERT so the row
participates in exactly the same unit of work as the mutation it describes: if
the mutation rolls back, the audit row rolls back with it; if the mutation
commits, the audit row commits with it.

Two invariants the recorder enforces by contract (the caller must honour them):

- ``actor_role`` is taken from the **authenticated principal**, never from
  client input — callers pass ``current_user.role``.
- For a **delete**, the caller captures ``row_pk``/``target_owner_id`` **before**
  the row is removed and passes the captured values here, so the forensic record
  survives the deletion (the audit table has no foreign key to the target, 3.5.1).

The table is append-only: this module offers only a create path — no update and
no targeted single-row delete exist anywhere (schema-enforced by the Expand
migration; the sole deletion is the horizon-bounded superadmin retention purge).
"""

import uuid
from typing import Optional, Union

from sqlmodel import Session

from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)


def _coerce_actor_id(actor_user_id: Union[uuid.UUID, str]) -> uuid.UUID:
    """Normalize the principal's id (a JWT ``sub`` string or UUID) to ``uuid.UUID``."""
    if isinstance(actor_user_id, uuid.UUID):
        return actor_user_id
    return uuid.UUID(str(actor_user_id))


def record_privileged_action(
    session: Session,
    *,
    actor_user_id: Union[uuid.UUID, str],
    actor_role: RoleType,
    action: AuditAction,
    table_name: str,
    row_pk: Union[uuid.UUID, str, int],
    target_owner_id: Optional[Union[uuid.UUID, str]] = None,
) -> PrivilegedActionAudit:
    """Append one audit row for a privileged mutation, in the caller's transaction.

    Args:
        session: The **same** DB session that owns the audited mutation; the row
            is added and flushed here but committed by the caller.
        actor_user_id: Id of the authenticated privileged actor (from the JWT).
        actor_role: The actor's role snapshot, taken from the authenticated
            principal — never from client input.
        action: ``add`` / ``edit`` / ``delete`` (:class:`AuditAction`).
        table_name: Canonical **prefixed** table name of the mutated row.
        row_pk: Primary key (or, for a user-wide bulk revocation, the owning key)
            of the mutated row(s); stored as text so int and UUID PKs share it.
        target_owner_id: Owner id of the mutated row, or ``None`` when the target
            has no owner. For a delete this must be captured before removal.

    Returns:
        The persisted-in-transaction :class:`PrivilegedActionAudit` row.
    """
    row = PrivilegedActionAudit(
        actor_user_id=_coerce_actor_id(actor_user_id),
        actor_role=actor_role,
        action=action,
        table_name=table_name,
        row_pk=str(row_pk),
        target_owner_id=None if target_owner_id is None else str(target_owner_id),
    )
    session.add(row)
    session.flush()
    return row
