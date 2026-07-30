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

The table is append-only: this module offers only a create path plus one
horizon-bounded bulk-delete path — no update and no targeted single-row delete
exist anywhere. :func:`purge_expired_audit_rows` is that sole deletion path: a
superadmin-gated, floor-enforced, batched purge of rows older than a chosen
retention window (schema-level enforcement of the write-once/no-targeted-delete
contract is the separate Expand migration).
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Final, Optional, Union

import sqlalchemy as sa
from sqlmodel import Session, col, select

from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.core.config import settings
from auth_user_service.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)

_logger = logging.getLogger(__name__)

# Dialect names (per ``Session.get_bind().dialect.name``) whose Expand
# migration installs the ``BEFORE DELETE`` guard trigger (4.6: the real-dialect
# matrix is Postgres/MySQL/MariaDB; MariaDB shares the ``mysql`` dialect name
# via the ``mysql+pymysql`` driver family). SQLite (unit-test surrogate only,
# 4.6) never runs the migration and carries no trigger, so the authorization
# calls below are a no-op there.
_PURGE_GUARDED_DIALECTS: Final[frozenset[str]] = frozenset({"postgresql", "mysql"})


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


class RetentionWindow(str, Enum):
    """Selectable retention windows for the superadmin audit retention purge.

    The audit trail's only removal path (Phase 7): a superadmin chooses one of
    these fixed windows and every row older than it is bulk-deleted, subject to
    the configured minimum-retention floor (:func:`purge_expired_audit_rows`).
    """

    ONE_WEEK = "1w"
    ONE_MONTH = "1m"
    THREE_MONTHS = "3m"
    SIX_MONTHS = "6m"
    ONE_YEAR = "1y"


_WINDOW_SECONDS: Final[dict[RetentionWindow, int]] = {
    RetentionWindow.ONE_WEEK: 7 * 86400,
    RetentionWindow.ONE_MONTH: 30 * 86400,
    RetentionWindow.THREE_MONTHS: 90 * 86400,
    RetentionWindow.SIX_MONTHS: 180 * 86400,
    RetentionWindow.ONE_YEAR: 365 * 86400,
}


class AuditRetentionFloorError(ValueError):
    """Raised when the requested window is below the configured retention floor.

    The floor (default >= 90 days, ``AUDIT_PURGE_MIN_RETENTION_SECONDS``) is a
    deployment-level setting, not a per-call parameter: shortening it below the
    default is an explicit operator config opt-in, never something a caller of
    the purge action can request directly.
    """


class AuditPurgeStalledError(RuntimeError):
    """Raised when the purge loop selects the same rows twice in a row (G8-10).

    The loop's only progress evidence is the claimed batch actually shrinking
    or emptying between iterations; if a delete is silently suppressed (e.g. a
    ``BEFORE DELETE`` trigger returning ``NULL``, the exact PostgreSQL defect
    this plan already found and fixed once), the same eligible rows would
    otherwise be re-selected forever, holding a database session open
    indefinitely. This guard is independent of that specific defect's fix.
    """


@dataclass(frozen=True)
class AuditPurgeResult:
    """Outcome of one retention-purge run."""

    window: RetentionWindow
    removed: int


def _as_aware_utc(value: datetime) -> datetime:
    """Normalise a possibly-naive timestamp to timezone-aware UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _dialect_name(session: Session) -> str:
    bind = session.get_bind()
    return bind.dialect.name


def _set_purge_delete_authorized(
    session: Session, dialect: str, *, active: bool
) -> None:
    """Toggle the transaction/session-local flag the Expand migration's
    ``BEFORE DELETE`` guard trigger checks (schema-level enforcement of the
    no-targeted-delete contract, 4.6). Only this function ever sets it, so a
    raw/ad-hoc ``DELETE`` against the audit table is rejected by the trigger
    on every guarded dialect.

    PostgreSQL's ``set_config(..., true)`` is transaction-local and resets
    itself at commit/rollback, so clearing it explicitly is only required for
    MySQL/MariaDB, whose session variables (``@audit_purge_active``) persist
    on the pooled connection past the transaction boundary.
    """
    if dialect == "postgresql":
        session.execute(
            sa.text("SELECT set_config('audit.purge_active', :value, true)"),
            {"value": "true" if active else "false"},
        )
    elif dialect == "mysql":
        session.execute(
            sa.text("SET @audit_purge_active = :value"),
            {"value": 1 if active else None},
        )


def purge_expired_audit_rows(
    session: Session,
    *,
    window: RetentionWindow,
    actor_user_id: Union[uuid.UUID, str],
    actor_role: RoleType,
    batch_size: Optional[int] = None,
    now: Optional[datetime] = None,
) -> AuditPurgeResult:
    """Bulk-delete audit rows older than *window*; the sole removal path (3.5.1).

    Enforces the configured minimum-retention floor
    (``AUDIT_PURGE_MIN_RETENTION_SECONDS``) before touching any row: a *window*
    shorter than the floor raises :class:`AuditRetentionFloorError` and deletes
    nothing. Otherwise every row older than ``now - window`` is removed in
    ``AUDIT_PURGE_BATCH_SIZE``-row batches claimed with ``FOR UPDATE SKIP
    LOCKED`` (mirroring the outbox worker's batching), each batch committed
    before the next is claimed, so a large purge never holds one long-lived
    lock over the table.

    There is deliberately no row-id/target parameter — the horizon is the only
    selector, so this can never become a targeted single-row delete.

    Once the sweep completes, the purge writes **its own** maintenance audit
    row via :func:`record_privileged_action` (actor, action, and the window
    plus removed-row count packed into ``row_pk`` — the model has no dedicated
    fields for those, and ``row_pk`` is free text). That row is timestamped
    *now* — always newer than the horizon it was just computed from — so it
    survives this and every subsequent purge (mirrors the tombstone
    retention-horizon pattern, 3.5.1).

    Args:
        session: DB session; each batch commit is on this session.
        window: The chosen retention window.
        actor_user_id: Id of the authenticated superadmin performing the purge.
        actor_role: The actor's role snapshot, from the authenticated principal.
        batch_size: Rows per delete batch; defaults to
            ``settings.AUDIT_PURGE_BATCH_SIZE``.
        now: Override for the current time (tests only); defaults to the
            actual current UTC time.

    Returns:
        :class:`AuditPurgeResult` with the window and the total rows removed.

    Raises:
        AuditRetentionFloorError: *window* is shorter than the configured floor.
    """
    window_seconds = _WINDOW_SECONDS[window]
    floor_seconds = settings.AUDIT_PURGE_MIN_RETENTION_SECONDS
    if window_seconds < floor_seconds:
        raise AuditRetentionFloorError(
            f"retention window {window.value!r} ({window_seconds}s) is below "
            f"the configured minimum-retention floor ({floor_seconds}s); "
            "lowering the floor requires an explicit operator config change"
        )

    batch = batch_size or settings.AUDIT_PURGE_BATCH_SIZE
    current = _as_aware_utc(now or datetime.now(timezone.utc))
    horizon = current - timedelta(seconds=window_seconds)
    dialect = _dialect_name(session)
    guarded = dialect in _PURGE_GUARDED_DIALECTS

    removed = 0
    previous_ids: Optional[frozenset] = None
    while True:
        rows = session.exec(
            select(PrivilegedActionAudit)
            .where(col(PrivilegedActionAudit.created_at) < horizon)
            .order_by(col(PrivilegedActionAudit.created_at))
            .limit(batch)
            .with_for_update(skip_locked=True)
        ).all()
        if not rows:
            break
        ids = frozenset(row.id for row in rows)
        if previous_ids is not None and ids == previous_ids:
            raise AuditPurgeStalledError(
                "audit purge made no progress: the same "
                f"{len(ids)} row(s) were re-selected after a commit — deletes "
                "are being silently suppressed"
            )
        if guarded:
            _set_purge_delete_authorized(session, dialect, active=True)
        for row in rows:
            session.delete(row)
        session.commit()
        if guarded:
            _set_purge_delete_authorized(session, dialect, active=False)
        removed += len(rows)
        if len(rows) < batch:
            break
        previous_ids = ids

    record_privileged_action(
        session,
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        action=AuditAction.DELETE,
        table_name=PrivilegedActionAudit.__tablename__,
        row_pk=f"retention_purge:window={window.value}:removed={removed}",
        target_owner_id=None,
    )
    session.commit()
    return AuditPurgeResult(window=window, removed=removed)
