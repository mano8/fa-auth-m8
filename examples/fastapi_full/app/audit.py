"""Transaction-bound privileged-action recorder for the consumer example (Phase 7).

The consumer half of the issuer's audit contract, kept deliberately identical in
shape so a service that copies this example inherits the same guarantees.

:func:`record_privileged_action` writes **exactly one**
:class:`~fastapi_full.db_models.privileged_action_audit.PrivilegedActionAudit`
row **in the caller's session/transaction**, so a superadmin's cross-owner
category mutation can never commit without its audit row. It never commits — the
route owns the commit boundary — and it flushes the pending INSERT so the row
participates in exactly the same unit of work as the mutation it describes: if
the mutation rolls back, the audit row rolls back with it; if the mutation
commits, the audit row commits with it.

Two invariants the recorder enforces by contract (the caller must honour them):

- ``actor_role`` is taken from the **authenticated principal**, never from client
  input — callers pass ``current_user.role``.
- For a **delete**, the caller captures ``row_pk``/``target_owner_id`` **before**
  the row is removed and passes the captured values here, so the forensic record
  survives the deletion (the audit table has no foreign key to the target).

The table is append-only: this module offers only a create path plus one
horizon-bounded bulk-delete path — no update and no targeted single-row delete
exist anywhere. :func:`purge_expired_audit_rows` is that sole deletion path: a
superadmin-gated, floor-enforced, batched purge of rows older than a chosen
retention window, matched by the Expand migration's schema-level guard triggers.

:func:`read_audit_page` owns the read scope (superadmin-all / admin-own) so the
rule is decided from the authenticated principal in one testable place rather
than in a route body.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Final, Optional, Union

import sqlalchemy as sa
from sqlmodel import Session, col, func, select

from fastapi_m8 import UserModel

from fastapi_full.app.ownership import as_owner_id, is_owned_by
from fastapi_full.core.config import settings
from fastapi_full.db_models.categories import Category
from fastapi_full.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)

# Dialect names (per ``Session.get_bind().dialect.name``) whose Expand migration
# installs the ``BEFORE DELETE`` guard trigger: the certified engines are
# Postgres, MySQL, and MariaDB (MariaDB shares the ``mysql`` dialect name via the
# ``mysql+pymysql`` driver family). SQLite is a unit-test surrogate only, never
# runs the migration and carries no trigger, so the authorization calls below are
# a no-op there.
_PURGE_GUARDED_DIALECTS: Final[frozenset[str]] = frozenset({"postgresql", "mysql"})


def _coerce_actor_id(actor_user_id: Union[uuid.UUID, str]) -> uuid.UUID:
    """Normalize the principal's id (a JWT ``sub`` string or UUID) to ``uuid.UUID``."""
    if isinstance(actor_user_id, uuid.UUID):
        return actor_user_id
    return uuid.UUID(str(actor_user_id))


def role_text(actor_role: object) -> str:
    """Return the stored text form of an authenticated principal's role.

    ``UserModel.role`` is a string enum, whose ``str()`` is the member
    repr rather than its value; the audit row stores the value.

    Args:
        actor_role: The principal's role, as carried on the validated token.

    Returns:
        The role's text value (e.g. ``"superadmin"``).
    """
    value = getattr(actor_role, "value", actor_role)
    return str(value)


def record_privileged_action(
    session: Session,
    *,
    actor_user_id: Union[uuid.UUID, str],
    actor_role: object,
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
        row_pk: Primary key of the mutated row; stored as text so int and UUID
            PKs share one column.
        target_owner_id: Owner id of the mutated row, or ``None`` when the target
            has no owner. For a delete this must be captured before removal.

    Returns:
        The persisted-in-transaction :class:`PrivilegedActionAudit` row.
    """
    row = PrivilegedActionAudit(
        actor_user_id=_coerce_actor_id(actor_user_id),
        actor_role=role_text(actor_role),
        action=action,
        table_name=table_name,
        row_pk=str(row_pk),
        target_owner_id=None if target_owner_id is None else str(target_owner_id),
    )
    session.add(row)
    session.flush()
    return row


def record_cross_owner_category_action(
    session: Session,
    *,
    actor: UserModel,
    action: AuditAction,
    row_pk: Union[int, str],
    target_owner_id: Union[uuid.UUID, str],
) -> Optional[PrivilegedActionAudit]:
    """Audit a category mutation, but only when the actor does not own the row.

    This is the single place that decides *whether* a category mutation is a
    privileged one: a mutation of the actor's own data is ordinary work and
    leaves no audit row, while every mutation of someone else's data is
    recorded. Only a canonical superuser can reach the second case — the routes
    refuse a cross-owner mutation to everyone else — so this is exactly the
    "superadmin mutation of non-owned data" the audit trail exists for.

    Args:
        session: The **same** DB session that owns the audited mutation.
        actor: The authenticated principal; supplies both the actor id and the
            role snapshot, so neither can come from client input.
        action: ``add`` / ``edit`` / ``delete``.
        row_pk: Primary key of the mutated category. For a delete, capture it
            before the row is removed.
        target_owner_id: Owner of the mutated category, as resolved for a create
            or as read off the persisted row. For a delete, capture it before
            the row is removed. Compared through
            :func:`~fastapi_full.app.ownership.is_owned_by`, so the text form the
            ``CHAR(36)`` column returns classifies the same as a ``uuid.UUID``.

    Returns:
        The written audit row, or ``None`` when the actor owns the row and
        nothing was recorded.
    """
    if is_owned_by(target_owner_id, actor.id):
        return None
    return record_privileged_action(
        session,
        actor_user_id=actor.id,
        actor_role=actor.role,
        action=action,
        table_name=str(Category.__tablename__),
        row_pk=row_pk,
        target_owner_id=as_owner_id(target_owner_id),
    )


def read_audit_page(
    session: Session,
    *,
    actor_id: uuid.UUID,
    actor_is_canonical_superuser: bool,
    skip: int = 0,
    limit: int = 100,
) -> tuple[list[PrivilegedActionAudit], int]:
    """Return one page of audit rows visible to the caller, newest first.

    The read scope is decided here, from the authenticated principal alone: a
    canonical superuser sees every row, and any other (ADMIN-or-above) caller
    sees only the rows it authored. The filter is applied server-side against
    *actor_id*, never against a client-supplied identifier, so an admin cannot
    widen its own view by asking.

    Args:
        session: DB session.
        actor_id: The authenticated principal's id.
        actor_is_canonical_superuser: Result of the dual-evidence superuser
            predicate for the caller.
        skip: Rows to skip.
        limit: Maximum rows to return.

    Returns:
        The visible page and the total number of rows visible to the caller.
    """
    statement = select(PrivilegedActionAudit)
    count_statement = select(func.count()).select_from(PrivilegedActionAudit)

    if not actor_is_canonical_superuser:
        statement = statement.where(
            col(PrivilegedActionAudit.actor_user_id) == actor_id
        )
        count_statement = count_statement.where(
            col(PrivilegedActionAudit.actor_user_id) == actor_id
        )

    count = session.exec(count_statement).one()
    statement = statement.order_by(col(PrivilegedActionAudit.created_at).desc())
    rows = list(session.exec(statement.offset(skip).limit(limit)).all())
    return rows, count


class RetentionWindow(str, Enum):
    """Selectable retention windows for the superadmin audit retention purge.

    The audit trail's only removal path: a superadmin chooses one of these fixed
    windows and every row older than it is bulk-deleted, subject to the
    configured minimum-retention floor (:func:`purge_expired_audit_rows`).
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
    """Raised when the purge loop selects the same rows twice in a row.

    Mirrors the issuer's
    :class:`~auth_user_service.services.audit.AuditPurgeStalledError` (P8-6):
    the loop's only progress evidence is the claimed batch actually shrinking
    or emptying between iterations; if a delete is silently suppressed (e.g. a
    ``BEFORE DELETE`` trigger returning ``NULL``), the same eligible rows would
    otherwise be re-selected forever, holding a database session open
    indefinitely.
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
    no-targeted-delete contract). Only this function ever sets it, so a raw or
    ad-hoc ``DELETE`` against the audit table is rejected by the database on
    every guarded dialect.

    PostgreSQL's ``set_config(..., true)`` is transaction-local and resets itself
    at commit/rollback, so clearing it explicitly is only required for
    MySQL/MariaDB, whose session variables (``@audit_purge_active``) persist on
    the pooled connection past the transaction boundary.
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


def _enforce_retention_floor(window: RetentionWindow) -> int:
    """Return *window* in seconds, rejecting anything below the configured floor.

    Checked before a single row is claimed, so a too-short window deletes nothing.
    """
    window_seconds = _WINDOW_SECONDS[window]
    floor_seconds = settings.AUDIT_PURGE_MIN_RETENTION_SECONDS
    if window_seconds < floor_seconds:
        raise AuditRetentionFloorError(
            f"retention window {window.value!r} ({window_seconds}s) is below "
            f"the configured minimum-retention floor ({floor_seconds}s); "
            "lowering the floor requires an explicit operator config change"
        )
    return window_seconds


def _claim_purge_batch(
    session: Session, *, horizon: datetime, batch: int
) -> list[PrivilegedActionAudit]:
    """Claim up to *batch* rows older than *horizon*, oldest first.

    ``FOR UPDATE SKIP LOCKED`` means a concurrent purge skips rows this one
    already holds rather than blocking on them.
    """
    return list(
        session.exec(
            select(PrivilegedActionAudit)
            .where(col(PrivilegedActionAudit.created_at) < horizon)
            .order_by(col(PrivilegedActionAudit.created_at))
            .limit(batch)
            .with_for_update(skip_locked=True)
        ).all()
    )


def _delete_claimed_batch(
    session: Session,
    rows: list[PrivilegedActionAudit],
    *,
    dialect: str,
    guarded: bool,
) -> None:
    """Delete one claimed batch and commit it.

    The schema-level guard flag is held only for the delete itself and cleared
    immediately after, so an ad-hoc ``DELETE`` on the same pooled connection is
    still rejected by the trigger.
    """
    if guarded:
        _set_purge_delete_authorized(session, dialect, active=True)
    for row in rows:
        session.delete(row)
    session.commit()
    if guarded:
        _set_purge_delete_authorized(session, dialect, active=False)


def _sweep_expired_rows(
    session: Session,
    *,
    horizon: datetime,
    batch: int,
    dialect: str,
    guarded: bool,
) -> int:
    """Batch-delete every row older than *horizon*; return the number removed.

    Each batch is committed before the next is claimed, so a large purge never
    holds one long-lived lock over the table. Re-selecting an identical id set
    after a commit means the deletes are being silently suppressed — that is a
    stall (:class:`AuditPurgeStalledError`), not an empty result, and detecting
    it is what stops this loop from spinning forever.
    """
    removed = 0
    previous_ids: Optional[frozenset] = None
    while True:
        rows = _claim_purge_batch(session, horizon=horizon, batch=batch)
        if not rows:
            break
        ids = frozenset(row.id for row in rows)
        if previous_ids is not None and ids == previous_ids:
            raise AuditPurgeStalledError(
                "audit purge made no progress: the same "
                f"{len(ids)} row(s) were re-selected after a commit — deletes "
                "are being silently suppressed"
            )
        _delete_claimed_batch(session, rows, dialect=dialect, guarded=guarded)
        removed += len(rows)
        if len(rows) < batch:
            break
        previous_ids = ids
    return removed


def purge_expired_audit_rows(
    session: Session,
    *,
    window: RetentionWindow,
    actor_user_id: Union[uuid.UUID, str],
    actor_role: object,
    batch_size: Optional[int] = None,
    now: Optional[datetime] = None,
) -> AuditPurgeResult:
    """Bulk-delete audit rows older than *window*; the sole removal path.

    Enforces the configured minimum-retention floor
    (``AUDIT_PURGE_MIN_RETENTION_SECONDS``) before touching any row: a *window*
    shorter than the floor raises :class:`AuditRetentionFloorError` and deletes
    nothing. Otherwise every row older than ``now - window`` is removed in
    ``AUDIT_PURGE_BATCH_SIZE``-row batches claimed with ``FOR UPDATE SKIP
    LOCKED``, each batch committed before the next is claimed, so a large purge
    never holds one long-lived lock over the table.

    There is deliberately no row-id/target parameter — the horizon is the only
    selector, so this can never become a targeted single-row delete.

    Once the sweep completes, the purge writes **its own** maintenance audit row
    via :func:`record_privileged_action` (actor, action, and the window plus
    removed-row count packed into ``row_pk`` — the model has no dedicated fields
    for those, and ``row_pk`` is free text). That row is timestamped *now* —
    always newer than the horizon it was just computed from — so it survives this
    and every subsequent purge.

    Args:
        session: DB session; each batch commit is on this session.
        window: The chosen retention window.
        actor_user_id: Id of the authenticated superadmin performing the purge.
        actor_role: The actor's role snapshot, from the authenticated principal.
        batch_size: Rows per delete batch; defaults to
            ``settings.AUDIT_PURGE_BATCH_SIZE``.
        now: Override for the current time (tests only); defaults to the actual
            current UTC time.

    Returns:
        :class:`AuditPurgeResult` with the window and the total rows removed.

    Raises:
        AuditRetentionFloorError: *window* is shorter than the configured floor.
    """
    window_seconds = _enforce_retention_floor(window)
    batch = batch_size or settings.AUDIT_PURGE_BATCH_SIZE
    current = _as_aware_utc(now or datetime.now(timezone.utc))
    horizon = current - timedelta(seconds=window_seconds)
    dialect = _dialect_name(session)

    removed = _sweep_expired_rows(
        session,
        horizon=horizon,
        batch=batch,
        dialect=dialect,
        guarded=dialect in _PURGE_GUARDED_DIALECTS,
    )

    record_privileged_action(
        session,
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        action=AuditAction.DELETE,
        table_name=str(PrivilegedActionAudit.__tablename__),
        row_pk=f"retention_purge:window={window.value}:removed={removed}",
        target_owner_id=None,
    )
    session.commit()
    return AuditPurgeResult(window=window, removed=removed)
