"""Privileged-action audit routes for the consumer example (Phase 7).

Mirrors the issuer's `/security/audit-log` surface for the data this example
owns:

`GET /security/audit-log` is the read-only surface over the append-only
`app_privileged_action_audit` table: a superadmin sees every row, an admin sees
only rows it authored (`actor_user_id == self`, filtered server-side — never
from a client-supplied parameter), and every other role is denied with 403 by
the ADMIN-tier guard. No create/update/delete endpoint exists anywhere for this
table.

`POST /security/audit-log/purge` is the table's **only** removal path: a
superadmin-gated, horizon-bounded bulk delete of rows older than a chosen
retention window (`1w`/`1m`/`3m`/`6m`/`1y`), rejecting any window shorter than
the configured minimum-retention floor. It writes its own maintenance audit row,
which survives the purge that wrote it because it is timestamped after the
horizon.

Both routes are excluded from the OpenAPI schema and are JWT-only: they inherit
from the centralized `fastapi-m8` guards, so no role check is re-implemented
here (§3.3.1).
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import SQLModel

from fastapi_m8 import UserModel

from fastapi_full.app.audit import (
    AuditRetentionFloorError,
    RetentionWindow,
    purge_expired_audit_rows,
    read_audit_page,
)
from fastapi_full.app.deps import (
    SessionDep,
    get_current_active_admin,
    get_current_active_superuser,
)
from fastapi_full.app.ownership import is_canonical_superuser
from fastapi_full.db_models.privileged_action_audit import (
    PrivilegedActionAuditsPublic,
)

router = APIRouter(prefix="/security", tags=["security"])


@router.get(
    "/audit-log", include_in_schema=False, response_model=PrivilegedActionAuditsPublic
)
def read_audit_log(
    session: SessionDep,
    skip: int = 0,
    limit: int = 100,
    current_user: UserModel = Depends(get_current_active_admin),
) -> Any:
    """Read-only listing over the append-only privileged-action audit trail.

    A canonical superuser sees every row; any other ADMIN-or-above caller sees
    only rows it authored. USER, READER, and WRITER never reach this handler —
    `get_current_active_admin` already denies them with 403. In this example
    only a superadmin can mutate non-owned data, so an admin's view is
    legitimately empty.
    """
    rows, count = read_audit_page(
        session,
        actor_id=current_user.id,
        actor_is_canonical_superuser=is_canonical_superuser(current_user),
        skip=skip,
        limit=limit,
    )
    return PrivilegedActionAuditsPublic(data=rows, count=count)


class AuditPurgeRequest(SQLModel):
    """Request body for the superadmin retention-purge maintenance action."""

    window: RetentionWindow


class AuditPurgeResponse(SQLModel):
    """Response for the superadmin retention-purge maintenance action."""

    window: RetentionWindow
    removed: int


@router.post(
    "/audit-log/purge", include_in_schema=False, response_model=AuditPurgeResponse
)
def purge_audit_log(
    *,
    session: SessionDep,
    payload: AuditPurgeRequest,
    current_user: UserModel = Depends(get_current_active_superuser),
) -> Any:
    """Superadmin-only maintenance action: the audit table's sole removal path.

    Bulk-deletes rows older than the chosen retention *window*, never a targeted
    single row — the request carries no row identifier and the purge function
    accepts none. Rejects with `400` any window shorter than the configured
    minimum-retention floor (`AUDIT_PURGE_MIN_RETENTION_SECONDS`, default >= 90
    days); lowering that floor is an explicit operator config change. Deletes
    happen in batches (`FOR UPDATE SKIP LOCKED`), and the purge writes its own
    maintenance audit row (actor, window, rows removed), which survives because
    it is newer than the horizon it was computed from.
    """
    try:
        result = purge_expired_audit_rows(
            session,
            window=payload.window,
            actor_user_id=current_user.id,
            actor_role=current_user.role,
        )
    except AuditRetentionFloorError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return AuditPurgeResponse(window=result.window, removed=result.removed)
