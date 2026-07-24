"""Security-harness canary and privileged-action audit routes (3.9, Phase 7).

`GET /security/superuser-probe` exists exclusively as the non-destructive,
non-disclosing authorization canary consumed by the shared
`security-tests-m8` live harness. Forging a canonical
(`is_superuser=True`, `role="SUPERADMIN"`) token and sending it to a
PII-returning or mutating route would prove acceptance but also disclose data
or mutate state on a signature-verification regression; this route proves the
same thing — the canonical superuser guard rejected/accepted the token — with
no user query and no mutation.

`GET /security/audit-log` is the read-only surface over the append-only
`privileged_action_audit` table (Phase 7): a superadmin sees every row, an
admin sees only rows it authored (`actor_user_id == self`, filtered
server-side — never from a client-supplied parameter), and every other role
is denied with 403. No create/update/delete endpoint exists anywhere for this
table.

`POST /security/audit-log/purge` is the table's **only** removal path (Phase
7): a superadmin-gated, horizon-bounded bulk delete of rows older than a
chosen retention window (`1w`/`1m`/`3m`/`6m`/`1y`), rejecting any window
shorter than the configured minimum-retention floor. It writes its own
maintenance audit row, which survives the purge that wrote it because it is
timestamped after the horizon.
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import SQLModel, col, func, select

from auth_user_service.core.client import (
    AuditLogRateLimiter,
    AuditPurgeRateLimiter,
    SuperuserProbeRateLimiter,
)
from auth_user_service.core.config import settings
from auth_user_service.core.deps import (
    RedisDep,
    SessionDep,
    get_current_active_admin,
    get_current_active_superuser,
)
from auth_user_service.db_models.privileged_action_audit import (
    PrivilegedActionAudit,
    PrivilegedActionAuditsPublic,
)
from auth_user_service.services.audit import (
    AuditRetentionFloorError,
    RetentionWindow,
    purge_expired_audit_rows,
)
from auth_sdk_m8.authorization import has_superuser_privileges
from auth_sdk_m8.observability.metrics import get as _get_metrics
from auth_sdk_m8.schemas.user import UserModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/security", tags=["security"])


def _enforce_probe_rate_limit(redis: RedisDep, user_id: str) -> None:
    """Check and enforce the probe rate limit. Raises 429 or 503 as appropriate."""
    if redis is not None:
        if not SuperuserProbeRateLimiter(redis).is_allowed(user_id):
            logger.warning("event=security.superuser_probe.rate_limited")
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Try again later.",
            )
        return
    _mode = settings.effective_failure_mode("rate_limit")
    _m = _get_metrics()
    if _m and _m.degraded_decision_total:
        _m.degraded_decision_total.labels(
            control="rate_limit", mode=_mode, reason="redis_unavailable"
        ).inc()
    if _mode == "fail_closed":
        raise HTTPException(
            status_code=503,
            detail="Rate limiting service temporarily unavailable",
        )


@router.get("/superuser-probe", include_in_schema=False)
def superuser_probe(
    redis: RedisDep,
    current_user: UserModel = Depends(get_current_active_superuser),
) -> dict[str, bool]:
    """Non-disclosing superuser-authorization canary.

    JWT-only (inherited from `get_current_active_superuser` -> `CurrentUser`,
    which never accepts an API key), excluded from the OpenAPI schema, rate
    limited, and performs no user listing, no query of user data, and no
    mutation. Returns only ``{"authorized": true}``.
    """
    _enforce_probe_rate_limit(redis, str(current_user.id))
    return {"authorized": True}


def _enforce_audit_log_rate_limit(redis: RedisDep, user_id: str) -> None:
    """Check and enforce the audit-log read rate limit. Raises 429 or 503."""
    if redis is not None:
        if not AuditLogRateLimiter(redis).is_allowed(user_id):
            logger.warning("event=security.audit_log.rate_limited")
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Try again later.",
            )
        return
    _mode = settings.effective_failure_mode("rate_limit")
    _m = _get_metrics()
    if _m and _m.degraded_decision_total:
        _m.degraded_decision_total.labels(
            control="rate_limit", mode=_mode, reason="redis_unavailable"
        ).inc()
    if _mode == "fail_closed":
        raise HTTPException(
            status_code=503,
            detail="Rate limiting service temporarily unavailable",
        )


@router.get(
    "/audit-log", include_in_schema=False, response_model=PrivilegedActionAuditsPublic
)
def read_audit_log(
    session: SessionDep,
    redis: RedisDep,
    skip: int = 0,
    limit: int = 100,
    current_user: UserModel = Depends(get_current_active_admin),
) -> Any:
    """Read-only listing over the append-only privileged-action audit trail.

    Superadmin (canonical dual-evidence predicate) sees every row; any other
    ADMIN-or-above caller sees only rows it authored — the filter is applied
    server-side against the authenticated principal's id, never against a
    client-supplied identifier, so an admin cannot widen its own view. USER,
    READER, and WRITER never reach this dependency (`get_current_active_admin`
    already denies them with 403). Excluded from the OpenAPI schema and rate
    limited like the superuser probe. No PII beyond the ids already recorded
    on each audit row (no password hash, no key material — see the model's
    secret non-exposure invariant).
    """
    _enforce_audit_log_rate_limit(redis, str(current_user.id))

    statement = select(PrivilegedActionAudit)
    count_statement = select(func.count()).select_from(PrivilegedActionAudit)

    if not has_superuser_privileges(current_user.role, current_user.is_superuser):
        statement = statement.where(
            col(PrivilegedActionAudit.actor_user_id) == current_user.id
        )
        count_statement = count_statement.where(
            col(PrivilegedActionAudit.actor_user_id) == current_user.id
        )

    count = session.exec(count_statement).one()
    statement = statement.order_by(col(PrivilegedActionAudit.created_at).desc())
    rows = session.exec(statement.offset(skip).limit(limit)).all()

    return PrivilegedActionAuditsPublic(data=rows, count=count)


class AuditPurgeRequest(SQLModel):
    """Request body for the superadmin retention-purge maintenance action."""

    window: RetentionWindow


class AuditPurgeResponse(SQLModel):
    """Response for the superadmin retention-purge maintenance action."""

    window: RetentionWindow
    removed: int


def _enforce_audit_purge_rate_limit(redis: RedisDep, user_id: str) -> None:
    """Check and enforce the audit-purge rate limit. Raises 429 or 503."""
    if redis is not None:
        if not AuditPurgeRateLimiter(redis).is_allowed(user_id):
            logger.warning("event=security.audit_purge.rate_limited")
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Try again later.",
            )
        return
    _mode = settings.effective_failure_mode("rate_limit")
    _m = _get_metrics()
    if _m and _m.degraded_decision_total:
        _m.degraded_decision_total.labels(
            control="rate_limit", mode=_mode, reason="redis_unavailable"
        ).inc()
    if _mode == "fail_closed":
        raise HTTPException(
            status_code=503,
            detail="Rate limiting service temporarily unavailable",
        )


@router.post(
    "/audit-log/purge", include_in_schema=False, response_model=AuditPurgeResponse
)
def purge_audit_log(
    *,
    session: SessionDep,
    redis: RedisDep,
    payload: AuditPurgeRequest,
    current_user: UserModel = Depends(get_current_active_superuser),
) -> Any:
    """Superadmin-only maintenance action: the audit table's sole removal path.

    Bulk-deletes rows older than the chosen retention *window*, never a
    targeted single row. Rejects with `400` any window shorter than the
    configured minimum-retention floor (`AUDIT_PURGE_MIN_RETENTION_SECONDS`,
    default >= 90 days) — lowering that floor is an explicit operator config
    change, never a per-call parameter. Deletes happen in batches (`FOR UPDATE
    SKIP LOCKED`), and the purge writes its own maintenance audit row
    (actor, window, rows removed) in the same call, which survives because it
    is newer than the horizon it was computed from (mirrors the tombstone
    retention-horizon + guarded-cleanup pattern, 3.5.1). JWT-only (inherited
    from `get_current_active_superuser`), excluded from the OpenAPI schema,
    and rate limited.
    """
    _enforce_audit_purge_rate_limit(redis, str(current_user.id))

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
