"""Health check endpoint."""

from typing import Any

from fastapi import APIRouter, Request
from sqlmodel import text

from auth_sdk_m8.security.guards import make_internal_token_authorizer
from auth_user_service.core.config import settings
from auth_user_service.core.deps import get_redis_client, get_redis_degraded_since
from auth_user_service.core.engine_sync import engine

router = APIRouter(prefix="/health", tags=["health"])


def _redis_status() -> tuple[bool, bool]:
    """Return (redis_ok, circuit_breaker_open)."""
    if not settings.requires_redis:
        return True, False
    ok = get_redis_client() is not None
    return ok, not ok


def _db_status() -> bool:
    """Return True when the database accepts a simple query."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def _degradation_modes() -> dict[str, str]:
    return {
        "rate_limit": settings.effective_failure_mode("rate_limit"),
        "refresh_validation": settings.effective_failure_mode("refresh_validation"),
        "session_write": settings.effective_failure_mode("session_write"),
        "access_revocation": settings.effective_failure_mode("access_revocation"),
    }


def _collect_health() -> dict[str, Any]:
    """Return the full health/infrastructure detail body.

    Useful for monitoring and for diagnosing silent degradation when TOKEN_MODE
    is ``stateful`` or ``hybrid`` but Redis is unavailable.
    """
    redis_ok, circuit_breaker_open = _redis_status()
    db_ok = _db_status()

    effective_mode = (
        "stateless_degraded"
        if settings.requires_redis and not redis_ok
        else settings.TOKEN_MODE
    )
    degraded_since = get_redis_degraded_since()

    return {
        "status": "ok" if (redis_ok and db_ok) else "degraded",
        "token_mode": settings.TOKEN_MODE,
        "effective_mode": effective_mode,
        "redis": "ok" if redis_ok else "unavailable",
        "circuit_breaker": "open" if circuit_breaker_open else "closed",
        "database": "ok" if db_ok else "unavailable",
        "revocation_available": redis_ok and settings.requires_redis,
        "rate_limiting_available": redis_ok and settings.requires_redis,
        "degraded_since": degraded_since.isoformat() if degraded_since else None,
        "degradation_modes": _degradation_modes(),
    }


@router.get("/", summary="Service health and infrastructure status")
def health_check(request: Request) -> dict[str, Any]:
    """Return service liveness, gating the infrastructure detail at the app layer.

    The ungated response is a **constant, dependency-independent liveness body** —
    always ``{"status": "ok"}``, identical whether Redis/DB are healthy or
    ``degraded`` (plan 9.4, Design B). It never reflects degradation, so a public
    caller cannot use it as a timing/state oracle for fail-open degradation; this
    is what makes the route safe to route over public HTTPS. Readiness /
    degradation detection becomes **credential-only**: the full infrastructure
    detail (token mode, Redis/DB reachability, degradation modes) is revealed only
    to internal callers presenting the dedicated ``HEALTH_DETAIL_CREDENTIAL`` via
    the ``X-Internal-Token`` header (plan 9.3). When ``HEALTH_DETAIL_CREDENTIAL``
    is unset the gate **fails closed** — no detail body is ever revealed
    regardless of any presented token. The guard lives here, in the app, so it
    survives a reverse-proxy swap; proxy route-hiding stays defense-in-depth.
    ``{API_PREFIX}/ping`` remains the dependency-free public liveness route.
    """
    credential = settings.HEALTH_DETAIL_CREDENTIAL
    if credential is not None:
        authorize = make_internal_token_authorizer(credential.get_secret_value())
        if authorize(request):
            return _collect_health()
    return {"status": "ok"}
