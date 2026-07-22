"""Security-harness canary routes (3.9).

`GET /security/superuser-probe` exists exclusively as the non-destructive,
non-disclosing authorization canary consumed by the shared
`security-tests-m8` live harness. Forging a canonical
(`is_superuser=True`, `role="SUPERADMIN"`) token and sending it to a
PII-returning or mutating route would prove acceptance but also disclose data
or mutate state on a signature-verification regression; this route proves the
same thing — the canonical superuser guard rejected/accepted the token — with
no user query and no mutation.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException

from auth_user_service.core.client import SuperuserProbeRateLimiter
from auth_user_service.core.config import settings
from auth_user_service.core.deps import RedisDep, get_current_active_superuser
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
