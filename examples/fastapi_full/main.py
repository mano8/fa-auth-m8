"""fastapi_full — full-featured fastapi-m8 consumer service.

Demonstrates: DB session, metrics, health checks, auth deps, lifespan teardown.
All wiring is handled by ``create_app``; this file only imports and connects.
"""

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlmodel import select

from fastapi_m8 import (
    AppLifecycle,
    HealthCheckResult,
    HealthConfig,
    HealthStatus,
    create_app,
    make_scrape_credential_guard,
    render_metrics,
)

from .app.main import api_router as domain_router
from .core.config import settings
from .core.deps import auth, engine
from .core.events import make_lifespan_extras


async def check_db() -> HealthCheckResult:
    """Check database reachability."""
    try:
        with engine.session() as s:
            s.exec(select(1))
        return HealthCheckResult.from_bool("database", True)
    except Exception as exc:
        return HealthCheckResult(
            name="database", status=HealthStatus.FAIL, error=str(exc)
        )


def _register_metrics_endpoint(
    router: APIRouter, *, enabled: bool, credential: str | None = None
) -> None:
    """Expose Prometheus metrics under the API prefix when enabled.

    When ``credential`` is set, requests must present
    ``Authorization: Bearer <credential>`` (constant-time match) or receive
    ``401``. When unset the network boundary (internal entrypoint) is the sole
    control.
    """
    if not enabled:
        return

    guard = make_scrape_credential_guard(credential)

    @router.get("/metrics", include_in_schema=False, dependencies=[Depends(guard)])
    def metrics_endpoint() -> Response:
        data, content_type = render_metrics()
        return Response(content=data, media_type=content_type)


api_router = APIRouter(prefix=settings.API_PREFIX)
api_router.include_router(domain_router)

_cred = settings.METRICS_SCRAPE_CREDENTIAL
_register_metrics_endpoint(
    api_router,
    enabled=settings.METRICS_ENABLED,
    credential=_cred.get_secret_value() if _cred else None,
)


app = create_app(
    settings,
    api_router,
    service_name=settings.PROJECT_NAME,
    health=HealthConfig(checks=[check_db]),
    lifecycle=AppLifecycle(
        auth_deps=auth,
        db_engine=engine,
        lifespan_extras=make_lifespan_extras(settings, auth),
    ),
)
