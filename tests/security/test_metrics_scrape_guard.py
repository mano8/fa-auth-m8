"""Phase 1.4 — fa-auth-m8 ``/metrics`` scrape-credential guard.

fa-auth-m8 builds its own ``FastAPI()`` app, so it wires the shared
``auth_sdk_m8.security.guards.make_scrape_credential_guard`` onto the
``{API_PREFIX}/metrics`` route itself (main.py). These tests lock the intended
posture:

- Metrics are internal-only by default — when ``METRICS_SCRAPE_CREDENTIAL`` is
  unset the guard is a no-op and the network boundary stays the sole control.
- When the credential is set, the route demands
  ``Authorization: Bearer <credential>`` (constant-time match) and rejects
  anything else with ``401`` + a ``WWW-Authenticate: Bearer`` challenge.

The guarantee lives at the app layer so it survives a reverse-proxy swap; proxy
route-hiding stays defense-in-depth.
"""

from fastapi import Depends, FastAPI
from fastapi.responses import Response
from fastapi.testclient import TestClient

from auth_sdk_m8.security.guards import make_scrape_credential_guard
from auth_user_service.core.config import Settings

_SCRAPE_CREDENTIAL = "Aa1-test-metrics-scrape-credential-32!"

_BASE_SETTINGS: dict = {
    "DOMAIN": "localhost",
    "ENVIRONMENT": "local",
    "API_PREFIX": "/user",
    "PROJECT_NAME": "TestApp",
    "STACK_NAME": "test-stack",
    "BACKEND_HOST": "http://localhost:9000",
    "FRONTEND_HOST": "http://localhost:5173",
    "BACKEND_CORS_ORIGINS": "http://localhost",
    "ACCESS_TOKEN_ALGORITHM": "HS256",
    "TOKEN_STRICT_VALIDATION": False,
    "ACCESS_SECRET_KEY": "Aa1-test-access-secret-key-32chars!!",
    "REFRESH_SECRET_KEY": "Aa1-test-refresh-secret-key-32chars!",
    "EVENT_SIGNING_KEY": "Aa1-test-event-signing-key-32chars!!",
    "DB_HOST": "localhost",
    "DB_PORT": 3306,
    "DB_DATABASE": "test_db",
    "DB_USER": "test_user",
    "DB_PASSWORD": "TestPass1@#!",
    "REDIS_HOST": "localhost",
    "REDIS_PORT": 6379,
    "REDIS_USER": "testuser",
    "REDIS_PASSWORD": "TestRedis1@#!",
    "FIRST_SUPERUSER": "admin@example.com",
    "FIRST_SUPERUSER_PASSWORD": "TestAdmin1@#!",
    "PRIVATE_API_SECRET": "Aa1-test-private-api-secret-32chars!!",
    "SESSION_SECRET": "Aa1-test-session-secret-32chars-here!",
    "TOKENS_ENCRYPTION_KEY": "Aa1-test-encryption-key-32chars-here!",
}


def _metrics_client(**overrides) -> TestClient:
    """Build a client whose ``/metrics`` route is wired exactly as main.py wires it."""
    settings = Settings(_env_file=None, **{**_BASE_SETTINGS, **overrides})
    cred = settings.METRICS_SCRAPE_CREDENTIAL
    guard = make_scrape_credential_guard(cred.get_secret_value() if cred else None)
    app = FastAPI()

    @app.get(
        f"{settings.API_PREFIX}/metrics",
        include_in_schema=False,
        dependencies=[Depends(guard)],
    )
    def metrics() -> Response:
        return Response(content="metric 1.0", media_type="text/plain")

    return TestClient(app, raise_server_exceptions=False)


def test_credential_unset_leaves_metrics_network_gated_only() -> None:
    """No credential configured → guard is a no-op; the route answers."""
    resp = _metrics_client().get("/user/metrics")
    assert resp.status_code == 200
    assert resp.text == "metric 1.0"


def test_credential_set_rejects_missing_bearer() -> None:
    """Credential set but no Authorization header → 401 with a Bearer challenge."""
    client = _metrics_client(METRICS_SCRAPE_CREDENTIAL=_SCRAPE_CREDENTIAL)
    resp = client.get("/user/metrics")
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"


def test_credential_set_rejects_wrong_bearer() -> None:
    """Credential set, wrong bearer → 401."""
    client = _metrics_client(METRICS_SCRAPE_CREDENTIAL=_SCRAPE_CREDENTIAL)
    resp = client.get(
        "/user/metrics", headers={"Authorization": "Bearer not-the-credential"}
    )
    assert resp.status_code == 401


def test_credential_set_accepts_correct_bearer() -> None:
    """Credential set, correct bearer → 200 with metrics payload."""
    client = _metrics_client(METRICS_SCRAPE_CREDENTIAL=_SCRAPE_CREDENTIAL)
    resp = client.get(
        "/user/metrics",
        headers={"Authorization": f"Bearer {_SCRAPE_CREDENTIAL}"},
    )
    assert resp.status_code == 200
    assert resp.text == "metric 1.0"


def test_scrape_credential_is_a_masked_secret_field() -> None:
    """METRICS_SCRAPE_CREDENTIAL is a secret: in secret_fields, never in debug dump."""
    settings = Settings(
        _env_file=None,
        **{**_BASE_SETTINGS, "METRICS_SCRAPE_CREDENTIAL": _SCRAPE_CREDENTIAL},
    )
    assert "METRICS_SCRAPE_CREDENTIAL" in settings.secret_fields

    public = settings.model_dump()
    for field in settings.secret_fields:
        public.pop(field, None)
    assert "METRICS_SCRAPE_CREDENTIAL" not in public
    # And the raw credential never leaks via the remaining public values.
    assert _SCRAPE_CREDENTIAL not in str(public)
