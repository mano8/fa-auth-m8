"""Security regression (N2): fa-auth wires the shared response-hardening layer.

fa-auth-m8 builds its own ``FastAPI()`` app rather than going through
``fastapi_m8.create_app``, so it must wire
``auth_sdk_m8.security.headers.add_security_headers_middleware`` itself. These
tests verify fa-auth's ``Settings`` (which inherits the header knobs from
``CommonSettings``) drives the same tiered hardening layer the consumer services
get (auth-sdk-m8 >= 1.2.1):

  * Tier 1 — ``X-Content-Type-Options`` / ``X-Frame-Options`` everywhere.
  * Tier 2 — ``Referrer-Policy`` / ``Permissions-Policy`` on the production gate.
  * Tier 3 — ``Strict-Transport-Security`` / ``Content-Security-Policy`` are
    express opt-in (``HSTS_ENABLED`` / ``CONTENT_SECURITY_POLICY_ENABLED``, both
    default ``False``), decoupled from the production gate, and never emitted on
    a local stack even when opted in.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth_sdk_m8.security.headers import add_security_headers_middleware
from auth_user_service.core.config import Settings

_BASE_SETTINGS: dict = {
    "DOMAIN": "localhost",
    "API_PREFIX": "/user",
    "PROJECT_NAME": "TestApp",
    "STACK_NAME": "test-stack",
    "BACKEND_HOST": "http://localhost:9000",
    "FRONTEND_HOST": "http://localhost:5173",
    "BACKEND_CORS_ORIGINS": "http://localhost",
    # Pin HS256 + permissive binding so production settings construct without
    # requiring RS256 key material — this test is about headers, not signing.
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

# Tier 1 — emitted in every environment whenever SECURITY_HEADERS_ENABLED.
_ALWAYS_ON_HEADERS = ("x-content-type-options", "x-frame-options")
# Tier 2 — production gate only (ENVIRONMENT==production or STRICT_PRODUCTION_MODE).
_PRODUCTION_HEADERS = ("referrer-policy", "permissions-policy")
# Tier 3 — browser-persisted, express opt-in only, never on local.
_OPT_IN_HEADERS = ("strict-transport-security", "content-security-policy")

# Opt the two browser-persisted headers in, the way a real TLS-terminated
# deployment would.
_OPT_IN = {"HSTS_ENABLED": True, "CONTENT_SECURITY_POLICY_ENABLED": True}


def _client(**overrides) -> TestClient:
    settings = Settings(_env_file=None, **{**_BASE_SETTINGS, **overrides})
    app = FastAPI()

    @app.get("/ping")
    def ping() -> dict:
        return {"ok": True}

    add_security_headers_middleware(app, settings)
    return TestClient(app, raise_server_exceptions=False)


def test_always_on_headers_emitted_in_local() -> None:
    """Tier 1 (nosniff, frame-options) is safe everywhere — present even on local."""
    resp = _client(ENVIRONMENT="local").get("/ping")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    # Tiers 2 and 3 stay off on local.
    for header in _PRODUCTION_HEADERS:
        assert header not in resp.headers


def test_hsts_csp_never_emitted_on_local_even_when_opted_in() -> None:
    """Tier 3 is hard-blocked on local — HSTS would poison the localhost cache."""
    resp = _client(ENVIRONMENT="local", **_OPT_IN).get("/ping")
    for header in _OPT_IN_HEADERS:
        assert header not in resp.headers


_PROD_CONSUMERS = {
    "PRIVATE_API_CONSUMERS": {
        "test-svc": {"secret": "plain-test-secret", "scopes": ["introspection"]}
    }
}


def test_production_headers_without_opt_in() -> None:
    """The production gate emits tiers 1+2 but NOT the opt-in HSTS/CSP pair."""
    resp = _client(ENVIRONMENT="production", **_PROD_CONSUMERS).get("/ping")
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "permissions-policy" in resp.headers
    # Tier 3 is off until explicitly enabled.
    for header in _OPT_IN_HEADERS:
        assert header not in resp.headers


def test_full_opt_in_in_production() -> None:
    """Opting in adds HSTS and CSP on top of the production hardening set."""
    resp = _client(ENVIRONMENT="production", **_OPT_IN, **_PROD_CONSUMERS).get("/ping")
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert "max-age=31536000" in resp.headers["strict-transport-security"]
    assert "includeSubDomains" in resp.headers["strict-transport-security"]


def test_opt_in_decoupled_from_production_gate() -> None:
    """HSTS/CSP opt-in applies on a non-production, non-local stack (e.g. staging).

    Tier 3 is independent of the production gate, so a TLS-terminated staging
    stack gets HSTS/CSP without the Tier-2 production-only headers.
    """
    resp = _client(ENVIRONMENT="staging", **_OPT_IN).get("/ping")
    assert "strict-transport-security" in resp.headers
    assert "content-security-policy" in resp.headers
    # Production-gated headers stay off — staging is not production.
    for header in _PRODUCTION_HEADERS:
        assert header not in resp.headers


def test_master_switch_suppresses_every_tier() -> None:
    """SECURITY_HEADERS_ENABLED=False suppresses every tier, opt-ins included."""
    resp = _client(
        ENVIRONMENT="production",
        SECURITY_HEADERS_ENABLED=False,
        **_OPT_IN,
        **_PROD_CONSUMERS,
    ).get("/ping")
    for header in _ALWAYS_ON_HEADERS + _PRODUCTION_HEADERS + _OPT_IN_HEADERS:
        assert header not in resp.headers
