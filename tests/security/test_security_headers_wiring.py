"""Security regression (N2): fa-auth wires the shared response-hardening layer.

fa-auth-m8 builds its own ``FastAPI()`` app rather than going through
``fastapi_m8.create_app``, so it must wire
``auth_sdk_m8.security.headers.add_security_headers_middleware`` itself. These
tests verify fa-auth's ``Settings`` (which inherits the header knobs from
``CommonSettings``) drives the same env-gated hardening layer the consumer
services get: emitted in production, absent in local/dev.
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

_HARDENING_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
)


def _client(**overrides) -> TestClient:
    settings = Settings(_env_file=None, **{**_BASE_SETTINGS, **overrides})
    app = FastAPI()

    @app.get("/ping")
    def ping() -> dict:
        return {"ok": True}

    add_security_headers_middleware(app, settings)
    return TestClient(app, raise_server_exceptions=False)


def test_headers_emitted_in_production() -> None:
    """The provider now emits app-level hardening headers in production (N2)."""
    resp = _client(ENVIRONMENT="production").get("/ping")
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "max-age=31536000" in resp.headers["strict-transport-security"]


def test_headers_absent_in_local() -> None:
    """Local/dev stays unrestricted so Swagger/ReDoc keep working."""
    resp = _client(ENVIRONMENT="local").get("/ping")
    for header in _HARDENING_HEADERS:
        assert header not in resp.headers
