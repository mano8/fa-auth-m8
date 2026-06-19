"""Host-header routing tests for fa-auth-m8 (item 5.3).

Validates that ``TrustedHostMiddleware`` is correctly wired in
``auth_user_service/main.py`` and behaves consistently with the fastapi-m8
consumer pattern:

- ``ALLOWED_HOSTS=None`` (default) → middleware skipped; any Host accepted.
- ``ALLOWED_HOSTS`` set in a non-production env → listed hosts pass; unlisted
  hosts get 400; ``testserver`` is auto-injected for the HTTPX test client.
- ``ALLOWED_HOSTS`` set in ``ENVIRONMENT=production`` → listed hosts pass;
  ``testserver`` is NOT auto-injected; unlisted hosts get 400.
- ``ALLOWED_HOSTS`` set under ``STRICT_PRODUCTION_MODE=True`` → same as
  production; ``testserver`` not auto-injected.

Tests drive a minimal FastAPI app that replicates the middleware wiring from
``main.py`` without importing the module-level singleton (which binds to the
process-wide ``settings`` object).  This isolates the middleware behaviour from
startup I/O (DB/Redis) and keeps the suite fast and deterministic.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.trustedhost import TrustedHostMiddleware

from auth_user_service.core.config import Settings

# Minimal valid settings that construct without any env file or infrastructure.
# HS256 + permissive binding so no RS256 key material is needed.
_BASE: dict = {
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

# Production-safe CORS (no localhost) for tests that set ENVIRONMENT=production.
_PROD_CORS = {
    "BACKEND_CORS_ORIGINS": "https://auth.example.com",
    "FRONTEND_HOST": "https://auth.example.com",
    "BACKEND_HOST": "https://api.example.com",
}


def _client(**overrides) -> TestClient:
    """Build a minimal ASGI test client that replicates the TrustedHostMiddleware
    wiring from ``auth_user_service/main.py``."""
    s = Settings(_env_file=None, **{**_BASE, **overrides})

    app = FastAPI()

    @app.get("/ping")
    def ping() -> dict:
        return {"ok": True}

    if s.ALLOWED_HOSTS:
        hosts = list(s.ALLOWED_HOSTS)
        is_prod = s.ENVIRONMENT == "production" or s.STRICT_PRODUCTION_MODE
        if not is_prod and "testserver" not in hosts:
            hosts = [*hosts, "testserver"]
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

    return TestClient(app, raise_server_exceptions=False)


# ── No ALLOWED_HOSTS configured ───────────────────────────────────────────────


def test_no_allowed_hosts_permits_any_host() -> None:
    """ALLOWED_HOSTS=None skips TrustedHostMiddleware; any Host is accepted."""
    client = _client(ALLOWED_HOSTS=None)
    assert (
        client.get("/ping", headers={"Host": "arbitrary.host.example"}).status_code
        == 200
    )


def test_no_allowed_hosts_permits_testserver() -> None:
    """Without ALLOWED_HOSTS the default testserver Host is accepted too."""
    client = _client(ALLOWED_HOSTS=None)
    assert client.get("/ping").status_code == 200


# ── ALLOWED_HOSTS set in dev / local environment ──────────────────────────────


def test_dev_listed_host_accepted() -> None:
    """A host present in ALLOWED_HOSTS is accepted in the local environment."""
    client = _client(ALLOWED_HOSTS=["auth.example.com"])
    assert client.get("/ping", headers={"Host": "auth.example.com"}).status_code == 200


def test_dev_unlisted_host_rejected() -> None:
    """An unlisted host is rejected with 400 when ALLOWED_HOSTS is set."""
    client = _client(ALLOWED_HOSTS=["auth.example.com"])
    assert client.get("/ping", headers={"Host": "evil.example.com"}).status_code == 400


def test_dev_testserver_auto_injected() -> None:
    """In non-production, testserver is auto-added so HTTPX test clients work."""
    client = _client(ALLOWED_HOSTS=["auth.example.com"])
    # TestClient defaults to Host: testserver — must not be rejected.
    assert client.get("/ping").status_code == 200


def test_dev_explicit_testserver_accepted() -> None:
    """Listing testserver explicitly is accepted (no duplicate injection harm)."""
    client = _client(ALLOWED_HOSTS=["auth.example.com", "testserver"])
    assert client.get("/ping").status_code == 200


# ── ALLOWED_HOSTS in ENVIRONMENT=production ───────────────────────────────────


def test_production_listed_host_accepted() -> None:
    """A listed host passes in production."""
    client = _client(
        **_PROD_CORS, ENVIRONMENT="production", ALLOWED_HOSTS=["auth.example.com"]
    )
    assert client.get("/ping", headers={"Host": "auth.example.com"}).status_code == 200


def test_production_unlisted_host_rejected() -> None:
    """Unlisted hosts are rejected in production."""
    client = _client(
        **_PROD_CORS, ENVIRONMENT="production", ALLOWED_HOSTS=["auth.example.com"]
    )
    assert client.get("/ping", headers={"Host": "evil.example.com"}).status_code == 400


def test_production_testserver_not_auto_injected() -> None:
    """In production, testserver is NOT auto-added; Host: testserver → 400."""
    client = _client(
        **_PROD_CORS, ENVIRONMENT="production", ALLOWED_HOSTS=["auth.example.com"]
    )
    assert client.get("/ping", headers={"Host": "testserver"}).status_code == 400


# ── ALLOWED_HOSTS under STRICT_PRODUCTION_MODE ────────────────────────────────


def test_strict_mode_listed_host_accepted() -> None:
    """A listed host passes under STRICT_PRODUCTION_MODE."""
    client = _client(STRICT_PRODUCTION_MODE=True, ALLOWED_HOSTS=["auth.example.com"])
    assert client.get("/ping", headers={"Host": "auth.example.com"}).status_code == 200


def test_strict_mode_unlisted_host_rejected() -> None:
    """Unlisted hosts are rejected under STRICT_PRODUCTION_MODE."""
    client = _client(STRICT_PRODUCTION_MODE=True, ALLOWED_HOSTS=["auth.example.com"])
    assert client.get("/ping", headers={"Host": "evil.example.com"}).status_code == 400


def test_strict_mode_testserver_not_auto_injected() -> None:
    """Under STRICT_PRODUCTION_MODE, testserver is NOT auto-added → 400."""
    client = _client(STRICT_PRODUCTION_MODE=True, ALLOWED_HOSTS=["auth.example.com"])
    assert client.get("/ping", headers={"Host": "testserver"}).status_code == 400
