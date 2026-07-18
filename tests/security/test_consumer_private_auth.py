"""Phase 9.1 issuer-side tests — per-consumer scoped secrets + service tokens.

Covers the three new building blocks fa-auth-m8 layers on top of the auth-sdk-m8
verification primitives:

* ``core.consumer_registry`` — building a ``ConsumerCredentialRegistry`` from the
  ``PRIVATE_API_CONSUMERS`` setting (plaintext *and* hashed-at-rest forms);
* ``services.service_token`` — minting/verifying short-TTL scoped service tokens;
* ``core.deps.require_private_scope`` — the private-route auth dependency
  (per-consumer credential and service token; fail-closed with no registry now
  that the legacy single-secret gate is retired);
* the ``/private/v1/service-token`` exchange route.

The plan's required matrix is exercised end to end: wrong consumer secret
rejected; consumer A cannot use consumer B's secret; expired service token
rejected; scope violation denied.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from auth_sdk_m8.security.consumer_auth import (
    ConsumerCredential,
    ConsumerScope,
)

from auth_user_service.core import consumer_registry as cr
from pydantic import SecretStr

from auth_user_service.core.config import ConsumerCredentialConfig, settings
from auth_user_service.core.consumer_registry import get_consumer_registry
from auth_user_service.core.deps import (
    authenticate_private_consumer,
    require_private_scope,
)
from auth_user_service.routes import private as private_routes
from auth_user_service.services.service_token import (
    SERVICE_TOKEN_AUDIENCE,
    ServiceTokenError,
    ServiceTokenExpired,
    decode_service_token,
    issue_service_token,
)

_SIGNING_KEY = settings.PRIVATE_API_SECRET.get_secret_value()


def _consumers(**spec: tuple[str, list[str]]) -> dict[str, ConsumerCredentialConfig]:
    """Build a ``PRIVATE_API_CONSUMERS`` mapping from ``id=(secret, scopes)``."""
    return {
        client_id: ConsumerCredentialConfig(secret=SecretStr(secret), scopes=scopes)
        for client_id, (secret, scopes) in spec.items()
    }


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def _clear_registry_cache():
    """Drop the cached registry around each test so settings edits take effect."""
    cr._build_registry.cache_clear()
    yield
    cr._build_registry.cache_clear()


# ── consumer_registry ─────────────────────────────────────────────────────────


def test_registry_none_when_no_consumers(monkeypatch) -> None:
    """Empty config → no registry (a misconfiguration; callers fail closed)."""
    monkeypatch.setattr(settings, "PRIVATE_API_CONSUMERS", {})
    assert get_consumer_registry() is None


def test_registry_loads_plaintext_secret(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "PRIVATE_API_CONSUMERS",
        _consumers(media=("plain-secret", ["introspection"])),
    )
    registry = get_consumer_registry()
    assert registry is not None
    cred = registry.verify("media", "plain-secret")
    assert cred is not None and cred.has_scope(ConsumerScope.INTROSPECTION)
    assert registry.verify("media", "wrong") is None


def test_registry_loads_encoded_secret(monkeypatch) -> None:
    """A ``sha256$..`` value is loaded via the hashed-at-rest path."""
    encoded = ConsumerCredential.create("svc", "hashed-secret").encoded_secret
    assert encoded.startswith("sha256$")
    monkeypatch.setattr(
        settings,
        "PRIVATE_API_CONSUMERS",
        _consumers(svc=(encoded, ["event-stream"])),
    )
    registry = get_consumer_registry()
    assert registry is not None
    assert registry.verify("svc", "hashed-secret") is not None
    assert registry.verify("svc", "nope") is None


def test_registry_cached_per_snapshot(monkeypatch) -> None:
    """The same config snapshot returns the identical (cached) registry object."""
    monkeypatch.setattr(
        settings, "PRIVATE_API_CONSUMERS", _consumers(a=("s", ["introspection"]))
    )
    assert get_consumer_registry() is get_consumer_registry()


# ── service_token ─────────────────────────────────────────────────────────────


def test_service_token_round_trip() -> None:
    token, expires_in = issue_service_token(
        "media",
        ["introspection", "user-create"],
        signing_secret=_SIGNING_KEY,
        ttl_seconds=120,
    )
    assert expires_in == 120
    claims = decode_service_token(token, signing_secret=_SIGNING_KEY)
    assert claims.client_id == "media"
    assert claims.scopes == frozenset({"introspection", "user-create"})


def test_service_token_empty_scope() -> None:
    token, _ = issue_service_token(
        "media", [], signing_secret=_SIGNING_KEY, ttl_seconds=60
    )
    assert (
        decode_service_token(token, signing_secret=_SIGNING_KEY).scopes == frozenset()
    )


def test_service_token_expired_rejected() -> None:
    token, _ = issue_service_token(
        "media", ["introspection"], signing_secret=_SIGNING_KEY, ttl_seconds=1
    )
    time.sleep(1.1)
    with pytest.raises(ServiceTokenExpired):
        decode_service_token(token, signing_secret=_SIGNING_KEY)


def test_service_token_wrong_signing_secret_rejected() -> None:
    token, _ = issue_service_token(
        "media", ["introspection"], signing_secret=_SIGNING_KEY, ttl_seconds=60
    )
    with pytest.raises(ServiceTokenError):
        decode_service_token(token, signing_secret="a-different-key")


def test_service_token_wrong_type_rejected() -> None:
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "media",
            "scope": "introspection",
            "type": "access",
            "aud": SERVICE_TOKEN_AUDIENCE,
            "iat": now,
            "exp": now + timedelta(seconds=60),
        },
        _SIGNING_KEY,
        algorithm="HS256",
    )
    with pytest.raises(ServiceTokenError):
        decode_service_token(token, signing_secret=_SIGNING_KEY)


def test_service_token_empty_subject_rejected() -> None:
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "",
            "type": "service",
            "aud": SERVICE_TOKEN_AUDIENCE,
            "iat": now,
            "exp": now + timedelta(seconds=60),
        },
        _SIGNING_KEY,
        algorithm="HS256",
    )
    with pytest.raises(ServiceTokenError):
        decode_service_token(token, signing_secret=_SIGNING_KEY)


# ── require_private_scope dependency ──────────────────────────────────────────


def _guarded_client(scope: ConsumerScope) -> TestClient:
    app = FastAPI()

    @app.get("/p", dependencies=[Depends(require_private_scope(scope))])
    def _p() -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app)


def test_no_registry_denies_all(monkeypatch) -> None:
    """Legacy gate retired: no registry → every private call is denied (401).

    Even an ``X-Internal-Token`` matching the (still-present) ``PRIVATE_API_SECRET``
    no longer authorizes anything — the single shared-secret gate is gone, so the
    private surface fails closed until ``PRIVATE_API_CONSUMERS`` is configured.
    """
    monkeypatch.setattr(settings, "PRIVATE_API_CONSUMERS", {})
    client = _guarded_client(ConsumerScope.INTROSPECTION)
    # The retired legacy shared secret is rejected.
    assert (
        client.get("/p", headers={"X-Internal-Token": _SIGNING_KEY}).status_code == 401
    )
    # A would-be per-consumer credential is rejected (no registry to match).
    assert (
        client.get(
            "/p", headers={"X-Internal-Client": "a", "X-Internal-Token": "secret-a"}
        ).status_code
        == 401
    )
    # A bearer-shaped credential is rejected.
    assert (
        client.get("/p", headers={"Authorization": "Bearer whatever"}).status_code
        == 401
    )
    # No credential at all is rejected.
    assert client.get("/p").status_code == 401


def test_per_consumer_credential_paths(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "PRIVATE_API_CONSUMERS",
        _consumers(
            a=("secret-a", ["introspection"]),
            b=("secret-b", ["event-stream"]),
        ),
    )
    client = _guarded_client(ConsumerScope.INTROSPECTION)

    # Correct consumer + scope.
    ok = client.get(
        "/p", headers={"X-Internal-Client": "a", "X-Internal-Token": "secret-a"}
    )
    assert ok.status_code == 200

    # Wrong secret → 401.
    assert (
        client.get(
            "/p", headers={"X-Internal-Client": "a", "X-Internal-Token": "nope"}
        ).status_code
        == 401
    )

    # Consumer A cannot use Consumer B's secret → 401 (no enumeration).
    assert (
        client.get(
            "/p", headers={"X-Internal-Client": "a", "X-Internal-Token": "secret-b"}
        ).status_code
        == 401
    )

    # Authenticated but lacking the required scope → 403.
    assert (
        client.get(
            "/p", headers={"X-Internal-Client": "b", "X-Internal-Token": "secret-b"}
        ).status_code
        == 403
    )


def test_service_token_paths(monkeypatch) -> None:
    monkeypatch.setattr(
        settings, "PRIVATE_API_CONSUMERS", _consumers(a=("secret-a", ["introspection"]))
    )
    client = _guarded_client(ConsumerScope.INTROSPECTION)

    good, _ = issue_service_token(
        "a", ["introspection"], signing_secret=_SIGNING_KEY, ttl_seconds=60
    )
    assert (
        client.get("/p", headers={"Authorization": f"Bearer {good}"}).status_code == 200
    )

    # Token without the required scope → 403.
    wrong_scope, _ = issue_service_token(
        "a", ["event-stream"], signing_secret=_SIGNING_KEY, ttl_seconds=60
    )
    assert (
        client.get("/p", headers={"Authorization": f"Bearer {wrong_scope}"}).status_code
        == 403
    )

    # Expired token → 401.
    expired, _ = issue_service_token(
        "a", ["introspection"], signing_secret=_SIGNING_KEY, ttl_seconds=1
    )
    time.sleep(1.1)
    assert (
        client.get("/p", headers={"Authorization": f"Bearer {expired}"}).status_code
        == 401
    )

    # Garbage bearer → 401.
    assert (
        client.get("/p", headers={"Authorization": "Bearer not-a-jwt"}).status_code
        == 401
    )


# ── authenticate_private_consumer returns the caller identity (audience) ──────


def _identity_client(scope: ConsumerScope) -> TestClient:
    app = FastAPI()

    @app.get("/id")
    def _id(request: Request) -> dict[str, str]:
        return {"id": authenticate_private_consumer(request, scope)}

    return TestClient(app)


def test_authenticate_returns_credential_client_id(monkeypatch) -> None:
    """The per-consumer credential path yields the authenticated consumer id."""
    monkeypatch.setattr(
        settings,
        "PRIVATE_API_CONSUMERS",
        _consumers(media=("secret-m", ["introspection"])),
    )
    resp = _identity_client(ConsumerScope.INTROSPECTION).get(
        "/id", headers={"X-Internal-Client": "media", "X-Internal-Token": "secret-m"}
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == "media"


def test_authenticate_returns_service_token_client_id(monkeypatch) -> None:
    """The service-token path yields the token subject as the consumer id."""
    monkeypatch.setattr(
        settings,
        "PRIVATE_API_CONSUMERS",
        _consumers(media=("secret-m", ["introspection"])),
    )
    token, _ = issue_service_token(
        "media", ["introspection"], signing_secret=_SIGNING_KEY, ttl_seconds=60
    )
    resp = _identity_client(ConsumerScope.INTROSPECTION).get(
        "/id", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == "media"


# ── /private/v1/service-token exchange route ──────────────────────────────────


def _router_client() -> TestClient:
    app = FastAPI()
    app.include_router(private_routes.router)
    return TestClient(app)


def test_exchange_disabled_without_registry(monkeypatch) -> None:
    monkeypatch.setattr(settings, "PRIVATE_API_CONSUMERS", {})
    resp = _router_client().post("/private/v1/service-token")
    assert resp.status_code == 404


def test_exchange_mints_granted_scopes(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "PRIVATE_API_CONSUMERS",
        _consumers(media=("secret-m", ["introspection", "event-stream"])),
    )
    resp = _router_client().post(
        "/private/v1/service-token",
        headers={"X-Internal-Client": "media", "X-Internal-Token": "secret-m"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == settings.SERVICE_TOKEN_TTL_SECONDS
    assert set(body["scope"].split()) == {"introspection", "event-stream"}
    claims = decode_service_token(body["access_token"], signing_secret=_SIGNING_KEY)
    assert claims.client_id == "media"
    assert claims.scopes == frozenset({"introspection", "event-stream"})


def test_exchange_narrows_to_requested_subset(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "PRIVATE_API_CONSUMERS",
        _consumers(media=("secret-m", ["introspection", "event-stream"])),
    )
    resp = _router_client().post(
        "/private/v1/service-token",
        headers={"X-Internal-Client": "media", "X-Internal-Token": "secret-m"},
        json={"scopes": ["introspection"]},
    )
    assert resp.status_code == 200
    assert resp.json()["scope"] == "introspection"


def test_exchange_rejects_scope_escalation(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "PRIVATE_API_CONSUMERS",
        _consumers(media=("secret-m", ["introspection"])),
    )
    resp = _router_client().post(
        "/private/v1/service-token",
        headers={"X-Internal-Client": "media", "X-Internal-Token": "secret-m"},
        json={"scopes": ["user-create"]},
    )
    assert resp.status_code == 403


def test_exchange_rejects_consumer_without_scopes(monkeypatch) -> None:
    monkeypatch.setattr(
        settings, "PRIVATE_API_CONSUMERS", _consumers(noscope=("secret-n", []))
    )
    resp = _router_client().post(
        "/private/v1/service-token",
        headers={"X-Internal-Client": "noscope", "X-Internal-Token": "secret-n"},
    )
    assert resp.status_code == 403


def test_exchange_rejects_wrong_secret(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "PRIVATE_API_CONSUMERS",
        _consumers(media=("secret-m", ["introspection"])),
    )
    resp = _router_client().post(
        "/private/v1/service-token",
        headers={"X-Internal-Client": "media", "X-Internal-Token": "wrong"},
    )
    assert resp.status_code == 401
