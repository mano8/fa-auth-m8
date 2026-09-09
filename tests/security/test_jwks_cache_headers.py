"""JWKS freshness metadata — audit finding ``J4`` (plan step ``W1.4``).

The measured response carried no ``Cache-Control``, no ``ETag`` and no
``Last-Modified``: every intermediary and every consumer was left to invent its
own freshness policy, and a consumer wanting to re-validate more often than its
TTL had to refetch the whole document.

The endpoint now sends a ``max-age`` matching the SDK's own JWKS cache default
and a strong ``ETag`` over the serialized key set, and answers a matching
``If-None-Match`` with ``304``.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth_user_service.core.key_ids import derive_kid
from auth_user_service.routes import jwks as jwks_module


def _public_pem() -> str:
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


_CURRENT_PEM = _public_pem()
_OLD_PEM = _public_pem()


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(jwks_module.router)
    return TestClient(app)


class _StubSettings:
    """Only the attributes the endpoint reads."""

    def __init__(
        self,
        algorithm: str = "RS256",
        public_key: str | None = _CURRENT_PEM,
        old_public_key: str | None = None,
        ttl: int = 300,
    ) -> None:
        self.ACCESS_TOKEN_ALGORITHM = algorithm
        self.ACCESS_PUBLIC_KEY = public_key
        self.ACCESS_PUBLIC_KEY_OLD = old_public_key
        self.ACCESS_KEY_ID_OLD = None
        self.ACCESS_KEY_ID = derive_kid(public_key) if public_key else None
        self.JWKS_CACHE_TTL_SECONDS = ttl


def _get(settings: _StubSettings, headers: dict[str, str] | None = None):
    with (
        patch.object(jwks_module, "settings", settings),
        patch.object(
            jwks_module,
            "_resolve_kid",
            side_effect=lambda _algo: settings.ACCESS_KEY_ID,
        ),
    ):
        return _client().get("/.well-known/jwks.json", headers=headers or {})


# ── headers are present and correct ──────────────────────────────────────────


@pytest.mark.security
def test_response_carries_cache_control_and_etag() -> None:
    response = _get(_StubSettings())

    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=300"
    assert response.headers["etag"].startswith('"')
    assert response.headers["etag"].endswith('"')


@pytest.mark.security
def test_max_age_follows_the_configured_jwks_ttl() -> None:
    response = _get(_StubSettings(ttl=60))
    assert response.headers["cache-control"] == "public, max-age=60"


@pytest.mark.security
def test_etag_is_a_strong_validator() -> None:
    """A weak ETag would let an intermediary serve a semantically-equal body."""
    assert not _get(_StubSettings()).headers["etag"].startswith("W/")


@pytest.mark.security
def test_body_is_still_the_key_set() -> None:
    response = _get(_StubSettings())
    payload = response.json()
    assert response.headers["content-type"].startswith("application/json")
    assert [k["kid"] for k in payload["keys"]] == [derive_kid(_CURRENT_PEM)]


@pytest.mark.security
def test_empty_key_set_is_also_cacheable() -> None:
    """HS256 publishes nothing, but the answer is still worth caching."""
    response = _get(_StubSettings(algorithm="HS256", public_key=None))
    assert response.json() == {"keys": []}
    assert "max-age" in response.headers["cache-control"]
    assert "etag" in response.headers


# ── the ETag tracks the key set ──────────────────────────────────────────────


@pytest.mark.security
def test_etag_is_stable_across_requests() -> None:
    settings = _StubSettings()
    assert _get(settings).headers["etag"] == _get(settings).headers["etag"]


@pytest.mark.security
def test_etag_changes_when_the_key_set_changes() -> None:
    """Rotating the key, and opening the overlap window, must both move it."""
    single = _get(_StubSettings()).headers["etag"]
    rotated = _get(_StubSettings(public_key=_OLD_PEM)).headers["etag"]
    with_window = _get(_StubSettings(old_public_key=_OLD_PEM)).headers["etag"]

    assert len({single, rotated, with_window}) == 3


# ── conditional GET ──────────────────────────────────────────────────────────


@pytest.mark.security
def test_conditional_get_with_the_current_etag_returns_304() -> None:
    settings = _StubSettings()
    etag = _get(settings).headers["etag"]

    response = _get(settings, headers={"If-None-Match": etag})

    assert response.status_code == 304
    assert response.content == b""
    assert response.headers["etag"] == etag
    assert response.headers["cache-control"] == "public, max-age=300"


@pytest.mark.security
def test_conditional_get_accepts_a_weak_validator() -> None:
    """RFC 9110 §13.1.2: If-None-Match uses weak comparison."""
    settings = _StubSettings()
    etag = _get(settings).headers["etag"]

    assert _get(settings, headers={"If-None-Match": f"W/{etag}"}).status_code == 304


@pytest.mark.security
def test_conditional_get_accepts_a_wildcard() -> None:
    assert _get(_StubSettings(), headers={"If-None-Match": "*"}).status_code == 304


@pytest.mark.security
def test_conditional_get_accepts_a_list_containing_the_current_etag() -> None:
    settings = _StubSettings()
    etag = _get(settings).headers["etag"]
    header = f'"0000000000000000", {etag}, W/"1111111111111111"'

    assert _get(settings, headers={"If-None-Match": header}).status_code == 304


@pytest.mark.security
def test_conditional_get_with_a_stale_etag_returns_the_new_key_set() -> None:
    """The case that matters operationally: the key rotated under the cache."""
    stale = _get(_StubSettings()).headers["etag"]

    response = _get(
        _StubSettings(public_key=_OLD_PEM), headers={"If-None-Match": stale}
    )

    assert response.status_code == 200
    assert response.headers["etag"] != stale
    assert [k["kid"] for k in response.json()["keys"]] == [derive_kid(_OLD_PEM)]


@pytest.mark.security
def test_unconditional_get_is_never_304() -> None:
    assert _get(_StubSettings()).status_code == 200
