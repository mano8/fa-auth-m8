"""Tests for the issuer's /meta + /ping routes and build_service_meta."""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from packaging.version import Version

from auth_sdk_m8.controllers.meta import mount_service_meta
from auth_sdk_m8.schemas.meta import ServiceMeta

from auth_user_service import __version__
from auth_user_service.core.service_meta import (
    CONTRACT_RANGE,
    CONTRACT_VERSION,
    SERVICE_NAME,
    build_service_meta,
)


def _client(prefix: str = "/user") -> TestClient:
    app = FastAPI()
    mount_service_meta(app, build_service_meta(), prefix=prefix)
    return TestClient(app)


# ── build_service_meta ────────────────────────────────────────────────────────


def test_build_service_meta_values() -> None:
    meta = build_service_meta()
    assert isinstance(meta, ServiceMeta)
    assert meta.service == "fa-auth-m8"
    assert meta.version == __version__
    assert meta.api_version == "v1"
    assert meta.contract.name == "fa-auth-m8"
    assert meta.contract.version == CONTRACT_VERSION
    assert meta.contract.range == CONTRACT_RANGE


def test_service_version_in_contract_range() -> None:
    """The package version must stay inside the advertised compatibility range."""
    assert SERVICE_NAME == "fa-auth-m8"
    # Lower bound matches CONTRACT_RANGE: /meta + /ping ship from 0.9.8.
    assert Version(__version__) >= Version("0.9.8")
    assert Version(__version__) < Version("0.10.0")
    assert CONTRACT_RANGE == ">=0.9.8 <0.10.0"


# ── Mounted routes ────────────────────────────────────────────────────────────


def test_meta_route_under_api_prefix() -> None:
    resp = _client().get("/user/meta")
    assert resp.status_code == 200
    assert resp.json() == build_service_meta().model_dump()
    assert resp.headers["Cache-Control"] == "public, max-age=300"


def test_ping_route_prefix_independent() -> None:
    resp = _client().get("/ping")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
