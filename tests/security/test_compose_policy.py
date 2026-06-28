"""Compose hardening-policy tests (plan item 5.1).

Asserts the static security contract for the hardened_m8 stack:
- App services (auth_user_service, fastapi_full) carry the required container-hardening flags.
- Data/observability services (DB, Redis, Prometheus, Grafana) bind only to loopback in dev.
- Public Traefik routers explicitly exclude the security-contract internal paths
  (/user/private, /user/metrics) from the public routing rule.

Docker-socket absence, image-pin policy, and production-overlay data-port-reset are
covered by test_socketless_traefik.py, test_image_pins.py, and test_production_overlay.py
— not duplicated here.

Note on /user/health: per plan items 1.4 / 9.4 (Design B) the shallow health status is
served publicly — the ungated body is a constant {"status":"ok"} and the deep detail is
token-gated at the app layer. The static-policy tests assert /user/health is NOT
route-excluded from the public router (it must stay publicly reachable).
"""

from __future__ import annotations

import yaml
import pytest

from tests.security._compose import STACK, load_compose

BASE = STACK / "docker-compose.yml"
DEV_TRAEFIK = STACK / "traefik" / "dynamic_conf.yml"
PROD_TRAEFIK = STACK / "traefik" / "production_dynamic_conf.yml"

_DATA_OBS_SERVICES = ["m8_db", "redis_cache", "prometheus", "grafana"]

_TRAEFIK_CONFS = [
    pytest.param(DEV_TRAEFIK, id="dev"),
    pytest.param(PROD_TRAEFIK, id="production"),
]

# ── app-service container hardening ──────────────────────────────────────────


@pytest.mark.parametrize("service_name", ["auth_user_service", "fastapi_full"])
def test_app_service_drops_all_capabilities(service_name: str) -> None:
    svc = load_compose(BASE)["services"][service_name]
    assert svc.get("cap_drop") == ["ALL"], (
        f"{service_name}: expected cap_drop=[ALL], got {svc.get('cap_drop')}"
    )


@pytest.mark.parametrize("service_name", ["auth_user_service", "fastapi_full"])
def test_app_service_no_new_privileges(service_name: str) -> None:
    svc = load_compose(BASE)["services"][service_name]
    opts = svc.get("security_opt") or []
    assert "no-new-privileges:true" in opts, (
        f"{service_name}: expected no-new-privileges:true in security_opt, got {opts}"
    )


@pytest.mark.parametrize("service_name", ["auth_user_service", "fastapi_full"])
def test_app_service_read_only_filesystem(service_name: str) -> None:
    svc = load_compose(BASE)["services"][service_name]
    assert svc.get("read_only") is True, f"{service_name}: expected read_only=true"


@pytest.mark.parametrize("service_name", ["auth_user_service", "fastapi_full"])
def test_app_service_tmpfs_covers_tmp_and_run(service_name: str) -> None:
    svc = load_compose(BASE)["services"][service_name]
    tmpfs = svc.get("tmpfs") or []
    assert "/tmp" in tmpfs and "/run" in tmpfs, (
        f"{service_name}: expected /tmp and /run in tmpfs, got {tmpfs}"
    )


# ── dev base: data/observability services never bind to all interfaces ────────


@pytest.mark.parametrize("service_name", _DATA_OBS_SERVICES)
def test_dev_base_data_obs_port_is_loopback_bound(service_name: str) -> None:
    svc = load_compose(BASE)["services"][service_name]
    for port in svc.get("ports") or []:
        port_str = str(port)
        assert port_str.startswith("127.0.0.1:"), (
            f"{service_name}: port {port_str!r} does not use a loopback bind — "
            "prefix with '127.0.0.1:' to prevent all-interface exposure"
        )


# ── public Traefik routers exclude security-contract paths ────────────────────


@pytest.mark.parametrize("traefik_path", _TRAEFIK_CONFS)
@pytest.mark.parametrize("excluded_path", ["/user/private", "/user/metrics"])
def test_auth_public_router_excludes_internal_path(
    traefik_path, excluded_path: str
) -> None:
    conf = yaml.safe_load(traefik_path.read_text(encoding="utf-8"))
    rule = conf["http"]["routers"]["auth-public-router"]["rule"]
    assert excluded_path in rule, (
        f"{traefik_path.name}: auth-public-router rule must explicitly "
        f"exclude {excluded_path!r} — add it to the negated PathPrefix block"
    )


@pytest.mark.parametrize("traefik_path", _TRAEFIK_CONFS)
def test_auth_public_router_does_not_exclude_health(traefik_path) -> None:
    """Plan 9.4 Design B: /user/health must stay publicly reachable.

    The shallow body is a constant ``{"status":"ok"}`` and the deep detail is
    app-gated (fail-closed), so the route must NOT be excluded at the proxy.
    """
    conf = yaml.safe_load(traefik_path.read_text(encoding="utf-8"))
    rule = conf["http"]["routers"]["auth-public-router"]["rule"]
    assert "/user/health" not in rule, (
        f"{traefik_path.name}: auth-public-router rule must NOT exclude "
        "/user/health — Design B serves the shallow status publicly"
    )
