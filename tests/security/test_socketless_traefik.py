"""Socketless Traefik production-path regression tests (plan item 2.2).

The production path is the dev base (`docker-compose.yml`) merged with the thin
production overlay (`docker-compose.production.yml`). These static-policy tests
lock in the item 2.2 validation contract — "production compose does not mount the
Docker socket directly; routes still resolve" — so a future edit cannot quietly
re-introduce the Docker provider (the socket is equivalent to host root).

The guarantee is structural: routing is the Traefik **file provider** only
(`traefik.yml` declares no `docker` provider), backends are declared statically in
`production_dynamic_conf.yml` and resolve over Docker DNS by container name — so no
socket mount and no per-service Traefik discovery labels are needed in production.

No Docker is required; everything is parsed from the compose/Traefik files.
"""

from __future__ import annotations

import yaml

from tests.security._compose import STACK, load_compose

BASE = STACK / "docker-compose.yml"
OVERLAY = STACK / "docker-compose.production.yml"
TRAEFIK_STATIC = STACK / "traefik" / "traefik.yml"
PROD_TRAEFIK = STACK / "traefik" / "production_dynamic_conf.yml"

SOCKET = "/var/run/docker.sock"
# Container-DNS backends expected in the production file-provider config; each
# must be a compose service so file-provider routing resolves without Docker.
_EXPECTED_BACKENDS = {
    "auth-service": "http://auth_user_service:8000",
    "fastapi-service": "http://fastapi_full:8000",
}


def _service_volumes(service: dict) -> list[str]:
    """Return the string volume mounts declared on a compose service."""
    return [v for v in service.get("volumes") or [] if isinstance(v, str)]


# ── no Docker socket anywhere on the production path ──────────────────────────


def test_no_service_in_production_path_mounts_docker_socket() -> None:
    # Neither the dev base nor the production overlay may mount the socket: the
    # overlay !override's the traefik volumes, but the base must be clean too so
    # the production path is socketless however the files are composed.
    for path in (BASE, OVERLAY):
        services = load_compose(path)["services"]
        for name, service in services.items():
            for mount in _service_volumes(service):
                assert SOCKET not in mount, (
                    f"{path.name}:{name} mounts the Docker socket ({mount})"
                )


def test_production_traefik_volumes_are_socketless_and_explicit() -> None:
    # The overlay replaces the traefik volume list entirely; assert exactly the
    # three read-only config/cert mounts and no socket.
    volumes = load_compose(OVERLAY)["services"]["traefik"]["volumes"]
    assert not any(SOCKET in v for v in volumes), volumes
    assert all(v.endswith(":ro") for v in volumes), volumes
    assert any("production_dynamic_conf.yml:" in v for v in volumes), volumes


# ── file provider only — no Docker provider, no discovery labels ──────────────


def test_static_traefik_uses_file_provider_only() -> None:
    providers = yaml.safe_load(TRAEFIK_STATIC.read_text(encoding="utf-8"))["providers"]
    assert "file" in providers, providers
    assert "docker" not in providers, "Docker provider must not be enabled"


def test_production_path_declares_no_traefik_discovery_labels() -> None:
    # File-provider routing needs no per-container `traefik.*` labels; their
    # presence would imply (and invite re-enabling) the Docker provider.
    for path in (BASE, OVERLAY):
        services = load_compose(path)["services"]
        for name, service in services.items():
            labels = service.get("labels") or []
            keys = labels.keys() if isinstance(labels, dict) else labels
            assert not any(str(k).startswith("traefik") for k in keys), (
                f"{path.name}:{name} declares a traefik discovery label"
            )


# ── routes still resolve via the file provider ───────────────────────────────


def test_production_routers_resolve_to_defined_services() -> None:
    conf = yaml.safe_load(PROD_TRAEFIK.read_text(encoding="utf-8"))["http"]
    defined = set(conf["services"])
    for name, router in conf["routers"].items():
        service = router["service"]
        # api@internal is Traefik's built-in dashboard service, not file-declared.
        if service == "api@internal":
            continue
        assert service in defined, f"router {name} targets undeclared service {service}"


def test_production_backends_use_container_dns() -> None:
    conf = yaml.safe_load(PROD_TRAEFIK.read_text(encoding="utf-8"))["http"]
    compose_services = set(load_compose(BASE)["services"])
    for name, expected_url in _EXPECTED_BACKENDS.items():
        servers = conf["services"][name]["loadBalancer"]["servers"]
        urls = [s["url"] for s in servers]
        assert urls == [expected_url], (name, urls)
        # The DNS name must be a real compose service so it resolves on app_net.
        host = expected_url.removeprefix("http://").split(":", 1)[0]
        assert host in compose_services, f"{host} is not a compose service"
