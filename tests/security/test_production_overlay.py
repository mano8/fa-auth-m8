"""Static-policy tests for the hardened_m8 PRODUCTION overlay (plan item 2.1).

These parse the compose overlay, the production env examples, and the production
Traefik config and assert the hardening contract — no Docker required.
"""

from __future__ import annotations

import yaml

from tests.security._compose import STACK, load_compose as _load_compose
from tests.security._compose import parse_env as _parse_env

OVERLAY = STACK / "docker-compose.production.yml"
BASE = STACK / "docker-compose.yml"
AUTH_ENV = STACK / "auth.env.production.example"
API_ENV = STACK / "api.env.production.example"
ROOT_ENV = STACK / ".env.production.example"
PROD_TRAEFIK = STACK / "traefik" / "production_dynamic_conf.yml"


# ── overlay shape ───────────────────────────────────────────────────────────


def test_overlay_files_exist() -> None:
    for p in (OVERLAY, AUTH_ENV, API_ENV, ROOT_ENV, PROD_TRAEFIK):
        assert p.is_file(), f"missing {p}"


def test_traefik_publishes_only_redirect_and_https() -> None:
    svc = _load_compose(OVERLAY)["services"]["traefik"]
    ports = svc["ports"]
    assert ports == ["80:80", "443:443/tcp", "443:443/udp"]
    # No plaintext app port, no host-published dashboard or internal entryPoint.
    joined = " ".join(ports)
    for forbidden in ("8000", "8080", "9000"):
        assert forbidden not in joined


def test_traefik_mounts_production_dynamic_conf() -> None:
    svc = _load_compose(OVERLAY)["services"]["traefik"]
    mounts = svc["volumes"]
    assert any(
        m.startswith("./traefik/production_dynamic_conf.yml:") for m in mounts
    ), mounts


def test_data_and_observability_ports_reset() -> None:
    services = _load_compose(OVERLAY)["services"]
    for name in ("m8_db", "redis_cache", "prometheus", "grafana"):
        assert services[name]["ports"] == [], f"{name} still publishes host ports"


def test_cert_init_is_fail_closed_presence_check_not_generator() -> None:
    cmd = " ".join(_load_compose(OVERLAY)["services"]["cert-init"]["command"])
    assert "never generates self-signed" in cmd
    assert "exit 1" in cmd
    assert "openssl" not in cmd  # the dev generator is gone in production


def test_auth_service_image_is_pinned() -> None:
    img = _load_compose(OVERLAY)["services"]["auth_user_service"]["image"]
    assert img.startswith("tepochtli/fa-auth-m8:")
    assert not img.endswith(":latest")


def test_app_services_mount_production_env() -> None:
    services = _load_compose(OVERLAY)["services"]
    auth = services["auth_user_service"]
    assert auth["env_file"] == ["./auth.env.production"]
    assert any(
        v.startswith("./auth.env.production:/opt/auth_user_service/.env")
        for v in auth["volumes"]
    )
    api = services["fastapi_full"]
    assert api["env_file"] == ["./api.env.production"]
    assert any(
        v.startswith("./api.env.production:/opt/fastapi_full/.env")
        for v in api["volumes"]
    )


def test_overlay_documents_migration_decision() -> None:
    text = OVERLAY.read_text(encoding="utf-8")
    assert "MIGRATIONS" in text
    assert "alembic upgrade head" in text


# ── production env examples are fail-closed + production posture ──────────────

_SECRET_FIELDS_AUTH = (
    "DB_PASSWORD",
    "REDIS_PASSWORD",
    "REFRESH_SECRET_KEY",
    "PRIVATE_API_SECRET",
    "SESSION_SECRET",
    "TOKENS_ENCRYPTION_KEY",
    "EVENT_SIGNING_KEY",
    "FIRST_SUPERUSER_PASSWORD",
)


def test_auth_production_env_posture() -> None:
    env = _parse_env(AUTH_ENV)
    assert env["ENVIRONMENT"] == "production"
    assert env["STRICT_PRODUCTION_MODE"] == "true"
    assert env["SET_DOCS"] == "false"
    assert env["SET_OPEN_API"] == "false"
    assert env["SET_REDOC"] == "false"
    assert env["SESSION_COOKIE_SECURE"] == "true"
    assert env["ALLOWED_HOSTS"]  # non-empty host allowlist
    assert env["TOKEN_ISSUER"].startswith("https://")
    assert env["TOKEN_AUDIENCE"].startswith("https://")
    assert "localhost" not in env["BACKEND_CORS_ORIGINS"]
    # API-key verification must fail closed when Redis rate limiting is down
    # (inherited from AUTH_STRICT_MODE/production; set explicitly here) (11.3).
    assert env["AUTH_STRICT_MODE"] == "true"
    assert env["API_KEY_STRICT_RATE_LIMIT"] == "true"


def test_auth_production_secrets_are_fail_closed_placeholders() -> None:
    env = _parse_env(AUTH_ENV)
    for field in _SECRET_FIELDS_AUTH:
        assert env[field] == "changethis", (
            f"{field} must stay the changethis placeholder"
        )


def test_api_production_env_posture() -> None:
    env = _parse_env(API_ENV)
    assert env["ENVIRONMENT"] == "production"
    assert env["STRICT_PRODUCTION_MODE"] == "true"
    assert env["SET_DOCS"] == "false"
    assert env["ALLOWED_HOSTS"]
    # Internal http to auth over the Docker network is explicitly opted in.
    assert env["ALLOW_INTERNAL_HTTP"] == "true"
    assert "localhost" not in env["BACKEND_CORS_ORIGINS"]
    assert env["PRIVATE_API_SECRET"] == "changethis"


def test_root_production_env_no_public_bind() -> None:
    env = _parse_env(ROOT_ENV)
    # API_BIND_IP is commented out (unused under the overlay); never 0.0.0.0.
    assert env.get("API_BIND_IP") != "0.0.0.0"
    assert env["DB_PASSWORD"] == "changethis"
    assert env["REDIS_PASSWORD"] == "changethis"


# ── production Traefik config: FQDN host rules + preserved security contract ──


def test_production_traefik_uses_fqdn_host_rules() -> None:
    conf = yaml.safe_load(PROD_TRAEFIK.read_text(encoding="utf-8"))
    routers = conf["http"]["routers"]
    auth_rule = routers["auth-public-router"]["rule"]
    assert "auth.example.com" in auth_rule
    assert "Host(`localhost`)" not in auth_rule
    # security contract: metrics + private are never publicly routable
    for path in ("/user/metrics", "/user/private"):
        assert path in auth_rule
    # plan 9.4 Design B: /user/health is public-shallow — never route-excluded
    assert "/user/health" not in auth_rule
    assert "api.example.com" in routers["fastapi-public-router"]["rule"]


# ── dev/home-lab base is unchanged (overlay never mutates it) ────────────────


def test_dev_base_keeps_safe_defaults() -> None:
    base = _load_compose(BASE)["services"]
    # The dev base still ships the self-signed generator and the public app port.
    assert "openssl" in " ".join(base["cert-init"]["command"])
    assert any("8000:80" in p for p in base["traefik"]["ports"])
