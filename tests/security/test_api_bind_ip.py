"""Static policy tests for API_BIND_IP / port-9000 binding (plan item 5.4).

Asserts the security contract for the internal :9000 services entryPoint:

- Every dev-base compose that publishes :9000 uses `${API_BIND_IP:-127.0.0.1}`
  as the bind address — never a literal 0.0.0.0 hardcoded in the file.
- The production overlay drops :9000 from published ports entirely (traefik
  `ports: !override` only has :80 and :443).
- No *.env.example file sets API_BIND_IP=0.0.0.0 (the safe default is 127.0.0.1,
  and operators must opt in explicitly by editing a real env file).
- The preflight break-glass: ALLOW_PUBLIC_API_BIND=true allows API_BIND_IP=0.0.0.0
  in production (verified alongside the rejection test in test_preflight_security.py
  — here we assert the compose/env side only, not subprocess invocation).

The preflight rejection of API_BIND_IP=0.0.0.0 under ENVIRONMENT=production is
already tested in test_preflight_security.py::test_preflight_rejects_public_api_bind_in_production.
This module covers the static file-level guarantees so regressions are caught
without running the shell preflight.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.security._compose import REPO_ROOT, STACK, load_compose

COMPOSE_DIR = REPO_ROOT / "examples" / "docker_compose"
PRODUCTION_OVERLAY = STACK / "docker-compose.production.yml"

# Stacks that publish :9000 (dev examples; vault_prod_template is non-runnable)
_DEV_STACKS_WITH_9000 = [
    pytest.param(STACK / "docker-compose.yml", id="hardened_m8"),
    pytest.param(COMPOSE_DIR / "metrics_m8" / "docker-compose.yml", id="metrics_m8"),
    pytest.param(COMPOSE_DIR / "postgres_m8" / "docker-compose.yml", id="postgres_m8"),
    pytest.param(
        COMPOSE_DIR / "quickstart_m8" / "docker-compose.yml", id="quickstart_m8"
    ),
    pytest.param(COMPOSE_DIR / "rs256_m8" / "docker-compose.yml", id="rs256_m8"),
    pytest.param(
        COMPOSE_DIR / "vault_dev_m8" / "docker-compose.yml", id="vault_dev_m8"
    ),
]

# All *.env.example files across every compose stack
_ENV_EXAMPLES = list(COMPOSE_DIR.rglob("*.env.example")) + list(
    COMPOSE_DIR.rglob(".env.example")
)


# ── dev base: :9000 must use the safe ${API_BIND_IP:-127.0.0.1} default ──────


@pytest.mark.parametrize("compose_path", _DEV_STACKS_WITH_9000)
def test_dev_port_9000_uses_api_bind_ip_variable(compose_path: Path) -> None:
    """Port 9000 must not be hardcoded to 0.0.0.0 in the dev base compose."""
    text = compose_path.read_text(encoding="utf-8")
    # The port line may look like `"0.0.0.0:9000:9000"` — assert it does NOT.
    assert "0.0.0.0:9000" not in text, (
        f"{compose_path.name}: port 9000 must not be hardcoded to 0.0.0.0 — "
        "use '${API_BIND_IP:-127.0.0.1}:9000:9000' so the default is loopback"
    )


@pytest.mark.parametrize("compose_path", _DEV_STACKS_WITH_9000)
def test_dev_port_9000_declares_api_bind_ip_variable(compose_path: Path) -> None:
    """Port 9000 must reference ${API_BIND_IP:-...} so operators can override it."""
    text = compose_path.read_text(encoding="utf-8")
    assert "${API_BIND_IP:-" in text, (
        f"{compose_path.name}: port 9000 binding must use "
        "'${API_BIND_IP:-127.0.0.1}:9000:9000' "  # noqa: ISC003
        "so operators can override the bind address via API_BIND_IP in .env"
    )


# ── production overlay: :9000 must NOT be host-published ─────────────────────


def test_production_overlay_does_not_publish_port_9000() -> None:
    """The production overlay must not expose :9000 on any host interface.

    The overlay uses `ports: !override` on the traefik service with only :80
    and :443; port 9000 stays on the Docker network only (Case A).
    """
    compose = load_compose(PRODUCTION_OVERLAY)
    traefik_ports = compose.get("services", {}).get("traefik", {}).get("ports") or []
    published_9000 = [p for p in traefik_ports if "9000" in str(p)]
    assert not published_9000, (
        "production overlay must not publish :9000 — "
        f"found: {published_9000}. Port 9000 must stay Docker-network-only in production."
    )


def test_production_overlay_traefik_only_publishes_80_and_443() -> None:
    """Production overlay traefik ports must be limited to :80 and :443."""
    compose = load_compose(PRODUCTION_OVERLAY)
    traefik_ports = compose.get("services", {}).get("traefik", {}).get("ports") or []
    allowed = re.compile(r"^(\"?)(:?80:80|443:443|80:80|443:443/tcp|443:443/udp)(\"?)$")
    unexpected = [p for p in traefik_ports if not allowed.match(str(p).strip('"'))]
    assert not unexpected, (
        f"production overlay traefik must only publish :80 and :443, "
        f"found unexpected ports: {unexpected}"
    )


# ── env examples: API_BIND_IP must not be set to 0.0.0.0 ────────────────────


def _active_api_bind_ip(path: Path) -> str | None:
    """Return the active (uncommented) API_BIND_IP value, or None if absent/commented."""
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith("API_BIND_IP="):
            return stripped.split("=", 1)[1].strip()
    return None


@pytest.mark.parametrize(
    "env_path",
    [pytest.param(p, id=str(p.relative_to(COMPOSE_DIR))) for p in _ENV_EXAMPLES],
)
def test_env_example_does_not_set_api_bind_ip_to_0000(env_path: Path) -> None:
    """*.env.example files must never set API_BIND_IP=0.0.0.0.

    The safe default is 127.0.0.1 (commented or absent); operators who need
    LAN/public exposure must edit their real env file explicitly.
    """
    value = _active_api_bind_ip(env_path)
    assert value != "0.0.0.0", (
        f"{env_path.relative_to(COMPOSE_DIR)}: must not set API_BIND_IP=0.0.0.0 — "
        "example files must document the safe default (127.0.0.1, commented) only"
    )
