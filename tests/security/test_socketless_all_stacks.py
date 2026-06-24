"""All-stacks Docker-socket policy tests (plan item 0.3).

Decision (2026-06-24): **no** example stack — hardened *or* dev — mounts the raw
Docker socket. Every stack routes exclusively through the Traefik **file
provider**; the Docker provider (which requires the host root-equivalent socket)
is gone everywhere. This removes the dev/prod routing asymmetry and makes the dev
examples exercise the same routing config production relies on.

`test_socketless_traefik.py` already locks the hardened production *path* (item
2.2). This module generalises the guarantee to **every** stack under
``examples/docker_compose`` so a future edit cannot quietly re-introduce the
Docker provider in any example. Stacks are discovered dynamically, so a new
example is covered automatically.

Everything is parsed statically — no running Docker required.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tests.security._compose import REPO_ROOT, load_compose

EXAMPLES = REPO_ROOT / "examples" / "docker_compose"
SOCKET = "/var/run/docker.sock"

# Every stack directory that ships a compose file.
_STACKS = sorted(p.parent.name for p in EXAMPLES.glob("*/docker-compose.yml"))
# Every compose file (base + any production overlay) across all stacks.
_COMPOSE_FILES = sorted(EXAMPLES.glob("*/docker-compose*.yml"))
# Every Traefik static-config file across all stacks.
_TRAEFIK_FILES = sorted(EXAMPLES.glob("*/traefik/traefik.yml"))


def _rel(path: Path) -> str:
    return str(path.relative_to(EXAMPLES))


def _service_volumes(service: dict) -> list[str]:
    return [v for v in service.get("volumes") or [] if isinstance(v, str)]


def test_examples_dir_has_stacks() -> None:
    # Guard the discovery globs: an empty list would make every parametrised
    # test below vacuously pass.
    assert _STACKS, "no example stacks discovered under examples/docker_compose"
    assert _COMPOSE_FILES and _TRAEFIK_FILES


@pytest.mark.parametrize("compose", _COMPOSE_FILES, ids=_rel)
def test_no_stack_mounts_docker_socket(compose: Path) -> None:
    services = load_compose(compose)["services"]
    for name, service in services.items():
        for mount in _service_volumes(service):
            assert SOCKET not in mount, (
                f"{_rel(compose)}:{name} mounts the Docker socket ({mount}) — "
                "the Docker API is equivalent to host root. Route via the Traefik "
                "file provider instead."
            )


@pytest.mark.parametrize("traefik", _TRAEFIK_FILES, ids=_rel)
def test_no_stack_enables_docker_provider(traefik: Path) -> None:
    providers = yaml.safe_load(traefik.read_text(encoding="utf-8"))["providers"]
    assert "file" in providers, f"{_rel(traefik)}: file provider missing"
    assert "docker" not in providers, (
        f"{_rel(traefik)}: the Docker provider must not be enabled — it requires "
        "the host root-equivalent Docker socket. Use the file provider only."
    )


@pytest.mark.parametrize("compose", _COMPOSE_FILES, ids=_rel)
def test_no_stack_declares_traefik_discovery_labels(compose: Path) -> None:
    # File-provider routing needs no per-container `traefik.*` labels; their
    # presence would imply (and invite re-enabling) the Docker provider.
    services = load_compose(compose)["services"]
    for name, service in services.items():
        labels = service.get("labels") or []
        keys = labels.keys() if isinstance(labels, dict) else labels
        assert not any(str(k).startswith("traefik") for k in keys), (
            f"{_rel(compose)}:{name} declares a traefik discovery label — the "
            "file provider makes it unnecessary."
        )
