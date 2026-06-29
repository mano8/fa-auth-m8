"""Static compose-policy tests for image pinning (item 4.1).

Checks every docker-compose*.yml in examples/docker_compose/ for bare
(untagged) image references and :latest tags — no running Docker required.

Services that build locally (build: key, no image: key) are intentionally
excluded; only services that pull a remote image are in scope.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_COMPOSE_ROOT = Path(__file__).parent.parent / "examples" / "docker_compose"

_BARE_IMAGE_RE = re.compile(r"^[^:@]+$")
_LATEST_RE = re.compile(r":latest$", re.IGNORECASE)

_COMPOSE_FILES = sorted(_COMPOSE_ROOT.rglob("docker-compose*.yml"))


# ── YAML loader that tolerates Compose !reset / !override merge tags ──────────


class _ComposeLoader(yaml.SafeLoader):
    pass


def _identity(loader: _ComposeLoader, node: yaml.Node) -> object:
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_constructor("!reset", _identity)
_ComposeLoader.add_constructor("!override", _identity)


def _load(path: Path) -> dict:
    # _ComposeLoader only extends SafeLoader with !reset/!override; safe to use.
    return yaml.load(path.read_text(), Loader=_ComposeLoader)  # nosec B506


def _service_images(path: Path) -> list[tuple[str, str, str]]:
    """Return [(stack, service_name, image_ref), ...] for remote-image services."""
    data = _load(path)
    stack = path.parent.name
    return [
        (stack, name, svc["image"])
        for name, svc in (data or {}).get("services", {}).items()
        if "image" in svc
    ]


def _all_images() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for f in _COMPOSE_FILES:
        rows.extend(_service_images(f))
    return rows


class TestAuthComposeImagePins:
    """Image-pin policy across all fa-auth-m8 example compose stacks."""

    def test_compose_files_found(self):
        assert _COMPOSE_FILES, (
            f"No docker-compose*.yml files found under {_COMPOSE_ROOT} — "
            "check that the examples/docker_compose/ tree is present"
        )

    def test_no_bare_images(self):
        bare = [
            (stack, svc, img)
            for stack, svc, img in _all_images()
            if _BARE_IMAGE_RE.match(img)
        ]
        assert not bare, (
            "Bare (untagged) image references — pin each to a specific tag or digest:\n"
            + "\n".join(f"  {stack}/{svc}: {img}" for stack, svc, img in bare)
        )

    def test_no_latest_tag(self):
        latest = [
            (stack, svc, img)
            for stack, svc, img in _all_images()
            if _LATEST_RE.search(img)
        ]
        assert not latest, (
            ":latest tags found — pin to an immutable tag or digest:\n"
            + "\n".join(f"  {stack}/{svc}: {img}" for stack, svc, img in latest)
        )
