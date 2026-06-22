"""Image-pin policy tests for hardened/production compose (plan item 4.1).

The hardened stack (and its production overlay) must never use bare image names
(no tag) or the mutable `:latest` tag. Both allow silent pulls of a different
image layer after the initial pull, breaking the supply-chain guarantee of
pinned, reproducible deployments.

Rules asserted here:
- Every `image:` value in the hardened base and production overlay has an
  explicit tag (`name:tag`, not bare `name`).
- No image uses the `:latest` tag.
- Services that use `build:` instead of `image:` are excluded (they are
  built locally from source and are covered by CI image scanning).

No Docker is required; everything is parsed from the compose files.
"""

from __future__ import annotations

import pytest

from tests.security._compose import STACK, load_compose

BASE = STACK / "docker-compose.yml"
OVERLAY = STACK / "docker-compose.production.yml"

_COMPOSE_FILES = [
    pytest.param(BASE, id="base"),
    pytest.param(OVERLAY, id="production-overlay"),
]


def _image_entries(path) -> list[tuple[str, str]]:
    """Return (service_name, image) pairs that declare an `image:` key."""
    services = load_compose(path)["services"]
    return [(name, svc["image"]) for name, svc in services.items() if "image" in svc]


@pytest.mark.parametrize("compose_path", _COMPOSE_FILES)
def test_no_bare_image_tags(compose_path) -> None:
    """Every image in the hardened compose declares an explicit version tag."""
    for name, image in _image_entries(compose_path):
        # A bare image has no `:` at all (e.g. `alpine`), or the part after the
        # last `/` contains no `:` (handles `library/alpine` style).
        ref = image.split("@")[0]  # strip digest if present
        local_part = ref.rsplit("/", 1)[-1]
        assert ":" in local_part, (
            f"{compose_path.name}: service '{name}' uses bare image '{image}' "
            f"— pin to a specific version tag (e.g. alpine:3.22)"
        )


@pytest.mark.parametrize("compose_path", _COMPOSE_FILES)
def test_no_latest_tag(compose_path) -> None:
    """No image in the hardened compose uses the mutable ':latest' tag."""
    for name, image in _image_entries(compose_path):
        ref = image.split("@")[0]
        tag = ref.rsplit(":", 1)[-1] if ":" in ref.rsplit("/", 1)[-1] else ""
        assert tag != "latest", (
            f"{compose_path.name}: service '{name}' uses ':latest' ({image}) "
            f"— pin to a specific immutable version tag"
        )
