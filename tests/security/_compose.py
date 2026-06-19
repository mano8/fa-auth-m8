"""Shared helpers for static compose/env policy tests.

Parsing Docker Compose files in tests needs a loader that tolerates Compose's
`!reset` / `!override` merge tags (used by the production overlay). Centralised
here so the overlay and socketless-path suites share one implementation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
STACK = REPO_ROOT / "examples" / "docker_compose" / "hardened_m8"


class ComposeLoader(yaml.SafeLoader):
    """SafeLoader that tolerates Compose's `!reset` / `!override` merge tags."""


def _identity(loader: ComposeLoader, node: yaml.Node) -> object:
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


ComposeLoader.add_constructor("!reset", _identity)
ComposeLoader.add_constructor("!override", _identity)


def load_compose(path: Path) -> dict:
    """Parse a compose file, tolerating the `!reset` / `!override` merge tags."""
    # ComposeLoader subclasses SafeLoader (only adds !reset/!override), so this
    # is a safe load despite using yaml.load to pass a custom Loader.
    return yaml.load(  # nosec B506
        path.read_text(encoding="utf-8"), Loader=ComposeLoader
    )


def parse_env(path: Path) -> dict[str, str]:
    """Parse a flat `KEY=value` env file, ignoring comments and blanks."""
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out
