"""Locked, hashed release-dependency policy tests — finding 11.8.

Release Docker images must install from a fully pinned, hash-locked dependency
set so that rebuilding the same source cannot silently resolve a different
dependency graph. These tests parse the lock file, the service Dockerfile, and
the publish workflow — no Docker or network is required.

Regenerate the lock with (Python 3.12, matching the fleet baseline)::

    pip-compile --generate-hashes --no-emit-index-url \
        --output-file=requirements_prod.lock requirements_prod.txt
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVICE = REPO_ROOT / "auth_user_service"
DOCKERFILE = SERVICE / "Dockerfile"
LOCK = SERVICE / "requirements_prod.lock"
REQ_BASE = SERVICE / "requirements_base.txt"
REQ_PROD = SERVICE / "requirements_prod.txt"
PUBLISH_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "docker-publish.yaml"

# A pinned requirement line, e.g. ``auth-sdk-m8==2.1.1 \``.
_PIN_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]+\])?==")
# Any range/inequality operator that would break reproducibility.
_RANGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]+\])?\s*(>=|<=|~=|!=|>|<)")


def _normalize(name: str) -> str:
    """Normalize a distribution name to its canonical comparison form."""
    return name.lower().replace("_", "-")


def _lock_lines() -> list[str]:
    return LOCK.read_text().splitlines()


def _lock_pins() -> dict[str, int]:
    """Return {normalized-name: line-index} for every pinned lock requirement."""
    pins: dict[str, int] = {}
    for idx, line in enumerate(_lock_lines()):
        m = _PIN_RE.match(line)
        if m:
            pins[_normalize(m.group("name"))] = idx
    return pins


def _declared_top_level() -> set[str]:
    """Top-level dependency names declared across base + prod requirement files."""
    names: set[str] = set()
    for req in (REQ_BASE, REQ_PROD):
        for raw in req.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "-r ", "-c ", "-")):
                continue
            token = re.split(r"[<>=!~\[; ]", line, maxsplit=1)[0]
            if token:
                names.add(_normalize(token))
    return names


# ── lock integrity ──────────────────────────────────────────────────────────


def test_lock_file_exists() -> None:
    """The hash-locked production requirement set must be committed."""
    assert LOCK.is_file(), (
        "requirements_prod.lock is missing — generate it with "
        "pip-compile --generate-hashes."
    )


def test_lock_every_requirement_is_pinned_and_hashed() -> None:
    """Every requirement is exact-pinned (``==``) and carries a sha256 hash."""
    lines = _lock_lines()
    pins = _lock_pins()
    assert pins, "No pinned requirements found in requirements_prod.lock."
    ordered = sorted(pins.values())
    for pos, start in enumerate(ordered):
        end = ordered[pos + 1] if pos + 1 < len(ordered) else len(lines)
        block = "\n".join(lines[start:end])
        assert "--hash=sha256:" in block, (
            f"{lines[start].split()[0]} in requirements_prod.lock has no hash "
            f"— regenerate with pip-compile --generate-hashes."
        )


def test_lock_has_no_version_ranges() -> None:
    """No lock requirement uses a range operator — reproducibility demands ``==``."""
    for line in _lock_lines():
        assert not _RANGE_RE.match(line), (
            f"requirements_prod.lock contains an unpinned range: {line!r}"
        )


def test_lock_uses_no_custom_index_url() -> None:
    """The lock must resolve from public PyPI only (no private index leakage)."""
    text = LOCK.read_text()
    for directive in ("--index-url", "--extra-index-url"):
        assert directive not in text, (
            f"requirements_prod.lock pins a custom index ({directive}); "
            f"internal packages must publish to public PyPI."
        )


def test_lock_pins_internal_auth_sdk() -> None:
    """The internal auth-sdk-m8 dependency is pinned and hashed like any other."""
    assert "auth-sdk-m8" in _lock_pins(), (
        "auth-sdk-m8 must appear as a pinned, hashed entry in the lock."
    )


def test_lock_covers_all_declared_top_level_deps() -> None:
    """Every declared base/prod dependency is present in the locked set."""
    missing = _declared_top_level() - set(_lock_pins())
    assert not missing, (
        f"requirements_prod.lock is missing declared dependencies: {sorted(missing)} "
        f"— regenerate the lock from requirements_prod.txt."
    )


# ── Dockerfile release install ──────────────────────────────────────────────


def test_dockerfile_copies_lock() -> None:
    """The Dockerfile must COPY the lock into the build context."""
    assert "requirements_prod.lock" in DOCKERFILE.read_text(), (
        "Dockerfile does not COPY requirements_prod.lock."
    )


def test_dockerfile_release_install_requires_hashes() -> None:
    """The non-development install path enforces --require-hashes against the lock."""
    text = DOCKERFILE.read_text()
    assert "--require-hashes" in text, (
        "Dockerfile release install must use pip --require-hashes."
    )
    require_line = next(
        (ln for ln in text.splitlines() if "--require-hashes" in ln), ""
    )
    # The hashed install and its requirements file may be split across lines by
    # the shell line-continuation; assert both invariants over the whole file.
    assert "-r requirements_prod.lock" in text, (
        "Dockerfile --require-hashes install must target requirements_prod.lock."
    )
    assert "requirements_dev" not in require_line, (
        "Dev requirements must not be installed on the hash-locked release path."
    )


# ── SBOM corresponds to the locked environment ──────────────────────────────


def test_publish_workflow_sbom_reflects_locked_prod_env() -> None:
    """The scanned/SBOM'd image must build the locked production install path.

    The publish workflow must not override the Dockerfile's default
    ``ENVIRONMENT=production`` with ``development``; otherwise the SBOM would
    describe the unlocked dev dependency graph instead of the released one.
    """
    text = PUBLISH_WORKFLOW.read_text()
    assert "anchore/sbom-action" in text, "Publish workflow must generate an SBOM."
    assert "ENVIRONMENT=development" not in text, (
        "Publish workflow builds with ENVIRONMENT=development — the SBOM would "
        "not reflect the hash-locked production dependency set."
    )
