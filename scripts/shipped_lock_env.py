"""Build and police a test environment that is the *shipped* dependency set.

`requirements_prod.lock` is the graph the release image installs with
`--require-hashes`. CI's test matrix installs `requirements_dev.txt` instead —
`-r requirements_base.txt` plus dev tools, every entry a `>=` floor — so it
exercises whatever resolves newest on the day it runs. The two sets are not the
same, and the shipped one was the one never executed.

This script supports the `test-shipped-lock` job:

  --emit-constraints PATH
      Write `name==version` for every pin in the lock, so test tooling can be
      installed *on top of* the shipped set without dragging any of it forward.

  --verify
      Assert every lock pin is installed at exactly its locked version. Without
      this, `pip install pytest` quietly upgrading a runtime package would put
      the job back to testing a set that is not the one that ships — the very
      defect the job exists to close, reintroduced by the job itself.
"""

from __future__ import annotations

import argparse
import re
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCK_FILE = REPO_ROOT / "auth_user_service" / "requirements_prod.lock"

# A lock line is `name==version \` or `name[extra1,extra2]==version \`. Hash
# continuation lines are indented, so anchoring at column 0 skips them.
_PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9,_-]+\])?==(\S+)")


def read_pins() -> dict[str, str]:
    """Map every distribution pinned in the lock to its locked version."""
    pins: dict[str, str] = {}
    for line in LOCK_FILE.read_text(encoding="utf-8").splitlines():
        match = _PIN_RE.match(line)
        if match:
            name, pinned = match.group(1), match.group(2).rstrip("\\").strip()
            pins[name] = pinned
    if not pins:
        sys.exit(f"no pins parsed from {LOCK_FILE} — the lock format changed")
    return pins


def emit_constraints(destination: Path) -> int:
    pins = read_pins()
    body = "\n".join(f"{name}=={pinned}" for name, pinned in sorted(pins.items()))
    destination.write_text(body + "\n", encoding="utf-8")
    print(f"wrote {len(pins)} constraints to {destination}")
    return 0


def verify_installed() -> int:
    """Fail if the environment has drifted from the lock in either direction."""
    drifted: list[str] = []
    missing: list[str] = []
    for name, pinned in sorted(read_pins().items()):
        try:
            installed = version(name)
        except PackageNotFoundError:
            missing.append(name)
            continue
        if installed != pinned:
            drifted.append(f"  {name}: lock pins {pinned}, environment has {installed}")

    if missing:
        print("NOT INSTALLED (the lock was not fully applied):", file=sys.stderr)
        for name in missing:
            print(f"  {name}", file=sys.stderr)
    if drifted:
        print(
            "DRIFTED (something moved a shipped package after the lock install):",
            file=sys.stderr,
        )
        for line in drifted:
            print(line, file=sys.stderr)
    if missing or drifted:
        print(
            "\nThis job only means something while the environment IS the shipped "
            "set. Pin the offending install with the emitted constraints file.",
            file=sys.stderr,
        )
        return 1

    print(f"environment matches all {len(read_pins())} lock pins")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--emit-constraints", type=Path, metavar="PATH")
    group.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        return verify_installed()
    return emit_constraints(args.emit_constraints)


if __name__ == "__main__":
    raise SystemExit(main())
