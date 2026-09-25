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

  --check-portable [LOCK ...]
      Refuse a lock (the shipped one unless others are named) that only
      resolves where it was generated. `pip-compile`
      resolves for the host it runs on and records that host's package
      sources, so a lock regenerated on a Windows workstation, or beside a
      sibling checkout, still installs on Linux and passes every other check
      here while shipping what it should not. Runs first in the job.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCK_FILE = REPO_ROOT / "auth_user_service" / "requirements_prod.lock"

# A lock line is `name==version \` or `name[extra1,extra2]==version \`. Hash
# continuation lines are indented, so anchoring at column 0 skips them.
_PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9,_-]+\])?==(\S+)")

# pip options that name a package source other than public PyPI, or install
# from a working tree. Any of them makes the lock depend on where it was made.
_SOURCE_OPTION_RE = re.compile(
    r"^(?:-f|--find-links|-i|--index-url|--extra-index-url|-e|--editable)(?=[\s=]|$)"
)
# A filesystem location: relative, home, absolute, a file URL or a Windows drive.
_PATH_RE = re.compile(r"(?:^|[\s=@])(?:\.{1,2}[\\/]|~[\\/]|/|file:|[A-Za-z]:[\\/])")

# Distributions that exist only for another platform. pip-compile adds them
# with no environment marker when it runs there, and the Linux image then
# installs them unconditionally. Keep the list short and name each reason.
PLATFORM_ONLY = {
    "colorama": "Windows ANSI shim pulled in by click",
    "pywin32": "Windows API bindings",
    "pywin32-ctypes": "Windows API bindings used by keyring",
    "pywinpty": "Windows pseudo-terminal",
}


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


def portability_problems(text: str) -> list[str]:
    """Name every lock line that ties the lock to the host that generated it."""
    problems: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if _SOURCE_OPTION_RE.match(line):
            problems.append(f"  line {number}: package-source option: {line}")
        elif not line.startswith("--hash=") and _PATH_RE.search(line):
            problems.append(f"  line {number}: filesystem path: {line}")
        elif match := _PIN_RE.match(line):
            name = match.group(1).lower().replace("_", "-")
            if name in PLATFORM_ONLY:
                problems.append(
                    f"  line {number}: {name} is platform-only "
                    f"({PLATFORM_ONLY[name]}); the lock was not resolved on Linux"
                )
    return problems


def check_portable(locks: Sequence[Path] = (LOCK_FILE,)) -> int:
    """Fail if any lock carries a host-specific source, path or distribution."""
    failed = False
    for lock in locks:
        problems = portability_problems(lock.read_text(encoding="utf-8"))
        if problems:
            failed = True
            print(f"NOT PORTABLE: {lock}", file=sys.stderr)
            for line in problems:
                print(line, file=sys.stderr)
        else:
            print(f"portable, PyPI-only resolve: {lock}")
    if failed:
        print(
            "\nRegenerate it inside the Dockerfile's own pinned base image, "
            "resolving from PyPI only.",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--emit-constraints", type=Path, metavar="PATH")
    group.add_argument("--verify", action="store_true")
    group.add_argument("--check-portable", nargs="*", type=Path, metavar="LOCK")
    args = parser.parse_args()
    if args.check_portable is not None:
        return check_portable(args.check_portable or (LOCK_FILE,))
    if args.verify:
        return verify_installed()
    return emit_constraints(args.emit_constraints)


if __name__ == "__main__":
    raise SystemExit(main())
