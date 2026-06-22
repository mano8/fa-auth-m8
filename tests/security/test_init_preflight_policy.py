"""Static policy tests for the init-common.sh advisory preflight contract (item 0.4).

These tests parse the shell script directly — no running Docker or scanner required.

Policy:
  init-common.sh MUST shell out to `security-tests-m8 preflight` when the CLI
  is available, but MUST NOT exit on a non-zero return code — the invocation is
  advisory only and must never block `compose up`.

Contract rules verified:
  1. The scanner is invoked (positive: line is present).
  2. The invocation uses `|| _preflight_rc=$?` to capture — not propagate — the
     exit code (non-zero is never re-raised).
  3. A `command -v` guard wraps the call (graceful fallback when not installed).
  4. The script never calls `exit 1` (or any exit with a hard-coded non-zero
     code) in the preflight block — blocking init on preflight failure is the
     specific anti-pattern this item corrects.
  5. A fallback message is emitted when the scanner is absent, directing the
     operator to install it.
"""

from __future__ import annotations

import re
from pathlib import Path

_INIT_COMMON = (
    Path(__file__).resolve().parents[2]
    / "examples"
    / "docker_compose"
    / "shared"
    / "scripts"
    / "init-common.sh"
)


def _script() -> str:
    return _INIT_COMMON.read_text()


# ---------------------------------------------------------------------------
# Positive: scanner invocation is present
# ---------------------------------------------------------------------------


class TestPreflightInvocationPresent:
    """init-common.sh must invoke the security-tests-m8 scanner."""

    def test_scanner_cli_called(self):
        assert "security-tests-m8 preflight" in _script(), (
            "init-common.sh must call `security-tests-m8 preflight` — "
            "the advisory preflight block is missing."
        )

    def test_deployment_root_flag_passed(self):
        assert "--deployment-root" in _script(), (
            "init-common.sh must pass `--deployment-root` to the scanner so it "
            "inspects the correct compose directory."
        )

    def test_command_v_guard_present(self):
        assert "command -v security-tests-m8" in _script(), (
            "init-common.sh must guard the scanner call with "
            "`command -v security-tests-m8` so init works without the tool."
        )

    def test_fallback_install_hint_present(self):
        assert "pip install security-tests-m8" in _script(), (
            "init-common.sh must print an install hint when the scanner is absent."
        )


# ---------------------------------------------------------------------------
# Advisory contract: non-zero exit is captured, never propagated
# ---------------------------------------------------------------------------


class TestPreflightIsAdvisory:
    """The preflight invocation must never block compose up on failure."""

    def test_exit_code_captured_not_propagated(self):
        # The canonical advisory pattern: `cmd || _preflight_rc=$?`
        # captures a non-zero exit into a variable instead of aborting.
        assert re.search(
            r"security-tests-m8 preflight.*\|\|.*_preflight_rc=\$\?",
            _script(),
            re.DOTALL,
        ), (
            "init-common.sh must capture the scanner exit code with "
            "`|| _preflight_rc=$?` — a bare call would abort init on failure."
        )

    def test_no_exit_nonzero_in_preflight_block(self):
        # Extract the preflight block (between the preflight sentinel comment
        # and the env-bootstrap comment that follows it).
        script = _script()
        start = script.find("# --- Deployment security preflight")
        end = script.find("# --- Bootstrap missing env files", start)
        assert start != -1 and end != -1, (
            "Could not locate the preflight block in init-common.sh — "
            "check that the sentinel comments are still present."
        )
        block = script[start:end]

        # `exit 1` (or any hard-coded non-zero exit) must not appear inside the
        # preflight block; it would turn the advisory check into a hard gate.
        assert not re.search(r"\bexit\s+[1-9]", block), (
            "init-common.sh preflight block must not call `exit <non-zero>` — "
            "the block is advisory; failures must be reported, not fatal."
        )

    def test_proceeds_message_present(self):
        assert "init will proceed regardless" in _script(), (
            "init-common.sh must tell the operator that init proceeds despite "
            "preflight findings."
        )
