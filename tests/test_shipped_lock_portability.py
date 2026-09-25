"""The shipped lock must be a portable, PyPI-only Linux resolve.

`pip-compile` resolves for the host it runs on and writes that host's package
sources into the lock. A lock regenerated on a Windows workstation gains
Windows-only distributions with no environment marker, and one regenerated
beside a sibling checkout gains a `--find-links` into it. Both still install
on Linux, so every other lock check stays green while the image ships them.

`scripts/shipped_lock_env.py --check-portable` refuses such a lock and runs
first in CI's `test-shipped-lock` job; these tests pin its behaviour and its
place in that job. No Docker or network access is required.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "shipped_lock_env.py"
CI_YAML = REPO_ROOT / ".github" / "workflows" / "CI.yaml"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("shipped_lock_env", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shipped_lock_env = _load_script()


def test_the_shipped_lock_is_portable() -> None:
    text = shipped_lock_env.LOCK_FILE.read_text(encoding="utf-8")
    assert shipped_lock_env.portability_problems(text) == []
    assert shipped_lock_env.check_portable() == 0


@pytest.mark.parametrize(
    "line",
    [
        "--find-links ../../media-sdk-m8/dist",
        "-f ./dist",
        "--index-url https://mirror.example/simple",
        "-i https://mirror.example/simple",
        "--extra-index-url=https://mirror.example/simple",
        "-e .",
        "--editable ../sibling",
        "pkg @ file:///tmp/pkg-1.0-py3-none-any.whl",
        "./wheels/pkg-1.0-py3-none-any.whl",
        r"C:\wheels\pkg-1.0-py3-none-any.whl",
        "colorama==0.4.6 \\",
        "pywin32==311 \\",
        "pywin32_ctypes==0.2.3 \\",
        "PyWinPTY==3.0.2 \\",
    ],
)
def test_a_host_specific_line_is_refused(line: str) -> None:
    assert shipped_lock_env.portability_problems(line), line


@pytest.mark.parametrize(
    "line",
    [
        "#    pip-compile --find-links=../../media-sdk-m8/dist --generate-hashes",
        "arq==0.28.0 \\",
        "httpx[http2]==0.28.1 \\",
        "    --hash=sha256:a458188aefc2d7ee17d136f80d8fa8df1d6eba4ceebdead87e9f172d027dc311",
        "    # via -r requirements_base.txt",
        "exceptiongroup==1.3.0 ; python_version < '3.11' \\",
    ],
)
def test_an_ordinary_lock_line_passes(line: str) -> None:
    assert shipped_lock_env.portability_problems(line) == []


def test_ci_checks_portability_before_installing_the_lock() -> None:
    text = CI_YAML.read_text(encoding="utf-8")
    job = text[text.index("test-shipped-lock:") :]
    check = job.find("shipped_lock_env.py --check-portable")
    install = job.find("--require-hashes")
    assert check != -1, "test-shipped-lock does not run --check-portable"
    assert check < install, "--check-portable must run before the lock install"
