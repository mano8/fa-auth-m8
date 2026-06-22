from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
INIT_COMMON = (
    REPO_ROOT / "examples" / "docker_compose" / "shared" / "scripts" / "init-common.sh"
)


def _env_mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def _write_dev_env_examples(stack_dir: Path) -> None:
    """Write minimal valid .example files that pass preflight in dev mode."""
    (stack_dir / ".env.example").write_text(
        "DB_USER=m8_admin\n"
        "DB_PASSWORD=dev-db-secret-x1!\n"
        "REDIS_PASSWORD=dev-redis-secret-x1!\n",
        encoding="utf-8",
    )
    (stack_dir / "auth.env.example").write_text(
        "ACCESS_TOKEN_ALGORITHM=HS256\n"
        "ACCESS_SECRET_KEY=dev-access-secret-x1!\n"
        "REFRESH_SECRET_KEY=dev-refresh-secret-x1!\n"
        "PRIVATE_API_SECRET=dev-private-api-secret-x1!\n"
        "SESSION_SECRET=dev-session-secret-x1!\n"
        "TOKENS_ENCRYPTION_KEY=dev-tokens-enc-secret-x1!\n",
        encoding="utf-8",
    )
    (stack_dir / "api.env.example").write_text(
        "ACCESS_SECRET_KEY=dev-api-access-secret-x1!\n"
        "REFRESH_SECRET_KEY=dev-api-refresh-secret-x1!\n"
        "PRIVATE_API_SECRET=dev-api-private-secret-x1!\n",
        encoding="utf-8",
    )


def _run_init_common(stack_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(INIT_COMMON)],
        cwd=str(stack_dir),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def test_init_common_sets_chmod_600_on_newly_copied_env_files(
    tmp_path: Path,
) -> None:
    _write_dev_env_examples(tmp_path)

    result = _run_init_common(tmp_path)

    assert result.returncode == 0, result.stdout
    for env_file in (".env", "auth.env", "api.env"):
        p = tmp_path / env_file
        assert p.exists(), f"{env_file} was not created"
        assert _env_mode(p) == 0o600, (
            f"{env_file} mode is {oct(_env_mode(p))}, expected 0o600"
        )


def test_init_common_fixes_permissive_existing_env_files(tmp_path: Path) -> None:
    _write_dev_env_examples(tmp_path)
    # Pre-create env files with permissive mode (simulating manually-created files)
    for env_file in (".env", "auth.env", "api.env"):
        p = tmp_path / env_file
        p.write_text("ACCESS_TOKEN_ALGORITHM=HS256\nACCESS_SECRET_KEY=dev-secret-x1!\n")
        os.chmod(p, 0o644)

    result = _run_init_common(tmp_path)

    assert result.returncode == 0, result.stdout
    for env_file in (".env", "auth.env", "api.env"):
        p = tmp_path / env_file
        assert _env_mode(p) == 0o600, (
            f"{env_file} mode is {oct(_env_mode(p))}, expected 0o600"
        )
    assert "enforced chmod 600" in result.stdout


def test_init_common_fixes_permissive_private_key(tmp_path: Path) -> None:
    _write_dev_env_examples(tmp_path)
    # Pre-create a private key with wrong perms
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    priv = keys_dir / "private.pem"
    priv.write_text("FAKE-PEM-CONTENT")
    os.chmod(priv, 0o644)

    result = _run_init_common(tmp_path)

    assert result.returncode == 0, result.stdout
    assert _env_mode(priv) == 0o600, (
        f"keys/private.pem mode is {oct(_env_mode(priv))}, expected 0o600"
    )
    assert "enforced chmod 600" in result.stdout


def test_init_common_skips_perm_report_when_all_modes_correct(
    tmp_path: Path,
) -> None:
    _write_dev_env_examples(tmp_path)
    # Pre-create env files already at 600
    for env_file in (".env", "auth.env", "api.env"):
        p = tmp_path / env_file
        p.write_text("ACCESS_TOKEN_ALGORITHM=HS256\nACCESS_SECRET_KEY=dev-secret-x1!\n")
        os.chmod(p, 0o600)

    result = _run_init_common(tmp_path)

    assert result.returncode == 0, result.stdout
    assert "enforced chmod 600" not in result.stdout
