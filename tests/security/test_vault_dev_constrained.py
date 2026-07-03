"""Static-policy and preflight tests for the Vault example constraint (plan item 2.3).

Validates:
- vault_dev_m8 exists and is clearly marked dev-only (has -dev flag in compose,
  VAULT_DEV_TOKEN in .env.example, dev-mode docs in README).
- vault_prod_template exists and is free of dev-mode markers (no VAULT_DEV_TOKEN
  in any env or compose template, no -dev flag, scoped-token pattern present).
- preflight hard-fails when VAULT_DEV_TOKEN is present under ENVIRONMENT=production.
- preflight hard-fails when the compose has a Vault service in dev mode under production.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = REPO_ROOT / "examples" / "docker_compose"
VAULT_DEV = EXAMPLES / "vault_dev_m8"
VAULT_PROD_TMPL = EXAMPLES / "vault_prod_template"
PREFLIGHT = (
    REPO_ROOT
    / "examples"
    / "docker_compose"
    / "shared"
    / "scripts"
    / "preflight-security.sh"
)


def _run_preflight(stack_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(PREFLIGHT), str(stack_dir)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def _write_stack(
    stack_dir: Path,
    *,
    root_env: str = "",
    auth_env: str = "",
    compose: str = "",
) -> None:
    stack_dir.mkdir(parents=True, exist_ok=True)
    if root_env:
        (stack_dir / ".env").write_text(root_env, encoding="utf-8")
    if auth_env:
        (stack_dir / "auth.env").write_text(auth_env, encoding="utf-8")
    if compose:
        (stack_dir / "docker-compose.yml").write_text(compose, encoding="utf-8")


_PROD_ROOT_ENV = "\n".join(
    [
        "DB_USER=m8_admin",
        "DB_PASSWORD=root-admin-db-secret-A1!",
        "DB_PORT=5432",
        "AUTH_DB_USER=auth_user",
        "AUTH_DB_PASSWORD=auth-db-secret-A1!",
        "API_DB_USER=api_user",
        "API_DB_PASSWORD=api-db-secret-A1!",
        "REDIS_PASSWORD=redis-secret-A1!",
    ]
)

_PROD_AUTH_ENV = "\n".join(
    [
        "ENVIRONMENT=production",
        "STRICT_PRODUCTION_MODE=true",
        "BACKEND_CORS_ORIGINS=https://app.example.com",
        "SET_OPEN_API=false",
        "SET_DOCS=false",
        "SET_REDOC=false",
        "DB_PASSWORD=auth-db-secret-A1!",
        "REDIS_PASSWORD=redis-secret-A1!",
        "REFRESH_SECRET_KEY=refresh-secret-A1!",
        "PRIVATE_API_SECRET=private-api-secret-A1!",
        "SESSION_SECRET=session-secret-A1!",
        "TOKENS_ENCRYPTION_KEY=tokens-encryption-secret-A1!",
        "EVENT_SIGNING_ENABLED=true",
        "EVENT_SIGNING_KEY=event-signing-secret-A1!",
        "TOKEN_STRICT_VALIDATION=true",
        "ACCESS_REVOCATION_FAILURE_MODE=fail_closed",
    ]
)


# ── vault_dev_m8 structure ────────────────────────────────────────────────────


def test_vault_dev_m8_directory_exists() -> None:
    assert VAULT_DEV.is_dir(), "vault_dev_m8 directory must exist"


def test_vault_dev_m8_compose_has_vault_dev_flag() -> None:
    compose = (VAULT_DEV / "docker-compose.yml").read_text(encoding="utf-8")
    assert "- -dev" in compose, (
        "vault_dev_m8 compose must use Vault dev mode (-dev flag)"
    )


def test_vault_dev_m8_env_example_has_vault_dev_token() -> None:
    env = (VAULT_DEV / ".env.example").read_text(encoding="utf-8")
    assert "VAULT_DEV_TOKEN" in env, (
        ".env.example must document VAULT_DEV_TOKEN for dev mode"
    )


def test_vault_dev_m8_readme_marks_as_dev_only() -> None:
    readme = (VAULT_DEV / "README.md").read_text(encoding="utf-8")
    assert "dev" in readme.lower() and "production" in readme.lower(), (
        "README must document the dev-only nature and production distinction"
    )
    assert "vault_prod_template" in readme, (
        "README must link to vault_prod_template for the production path"
    )


def test_vault_dev_m8_has_no_old_name_in_readme() -> None:
    readme = (VAULT_DEV / "README.md").read_text(encoding="utf-8")
    assert "# vault_m8\n" not in readme, (
        "README heading must say vault_dev_m8, not vault_m8"
    )
    assert readme.startswith("# vault_dev_m8"), "README must be titled vault_dev_m8"


# ── vault_prod_template structure ────────────────────────────────────────────


def test_vault_prod_template_directory_exists() -> None:
    assert VAULT_PROD_TMPL.is_dir(), "vault_prod_template directory must exist"


def test_vault_prod_template_key_files_exist() -> None:
    for relative in (
        "README.md",
        "vault/config/vault.hcl",
        "vault/policies/app-policy.hcl",
        "docker-compose.app.yml.template",
    ):
        assert (VAULT_PROD_TMPL / relative).exists(), f"missing {relative}"


def _non_comment_lines(text: str) -> str:
    """Return only non-comment, non-blank lines from a text file."""
    return "\n".join(
        line
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


_CONFIG_EXTENSIONS = {".yml", ".yaml", ".env", ".hcl", ".sh", ".template"}


def test_vault_prod_template_has_no_vault_dev_token() -> None:
    """Config/compose/env files in vault_prod_template must not set VAULT_DEV_TOKEN.

    README and other docs legitimately mention it in prose ("must be absent"),
    so only config-type files are checked.
    """
    for path in VAULT_PROD_TMPL.rglob("*"):
        if not path.is_file() or path.suffix not in _CONFIG_EXTENSIONS:
            continue
        non_comment = _non_comment_lines(path.read_text(encoding="utf-8"))
        assert "VAULT_DEV_TOKEN" not in non_comment, (
            f"{path.relative_to(REPO_ROOT)}: vault_prod_template config files must not set"
            " or use VAULT_DEV_TOKEN (comments explaining what to avoid are fine)"
        )


def test_vault_prod_template_has_no_dev_mode_vault() -> None:
    for path in VAULT_PROD_TMPL.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        assert "- -dev" not in text and "server -dev" not in text, (
            f"{path.relative_to(REPO_ROOT)}: vault_prod_template must not use Vault dev mode"
        )


def test_vault_prod_template_hcl_uses_persistent_storage() -> None:
    hcl = (VAULT_PROD_TMPL / "vault" / "config" / "vault.hcl").read_text(
        encoding="utf-8"
    )
    assert "storage" in hcl and ("raft" in hcl or "file" in hcl), (
        "vault.hcl must configure persistent storage (raft or file)"
    )


def test_vault_prod_template_hcl_tls_not_disabled() -> None:
    hcl = (VAULT_PROD_TMPL / "vault" / "config" / "vault.hcl").read_text(
        encoding="utf-8"
    )
    assert "tls_disable = false" in hcl or "tls_disable   = false" in hcl, (
        "vault.hcl must have TLS enabled (tls_disable = false)"
    )
    assert "tls_disable = true" not in hcl, (
        "vault.hcl must not disable TLS in the production template"
    )


def test_vault_prod_template_compose_uses_docker_secret_not_env_token() -> None:
    compose_tmpl = (VAULT_PROD_TMPL / "docker-compose.app.yml.template").read_text(
        encoding="utf-8"
    )
    assert "vault_token" in compose_tmpl, (
        "template must use a Docker secret for the Vault token"
    )
    non_comment = _non_comment_lines(compose_tmpl)
    assert "VAULT_DEV_TOKEN" not in non_comment, (
        "template must not set VAULT_DEV_TOKEN (mentions in comments are fine)"
    )
    # VAULT_TOKEN must not appear as a live env var — only via the Docker secret path.
    assert "VAULT_TOKEN:" not in non_comment, (
        "template must not set VAULT_TOKEN as a compose environment var; "
        "the token arrives via Docker secret file /run/secrets/vault_token"
    )


def test_vault_prod_template_policy_is_read_only() -> None:
    policy = (VAULT_PROD_TMPL / "vault" / "policies" / "app-policy.hcl").read_text(
        encoding="utf-8"
    )
    assert '"read"' in policy, "app-policy.hcl must grant read capability"
    assert (
        '"create"' not in policy
        and '"update"' not in policy
        and '"delete"' not in policy
    ), "app-policy.hcl must not grant write/delete capabilities"


# ── preflight hard-fails dev Vault under production ──────────────────────────


def test_preflight_rejects_vault_dev_token_in_production(tmp_path: Path) -> None:
    root_env = _PROD_ROOT_ENV + "\nVAULT_DEV_TOKEN=some-generated-uuid-value\n"
    _write_stack(tmp_path, root_env=root_env, auth_env=_PROD_AUTH_ENV)

    result = _run_preflight(tmp_path)

    assert result.returncode == 1
    assert "VAULT_DEV_TOKEN" in result.stdout
    assert "production" in result.stdout


def test_preflight_rejects_vault_dev_mode_in_compose_under_production(
    tmp_path: Path,
) -> None:
    dev_compose = "\n".join(
        [
            "services:",
            "  vault:",
            "    image: hashicorp/vault:1.17",
            "    command:",
            "      - server",
            "      - -dev",
            "      - -dev-listen-address=0.0.0.0:8200",
            "  auth_user_service:",
            "    image: tepochtli/fa-auth-m8:1.1.0",
        ]
    )
    _write_stack(
        tmp_path, root_env=_PROD_ROOT_ENV, auth_env=_PROD_AUTH_ENV, compose=dev_compose
    )

    result = _run_preflight(tmp_path)

    assert result.returncode == 1
    assert "dev mode" in result.stdout.lower()


def test_preflight_accepts_production_without_vault_dev_markers(tmp_path: Path) -> None:
    prod_compose = "\n".join(
        [
            "services:",
            "  auth_user_service:",
            "    image: tepochtli/fa-auth-m8:1.1.0",
        ]
    )
    _write_stack(
        tmp_path,
        root_env=_PROD_ROOT_ENV,
        auth_env=_PROD_AUTH_ENV,
        compose=prod_compose,
    )

    result = _run_preflight(tmp_path)

    assert result.returncode == 0
    assert "passed" in result.stdout
