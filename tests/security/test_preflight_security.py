from __future__ import annotations

import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = (
    REPO_ROOT
    / "examples"
    / "docker_compose"
    / "shared"
    / "scripts"
    / "preflight-security.sh"
)


def run_preflight(stack_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(PREFLIGHT), str(stack_dir)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def write_stack(
    stack_dir: Path,
    *,
    root_env: str = "",
    auth_env: str = "",
    api_env: str = "",
    compose: str = "",
    grafana: str = "",
) -> None:
    stack_dir.mkdir(parents=True, exist_ok=True)
    if root_env:
        (stack_dir / ".env").write_text(root_env, encoding="utf-8")
    if auth_env:
        (stack_dir / "auth.env").write_text(auth_env, encoding="utf-8")
    if api_env:
        (stack_dir / "api.env").write_text(api_env, encoding="utf-8")
    if compose:
        (stack_dir / "docker-compose.yml").write_text(compose, encoding="utf-8")
    if grafana:
        grafana_dir = stack_dir / "grafana"
        grafana_dir.mkdir(exist_ok=True)
        (grafana_dir / "config.monitoring").write_text(grafana, encoding="utf-8")


def production_root_env() -> str:
    return "\n".join(
        [
            "API_BIND_IP=127.0.0.1",
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


def production_auth_env(*, strict: bool = True) -> str:
    return "\n".join(
        [
            "ENVIRONMENT=production",
            f"STRICT_PRODUCTION_MODE={'true' if strict else 'false'}",
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


def production_api_env() -> str:
    return "\n".join(
        [
            "ENVIRONMENT=production",
            "BACKEND_CORS_ORIGINS=https://app.example.com",
            "SET_OPEN_API=false",
            "SET_DOCS=false",
            "SET_REDOC=false",
            "DB_PASSWORD=api-db-secret-A1!",
            "REFRESH_SECRET_KEY=refresh-secret-A1!",
            "PRIVATE_API_SECRET=private-api-secret-A1!",
            "EVENT_SIGNING_ENABLED=true",
            "EVENT_SIGNING_KEY=event-signing-secret-A1!",
            "TOKEN_STRICT_VALIDATION=true",
            "ACCESS_REVOCATION_FAILURE_MODE=fail_closed",
        ]
    )


def test_preflight_rejects_changethis_in_real_env(tmp_path: Path) -> None:
    write_stack(
        tmp_path,
        root_env="DB_ROOT_PASSWORD=changethis\nREDIS_PASSWORD=redis-secret-A1!\n",
    )

    result = run_preflight(tmp_path)

    assert result.returncode == 1
    assert "replace placeholder value for DB_ROOT_PASSWORD" in result.stdout


def test_preflight_rejects_duplicate_high_value_secret_groups(
    tmp_path: Path,
) -> None:
    write_stack(
        tmp_path,
        root_env="\n".join(
            [
                "DB_PASSWORD=root-admin-db-secret-A1!",
                "AUTH_DB_PASSWORD=reused-secret-A1!",
                "API_DB_PASSWORD=reused-secret-A1!",
                "REDIS_PASSWORD=redis-secret-A1!",
            ]
        ),
    )

    result = run_preflight(tmp_path)

    assert result.returncode == 1
    assert "secret value for API_DB_PASSWORD is reused" in result.stdout


def test_preflight_rejects_public_api_bind_in_production(
    tmp_path: Path,
) -> None:
    root_env = production_root_env().replace(
        "API_BIND_IP=127.0.0.1", "API_BIND_IP=0.0.0.0"
    )
    write_stack(
        tmp_path,
        root_env=root_env,
        auth_env=production_auth_env(),
        api_env=production_api_env(),
    )

    result = run_preflight(tmp_path)

    assert result.returncode == 1
    assert "API_BIND_IP=0.0.0.0 is blocked in production" in result.stdout


def test_preflight_allows_public_api_bind_with_break_glass(
    tmp_path: Path,
) -> None:
    root_env = (
        production_root_env().replace("API_BIND_IP=127.0.0.1", "API_BIND_IP=0.0.0.0")
        + "\nALLOW_PUBLIC_API_BIND=true"
    )
    write_stack(
        tmp_path,
        root_env=root_env,
        auth_env=production_auth_env(),
        api_env=production_api_env(),
    )

    result = run_preflight(tmp_path)

    assert result.returncode == 0, (
        "ALLOW_PUBLIC_API_BIND=true must suppress the API_BIND_IP=0.0.0.0 block"
    )
    assert "API_BIND_IP=0.0.0.0 is blocked in production" not in result.stdout


def test_preflight_rejects_latest_images_for_hardened_or_production(
    tmp_path: Path,
) -> None:
    stack_dir = tmp_path / "hardened_m8"
    write_stack(
        stack_dir,
        root_env=production_root_env(),
        auth_env=production_auth_env(),
        api_env=production_api_env(),
        compose="services:\n  auth:\n    image: tepochtli/fa-auth-m8:latest\n",
    )

    result = run_preflight(stack_dir)

    assert result.returncode == 1
    assert "not :latest" in result.stdout


def test_preflight_rejects_vault_and_grafana_defaults(tmp_path: Path) -> None:
    write_stack(
        tmp_path,
        root_env="\n".join(
            [
                "DB_PASSWORD=root-admin-db-secret-A1!",
                "AUTH_DB_PASSWORD=auth-db-secret-A1!",
                "API_DB_PASSWORD=api-db-secret-A1!",
                "REDIS_PASSWORD=redis-secret-A1!",
                "VAULT_DEV_TOKEN=changethis",
            ]
        ),
        grafana="GF_SECURITY_ADMIN_PASSWORD=foobar\n",
    )

    result = run_preflight(tmp_path)

    assert result.returncode == 1
    assert "VAULT_DEV_TOKEN must be generated" in result.stdout
    assert "Grafana admin password must be generated" in result.stdout


def test_preflight_warns_for_risky_flags_outside_strict_mode(
    tmp_path: Path,
) -> None:
    write_stack(
        tmp_path,
        root_env=production_root_env(),
        auth_env=production_auth_env(strict=False).replace(
            "ACCESS_REVOCATION_FAILURE_MODE=fail_closed",
            "ACCESS_REVOCATION_FAILURE_MODE=fail_open",
        ),
        api_env=production_api_env(),
    )

    result = run_preflight(tmp_path)

    assert result.returncode == 0
    assert "M8 security preflight warnings" in result.stdout
    assert "ACCESS_REVOCATION_FAILURE_MODE=fail_open" in result.stdout


def test_preflight_checks_each_service_env_file(tmp_path: Path) -> None:
    unsafe_api_env = (
        production_api_env()
        .replace("SET_DOCS=false", "SET_DOCS=true")
        .replace(
            "BACKEND_CORS_ORIGINS=https://app.example.com",
            "BACKEND_CORS_ORIGINS=http://localhost:5173",
        )
    )
    write_stack(
        tmp_path,
        root_env=production_root_env(),
        auth_env=production_auth_env(),
        api_env=unsafe_api_env,
    )

    result = run_preflight(tmp_path)

    assert result.returncode == 1
    assert "api.env" in result.stdout
    assert "SET_DOCS must be false" in result.stdout
    assert "must not include localhost origins" in result.stdout


def test_preflight_accepts_generated_production_values(tmp_path: Path) -> None:
    write_stack(
        tmp_path,
        root_env=production_root_env(),
        auth_env=production_auth_env(),
        api_env=production_api_env(),
        compose="services:\n  auth:\n    image: tepochtli/fa-auth-m8:1.2.3\n",
        grafana="GF_SECURITY_ADMIN_PASSWORD=grafana-admin-secret-A1!\n",
    )

    result = run_preflight(tmp_path)

    assert result.returncode == 0
    assert "M8 security preflight passed" in result.stdout
