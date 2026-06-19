"""Phase 6.1 — inherited ``*_FILE`` secret mechanism (fa-auth-m8 consumer side).

fa-auth-m8 does **not** re-implement secret sourcing. Its ``Settings`` inherits
``settings_customise_sources`` — and therefore the Docker/K8s ``<FIELD>_FILE``
convention — from ``auth_sdk_m8.core.config.CommonSettings``. The production
overlay (plan item 2.1) relies on this so runtime secrets can be mounted under
``/run/secrets/*`` instead of being inlined as plaintext env values. No new
production code ships for this item; the mechanism lands in auth-sdk-m8.

These tests lock that inheritance in place *at the service layer*: a future MRO
change, field rename, or accidental override of ``settings_customise_sources``
on ``Settings`` would silently break secret-file mounting, and this suite is
what catches it. They prove the ``_FILE`` source covers fields from both origins
in the MRO:

* service-declared — ``METRICS_SCRAPE_CREDENTIAL``, ``SESSION_SECRET``,
  ``PRIVATE_API_SECRET`` (``auth_user_service/core/config.py``),
* ``CommonSettings`` — ``DB_PASSWORD``.

Source precedence (init kwargs > ``*_FILE`` > ``.env`` > env > secrets-dir >
Vault) and fail-closed behaviour on a missing mount are also asserted, since the
overlay depends on a file mount outranking a plaintext value while a misconfigured
mount must never silently fall back.
"""

import pytest
from pydantic import SecretStr

from auth_user_service.core.config import Settings

# Full valid settings dict, mirroring tests/security/test_settings_validators.py.
# Init kwargs outrank the ``_FILE`` source, so any field whose mount is under
# test must be omitted from the constructor (see ``_make_without``).
_VALID_SETTINGS: dict = {
    "DOMAIN": "localhost",
    "ENVIRONMENT": "local",
    "API_PREFIX": "/user",
    "PROJECT_NAME": "TestApp",
    "STACK_NAME": "test-stack",
    "BACKEND_HOST": "http://localhost:9000",
    "FRONTEND_HOST": "http://localhost:5173",
    "BACKEND_CORS_ORIGINS": "http://localhost",
    "ACCESS_TOKEN_ALGORITHM": "HS256",
    "ACCESS_SECRET_KEY": "Aa1-test-access-secret-key-32chars!!",
    "REFRESH_SECRET_KEY": "Aa1-test-refresh-secret-key-32chars!",
    "DB_HOST": "localhost",
    "DB_PORT": 3306,
    "DB_DATABASE": "test_db",
    "DB_USER": "test_user",
    "DB_PASSWORD": "TestPass1@#!",
    "REDIS_HOST": "localhost",
    "REDIS_PORT": 6379,
    "REDIS_USER": "testuser",
    "REDIS_PASSWORD": "TestRedis1@#!",
    "FIRST_SUPERUSER": "admin@example.com",
    "FIRST_SUPERUSER_PASSWORD": "TestAdmin1@#!",
    "PRIVATE_API_SECRET": "Aa1-test-private-api-secret-32chars!!",
    "SESSION_SECRET": "Aa1-test-session-secret-32chars-here!",
    "TOKENS_ENCRYPTION_KEY": "Aa1-test-encryption-key-32chars-here!",
    "EVENT_SIGNING_KEY": "Aa1-test-event-signing-key-32chars!!",
    "TOKEN_STRICT_VALIDATION": False,
}


def _make_without(*omit: str, **overrides: object) -> Settings:
    """Build ``Settings`` from the valid dict with *omit* fields left unset.

    Bypasses the dotenv file (``_env_file=None``) so only kwargs + env/`_FILE`
    sources participate. A field whose ``_FILE`` mount is under test must be
    omitted here, otherwise the init kwarg (highest precedence) would win.
    """
    kwargs = {k: v for k, v in _VALID_SETTINGS.items() if k not in omit}
    return Settings(_env_file=None, **{**kwargs, **overrides})


# ── secrets sourced from a mounted file, across both MRO origins ──────────────


def test_optional_service_secret_sourced_from_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """An optional service-declared secret reads its ``<FIELD>_FILE`` mount.

    ``METRICS_SCRAPE_CREDENTIAL`` is unset in the valid dict (default ``None``),
    so the file source is the only thing that can populate it.
    """
    secret = tmp_path / "scrape_credential"
    secret.write_text("scrape-from-file\n", encoding="utf-8")
    monkeypatch.setenv("METRICS_SCRAPE_CREDENTIAL_FILE", str(secret))

    s = _make_without()

    assert s.METRICS_SCRAPE_CREDENTIAL is not None
    assert s.METRICS_SCRAPE_CREDENTIAL.get_secret_value() == "scrape-from-file"


def test_required_service_secret_sourced_from_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """A required service-declared secret (``SESSION_SECRET``) reads its mount.

    The file content must still satisfy ``SECRET_KEY_REGEX``, proving validators
    run on the file-sourced value exactly as on a plaintext one.
    """
    secret = tmp_path / "session_secret"
    secret.write_text("Aa1-session-secret-from-file-32chars!\n", encoding="utf-8")
    monkeypatch.setenv("SESSION_SECRET_FILE", str(secret))

    s = _make_without("SESSION_SECRET")

    assert s.SESSION_SECRET.get_secret_value() == "Aa1-session-secret-from-file-32chars!"


def test_private_api_secret_sourced_from_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """``PRIVATE_API_SECRET`` (service-declared) reads its mount.

    Anchors the no-key-reuse principle: each service sources its own internal
    secret from its own mount, never a shared inline value.
    """
    secret = tmp_path / "private_api_secret"
    secret.write_text("Aa1-private-api-secret-from-file-32c!\n", encoding="utf-8")
    monkeypatch.setenv("PRIVATE_API_SECRET_FILE", str(secret))

    s = _make_without("PRIVATE_API_SECRET")

    assert (
        s.PRIVATE_API_SECRET.get_secret_value()
        == "Aa1-private-api-secret-from-file-32c!"
    )


def test_common_settings_secret_sourced_from_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """A ``CommonSettings`` secret (``DB_PASSWORD``) reads its mount."""
    secret = tmp_path / "db_password"
    secret.write_text("DbFromFile1@#!\n", encoding="utf-8")
    monkeypatch.setenv("DB_PASSWORD_FILE", str(secret))

    s = _make_without("DB_PASSWORD")

    assert s.DB_PASSWORD.get_secret_value() == "DbFromFile1@#!"


# ── source precedence + fail-closed behaviour ────────────────────────────────


def test_file_mount_overrides_plaintext_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """``<FIELD>_FILE`` outranks a plaintext env value for the same field."""
    secret = tmp_path / "scrape_credential"
    secret.write_text("from-file\n", encoding="utf-8")
    monkeypatch.setenv("METRICS_SCRAPE_CREDENTIAL", "from-plain-env")
    monkeypatch.setenv("METRICS_SCRAPE_CREDENTIAL_FILE", str(secret))

    s = _make_without()

    assert s.METRICS_SCRAPE_CREDENTIAL is not None
    assert s.METRICS_SCRAPE_CREDENTIAL.get_secret_value() == "from-file"


def test_init_kwarg_outranks_file_mount(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Explicit constructor kwargs still win over a ``<FIELD>_FILE`` mount."""
    secret = tmp_path / "scrape_credential"
    secret.write_text("from-file\n", encoding="utf-8")
    monkeypatch.setenv("METRICS_SCRAPE_CREDENTIAL_FILE", str(secret))

    s = _make_without(METRICS_SCRAPE_CREDENTIAL=SecretStr("from-init"))

    assert s.METRICS_SCRAPE_CREDENTIAL is not None
    assert s.METRICS_SCRAPE_CREDENTIAL.get_secret_value() == "from-init"


def test_missing_secret_file_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Pointing ``<FIELD>_FILE`` at an absent file fails closed at construction.

    A misconfigured mount must never silently fall back to a plaintext value.
    """
    monkeypatch.setenv("SESSION_SECRET_FILE", str(tmp_path / "absent"))

    with pytest.raises(
        (ValueError, RuntimeError),
        match="SESSION_SECRET_FILE points to a missing file",
    ):
        _make_without("SESSION_SECRET")


# ── secret masking on the file-sourced value ─────────────────────────────────


def test_file_sourced_secret_is_masked(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """A file-sourced ``SecretStr`` is never rendered in ``repr`` or the debug dump."""
    secret = tmp_path / "scrape_credential"
    secret.write_text("super-sensitive\n", encoding="utf-8")
    monkeypatch.setenv("METRICS_SCRAPE_CREDENTIAL_FILE", str(secret))

    s = _make_without()

    assert "super-sensitive" not in repr(s)
    assert s.METRICS_SCRAPE_CREDENTIAL is not None
    assert "super-sensitive" not in str(s.METRICS_SCRAPE_CREDENTIAL)

    # Debug path (model_dump minus secret_fields) must not leak the value either.
    public = s.model_dump()
    for field in s.secret_fields:
        public.pop(field, None)
    assert "super-sensitive" not in str(public)
