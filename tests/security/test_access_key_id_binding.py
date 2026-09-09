"""``ACCESS_KEY_ID`` ↔ key binding — audit finding ``J1`` (plan step ``W1.2``).

Before ``2.1.0`` ``ACCESS_KEY_ID`` was free text: nothing checked that the kid a
deployment published had any cryptographic relationship to the key it labelled.
A stack measured during the audit pinned a kid left over from an earlier
keypair, so regenerating the keys served a *different* public key under the
*same* kid — the reported symptom, produced across time rather than within one
request burst.

The settings validator now refuses to boot in that state. These tests cover the
four paths the plan calls out — mismatch fails, break-glass warns and proceeds,
HS256 is untouched, a consumer holding no local public key is untouched — plus
the boundaries around them.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import ValidationError

from auth_user_service.core.config import Settings
from auth_user_service.core.key_ids import derive_kid

# Same shape as tests/security/test_settings_validators.py: a complete, valid
# settings dict built from kwargs only, so no dotenv or ambient env is read.
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


def _make(**overrides) -> Settings:
    return Settings(_env_file=None, **{**_VALID_SETTINGS, **overrides})


def _write_rsa_keypair(directory: Path) -> tuple[Path, Path, str]:
    """Write a 2048-bit keypair; return (private path, public path, public PEM)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = directory / "private.pem"
    public_path = directory / "public.pem"
    private_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    public_pem = (
        key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    public_path.write_text(public_pem, encoding="utf-8")
    return private_path, public_path, public_pem


def _write_ec_keypair(directory: Path) -> tuple[Path, Path, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    private_path = directory / "ec_private.pem"
    public_path = directory / "ec_public.pem"
    private_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    public_pem = (
        key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    public_path.write_text(public_pem, encoding="utf-8")
    return private_path, public_path, public_pem


@pytest.fixture
def rs256_issuer(tmp_path: Path):
    """Kwargs for a valid RS256 issuer, plus the key's canonical kid."""
    private_path, public_path, public_pem = _write_rsa_keypair(tmp_path)
    return {
        "kwargs": {
            "ACCESS_TOKEN_ALGORITHM": "RS256",
            "ACCESS_PRIVATE_KEY_FILE": str(private_path),
            "ACCESS_PUBLIC_KEY_FILE": str(public_path),
        },
        "kid": derive_kid(public_pem),
        "public_pem": public_pem,
    }


# ── path 1: a kid that does not name its key refuses to boot ─────────────────


@pytest.mark.security
def test_unbound_access_key_id_fails_startup(rs256_issuer) -> None:
    """The J1 headline: the measured misconfiguration must now be fatal."""
    with pytest.raises(ValidationError) as exc:
        _make(**rs256_issuer["kwargs"], ACCESS_KEY_ID="5e0ede4bd13f9a13")

    assert "ACCESS_KEY_ID" in str(exc.value)


@pytest.mark.security
def test_unbound_error_names_the_expected_kid_and_the_fix(rs256_issuer) -> None:
    """Actionable: the operator gets the value to set and where it comes from."""
    with pytest.raises(ValidationError) as exc:
        _make(**rs256_issuer["kwargs"], ACCESS_KEY_ID="deadbeefdeadbeef")

    message = str(exc.value)
    assert rs256_issuer["kid"] in message
    assert "deadbeefdeadbeef" in message
    assert "init-keys.sh" in message
    assert "ACCESS_KEY_ID_ALLOW_UNBOUND" in message


@pytest.mark.security
def test_unbound_error_does_not_leak_key_material(rs256_issuer) -> None:
    """SEC-NO-SECRET-DISCLOSURE: kids are public labels, PEM bodies are not."""
    with pytest.raises(ValidationError) as exc:
        _make(**rs256_issuer["kwargs"], ACCESS_KEY_ID="deadbeefdeadbeef")

    body = "".join(rs256_issuer["public_pem"].splitlines()[1:-1])
    assert body[:32] not in str(exc.value)
    assert "BEGIN" not in str(exc.value)


@pytest.mark.security
def test_stale_kid_after_key_regeneration_fails(tmp_path: Path) -> None:
    """The exact mechanism from the audit: keys rotated, label left behind."""
    _, public_path, first_pem = _write_rsa_keypair(tmp_path)
    stale_kid = derive_kid(first_pem)

    # The operator regenerates the keypair in place and forgets the label.
    rotated = tmp_path / "rotated"
    rotated.mkdir()
    _, rotated_public, rotated_pem = _write_rsa_keypair(rotated)
    public_path.write_text(rotated_pem, encoding="utf-8")

    with pytest.raises(ValidationError) as exc:
        _make(
            ACCESS_TOKEN_ALGORITHM="RS256",
            ACCESS_PUBLIC_KEY_FILE=str(public_path),
            ACCESS_KEY_ID=stale_kid,
        )

    assert derive_kid(rotated_pem) in str(exc.value)
    assert rotated_public.exists()


# ── path 2: the break-glass opt-out warns and proceeds ───────────────────────


@pytest.mark.security
def test_allow_unbound_downgrades_the_failure_to_a_warning(
    rs256_issuer, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="auth_user_service.core.config"):
        settings = _make(
            **rs256_issuer["kwargs"],
            ACCESS_KEY_ID="deadbeefdeadbeef",
            ACCESS_KEY_ID_ALLOW_UNBOUND=True,
        )

    assert settings.ACCESS_KEY_ID == "deadbeefdeadbeef"
    assert "ACCESS_KEY_ID_ALLOW_UNBOUND" in caplog.text
    assert rs256_issuer["kid"] in caplog.text


@pytest.mark.security
def test_allow_unbound_exposes_the_warning_for_startup_logging(rs256_issuer) -> None:
    """main.py re-logs this once application logging is configured."""
    settings = _make(
        **rs256_issuer["kwargs"],
        ACCESS_KEY_ID="deadbeefdeadbeef",
        ACCESS_KEY_ID_ALLOW_UNBOUND=True,
    )
    assert settings.access_key_id_binding_warning is not None
    assert rs256_issuer["kid"] in settings.access_key_id_binding_warning


@pytest.mark.security
def test_allow_unbound_is_silent_when_the_binding_is_correct(rs256_issuer) -> None:
    """The break-glass flag must not itself become a warning source."""
    settings = _make(
        **rs256_issuer["kwargs"],
        ACCESS_KEY_ID=rs256_issuer["kid"],
        ACCESS_KEY_ID_ALLOW_UNBOUND=True,
    )
    assert settings.access_key_id_binding_warning is None


@pytest.mark.security
def test_allow_unbound_defaults_to_false() -> None:
    """Secure by default: the escape hatch is opt-in, never implicit."""
    assert _make().ACCESS_KEY_ID_ALLOW_UNBOUND is False


# ── path 3: HS256 is unaffected ──────────────────────────────────────────────


@pytest.mark.security
def test_hs256_ignores_access_key_id() -> None:
    """Symmetric deployments publish no key set and carry no kid at all."""
    settings = _make(ACCESS_KEY_ID="anything-at-all")
    assert settings.ACCESS_KEY_ID == "anything-at-all"
    assert settings.access_key_id_binding_warning is None


# ── path 4: a consumer holding no local public key is unaffected ─────────────


@pytest.mark.security
def test_jwks_only_consumer_is_unaffected() -> None:
    """No local key to bind against — the kid arrives in the JWKS document."""
    settings = _make(
        ACCESS_TOKEN_ALGORITHM="RS256",
        ACCESS_SECRET_KEY=None,
        AUTH_SERVICE_ROLE="consumer",
        JWKS_URI="https://auth.example.com/user/.well-known/jwks.json",
        ACCESS_KEY_ID="a-kid-from-somewhere-else",
    )
    assert settings.ACCESS_PUBLIC_KEY is None
    assert settings.access_key_id_binding_warning is None


@pytest.mark.security
def test_consumer_holding_a_public_key_is_still_validated(tmp_path: Path) -> None:
    """A consumer that pins a local key and a kid must have them agree too."""
    _, public_path, _ = _write_rsa_keypair(tmp_path)
    with pytest.raises(ValidationError):
        _make(
            ACCESS_TOKEN_ALGORITHM="RS256",
            AUTH_SERVICE_ROLE="consumer",
            ACCESS_PUBLIC_KEY_FILE=str(public_path),
            ACCESS_KEY_ID="deadbeefdeadbeef",
        )


# ── the bound and unset configurations still boot ────────────────────────────


@pytest.mark.security
def test_bound_access_key_id_boots(rs256_issuer) -> None:
    settings = _make(**rs256_issuer["kwargs"], ACCESS_KEY_ID=rs256_issuer["kid"])
    assert settings.ACCESS_KEY_ID == rs256_issuer["kid"]
    assert settings.access_key_id_binding_warning is None


@pytest.mark.security
@pytest.mark.parametrize("unset", [None, "", "   "])
def test_unset_access_key_id_boots(rs256_issuer, unset) -> None:
    """Unset is safe by construction: the kid *is* the derived fingerprint."""
    settings = _make(**rs256_issuer["kwargs"], ACCESS_KEY_ID=unset)
    assert settings.access_key_id_binding_warning is None


@pytest.mark.security
def test_surrounding_whitespace_is_tolerated(rs256_issuer) -> None:
    """An ``auth.env`` line with a trailing space is bound, not broken."""
    settings = _make(
        **rs256_issuer["kwargs"], ACCESS_KEY_ID=f"  {rs256_issuer['kid']}  "
    )
    assert settings.access_key_id_binding_warning is None


@pytest.mark.security
def test_es256_issuer_is_validated_the_same_way(tmp_path: Path) -> None:
    private_path, public_path, public_pem = _write_ec_keypair(tmp_path)
    kwargs = {
        "ACCESS_TOKEN_ALGORITHM": "ES256",
        "ACCESS_PRIVATE_KEY_FILE": str(private_path),
        "ACCESS_PUBLIC_KEY_FILE": str(public_path),
    }

    assert _make(**kwargs, ACCESS_KEY_ID=derive_kid(public_pem))

    with pytest.raises(ValidationError):
        _make(**kwargs, ACCESS_KEY_ID="deadbeefdeadbeef")
