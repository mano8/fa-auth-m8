"""Phase 1.0 — fa-auth-m8 Settings validator regression tests.

Codifies what is already true in fa-auth-m8's Settings so the security
invariants for service-specific secrets cannot silently regress.
No new production code is introduced; every assertion reflects current
behaviour.

Invariants locked in:
- FIRST_SUPERUSER_PASSWORD rejects "changethis" and enforces PASSWORD_REGEX
  (8+ chars, upper, lower, digit, special char, no spaces).
- PRIVATE_API_SECRET / SESSION_SECRET / TOKENS_ENCRYPTION_KEY reject
  "changethis" and enforce SECRET_KEY_REGEX (32+ chars, upper, lower,
  digit, non-alphanumeric, no spaces).
- EVENT_SIGNING_KEY (inherited from CommonSettings) also rejects "changethis".
- Error messages name the affected field (operator-actionable).
- The debug output path (model_dump minus secret_fields) does not expose
  any service-specific secret value.
"""

import pytest
from pydantic import ValidationError

from auth_user_service.core.config import Settings

# ── isolated settings construction ────────────────────────────────────────────
# All required fields for a valid Settings instance, bypassing dotenv.
# Pattern mirrors the _MINIMAL_SETTINGS in test_event_signing_boot.py.

_VALID_SETTINGS: dict = {
    "DOMAIN": "localhost",
    "ENVIRONMENT": "local",
    "API_PREFIX": "/user",
    "PROJECT_NAME": "TestApp",
    "STACK_NAME": "test-stack",
    "BACKEND_HOST": "http://localhost:9000",
    "FRONTEND_HOST": "http://localhost:5173",
    "BACKEND_CORS_ORIGINS": "http://localhost",
    # Opt into HS256 to avoid RS256's public-key-source requirement.
    # This mirrors the explicit opt-out pattern used in auth-sdk-m8/tests/conftest.py.
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
    """Construct Settings from kwargs only, bypassing the dotenv file."""
    return Settings(_env_file=None, **{**_VALID_SETTINGS, **overrides})


# ── baseline: valid construction succeeds ─────────────────────────────────────


def test_valid_settings_constructs() -> None:
    """A fully-populated valid settings dict must construct without error."""
    s = _make()
    assert s.ENVIRONMENT == "local"


# ── changethis / placeholder rejection ────────────────────────────────────────


@pytest.mark.parametrize(
    "field,match",
    [
        # PASSWORD_REGEX fires first for password fields (no upper/digit/special)
        ("FIRST_SUPERUSER_PASSWORD", "strong password|Insecure default"),
        # SECRET_KEY_REGEX fires first for secret-key fields (length/complexity)
        ("PRIVATE_API_SECRET", "valid secret key|Insecure default"),
        ("SESSION_SECRET", "valid secret key|Insecure default"),
        ("TOKENS_ENCRYPTION_KEY", "valid secret key|Insecure default"),
        # EVENT_SIGNING_KEY is a CommonSettings secret_key field
        ("EVENT_SIGNING_KEY", "valid secret key|Insecure default|EVENT_SIGNING_KEY"),
    ],
)
def test_changethis_rejected_for_service_secrets(field: str, match: str) -> None:
    """Service-specific secret fields must not accept the 'changethis' placeholder."""
    with pytest.raises((ValidationError, ValueError, RuntimeError), match=match):
        _make(**{field: "changethis"})


# ── password-strength enforcement on FIRST_SUPERUSER_PASSWORD ─────────────────


@pytest.mark.parametrize(
    "weak",
    [
        "short",  # below minimum length
        "alllower1!",  # no uppercase
        "ALLUPPER1!",  # no lowercase
        "NoDigitHere!",  # no digit
        "NoSpecialChar1",  # no special character
    ],
)
def test_weak_first_superuser_password_rejected(weak: str) -> None:
    """FIRST_SUPERUSER_PASSWORD must enforce PASSWORD_REGEX (8+ chars, complexity)."""
    with pytest.raises(
        (ValidationError, ValueError, RuntimeError), match="strong password"
    ):
        _make(FIRST_SUPERUSER_PASSWORD=weak)


# ── secret-key-strength enforcement on key fields ─────────────────────────────


@pytest.mark.parametrize(
    "field",
    ["PRIVATE_API_SECRET", "SESSION_SECRET", "TOKENS_ENCRYPTION_KEY"],
)
@pytest.mark.parametrize(
    "weak",
    [
        "short",  # well below 32 chars
        "a" * 32,  # 32 chars but all lowercase (no upper/digit/special)
        "Abcdef1234567890123456789012345",  # 31 chars + otherwise valid
    ],
)
def test_weak_secret_key_rejected(field: str, weak: str) -> None:
    """Key fields must enforce SECRET_KEY_REGEX (32+ chars, upper/lower/digit/special)."""
    with pytest.raises(
        (ValidationError, ValueError, RuntimeError), match="valid secret key"
    ):
        _make(**{field: weak})


# ── TOKENS_ENCRYPTION_KEY_OLD rotation key (plan item 6.2-pre) ────────────────


def test_tokens_encryption_key_old_defaults_to_none() -> None:
    """The rotation key is optional and unset in the steady state."""
    s = _make()
    assert s.TOKENS_ENCRYPTION_KEY_OLD is None


def test_tokens_encryption_key_old_accepts_valid_key() -> None:
    """When set during a rotation it must be a strong, distinct secret key."""
    s = _make(TOKENS_ENCRYPTION_KEY_OLD="Aa1-previous-encryption-key-32chars!!")
    assert s.TOKENS_ENCRYPTION_KEY_OLD is not None
    assert (
        s.TOKENS_ENCRYPTION_KEY_OLD.get_secret_value()
        == "Aa1-previous-encryption-key-32chars!!"
    )


@pytest.mark.parametrize(
    "weak",
    [
        "short",
        "a" * 32,
        "Abcdef1234567890123456789012345",
    ],
)
def test_weak_tokens_encryption_key_old_rejected(weak: str) -> None:
    """A supplied rotation key is strength-validated like the current key."""
    with pytest.raises(
        (ValidationError, ValueError, RuntimeError), match="valid secret key"
    ):
        _make(TOKENS_ENCRYPTION_KEY_OLD=weak)


def test_changethis_rejected_for_tokens_encryption_key_old() -> None:
    """The rotation key must not accept the 'changethis' placeholder when set."""
    with pytest.raises(
        (ValidationError, ValueError, RuntimeError),
        match="valid secret key|Insecure default",
    ):
        _make(TOKENS_ENCRYPTION_KEY_OLD="changethis")


def test_tokens_encryption_key_old_excluded_from_debug_output() -> None:
    """The rotation key is a secret_field and never leaks via the debug dump."""
    sentinel = "Aa1-rotation-sentinel-value-32chars!!"
    s = _make(TOKENS_ENCRYPTION_KEY_OLD=sentinel)
    assert "TOKENS_ENCRYPTION_KEY_OLD" in s.secret_fields
    assert "TOKENS_ENCRYPTION_KEY_OLD" in s.secret_keys
    public = s.model_dump()
    for field in s.secret_fields:
        public.pop(field, None)
    assert "TOKENS_ENCRYPTION_KEY_OLD" not in public
    assert sentinel not in str(public)


# ── operator-actionable error messages ────────────────────────────────────────


@pytest.mark.parametrize(
    "field",
    [
        "FIRST_SUPERUSER_PASSWORD",
        "PRIVATE_API_SECRET",
        "SESSION_SECRET",
        "TOKENS_ENCRYPTION_KEY",
    ],
)
def test_validation_error_names_affected_field(field: str) -> None:
    """Validation errors must mention the field name so the operator knows what to fix."""
    with pytest.raises((ValidationError, ValueError, RuntimeError)) as exc_info:
        _make(**{field: "changethis"})
    assert field in str(exc_info.value)


# ── debug output path: service secrets excluded ───────────────────────────────

# Fields listed in Settings.secret_fields that are fa-auth-m8-specific.
# These are explicitly popped from model_dump() in the __main__ debug path.
_SECRET_FIELD_NAMES = {
    "FIRST_SUPERUSER_PASSWORD",
    "PRIVATE_API_SECRET",
    "SESSION_SECRET",
    "TOKENS_ENCRYPTION_KEY",
}


def test_debug_output_excludes_secret_fields() -> None:
    """model_dump() minus secret_fields must not contain service secret keys."""
    s = _make()
    public = s.model_dump()
    for field in s.secret_fields:
        public.pop(field, None)
    for field in _SECRET_FIELD_NAMES:
        assert field not in public, f"{field} must be absent from debug output"


def test_debug_output_does_not_expose_raw_secret_value() -> None:
    """A known sentinel placed in a service secret must not appear in debug output."""
    sentinel = "Aa1-test-sentinel-value-32chars!!"
    s = _make(PRIVATE_API_SECRET=sentinel)
    public = s.model_dump()
    for field in s.secret_fields:
        public.pop(field, None)
    assert sentinel not in str(public)


def test_event_signing_key_value_not_exposed_in_debug_output() -> None:
    """EVENT_SIGNING_KEY stays in model_dump() as SecretStr — raw value never exposed.

    EVENT_SIGNING_KEY is not in secret_fields, so the __main__ debug path does
    not pop it.  The safety guarantee comes from SecretStr masking: the field's
    repr is '**********', not the raw value.
    """
    sentinel = "Aa1-test-event-key-sentinel-32ch!"
    s = _make(EVENT_SIGNING_KEY=sentinel)
    public = s.model_dump()
    # Raw value must not appear anywhere in the stringified output.
    assert sentinel not in str(public)
