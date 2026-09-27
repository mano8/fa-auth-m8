"""C2 — account-lifecycle and mail settings (contract §7).

Locks in the configuration half of the optional account-lifecycle features:

- every feature is off by default, and that default starts cleanly;
- every invalid implication fails startup with a message naming settings only,
  never a configured value;
- the SMTP credentials are ``SecretStr``/redacted, ``*_FILE``-sourceable, and
  refuse the ``changethis`` placeholder;
- the challenge TTL bounds come from ``core.challenge_tokens`` and cannot drift;
- ``GOOGLE_OAUTH_ENABLED`` is tri-state, with unset keeping the 2.2.3 behavior.
"""

from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from auth_sdk_m8.schemas.base import AuthProviderType

from auth_user_service.core.challenge_tokens import CHALLENGE_TTLS, ChallengePurpose
from auth_user_service.core.config import Settings
from auth_user_service.schemas.account_lifecycle import EmailVerificationMode
from tests.security.test_settings_validators import _VALID_SETTINGS

# Distinctive values that must never surface in a startup error.
_SMTP_PASSWORD = "Smtp-Relay-Secret-9f3b7c2e"
_SMTP_USER = "relay-user-4d1e"
_GOOGLE = {
    "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
    "GOOGLE_CLIENT_SECRET": "TestGoogle!Secret1secureKeyXYZ098",
    "GOOGLE_OAUTH_REDIRECT_URI": "https://auth.example.com/user/google-auth/oauth-callback/",
}
# A complete, valid mail configuration for a non-local environment.
_MAIL = {
    "MAIL_ENABLED": True,
    "SMTP_HOST": "smtp.example.com",
    "SMTP_USER": _SMTP_USER,
    "SMTP_PASSWORD": _SMTP_PASSWORD,
    "EMAILS_FROM_EMAIL": "no-reply@example.com",
    "PUBLIC_UI_URL": "https://app.example.com",
    "ALLOWED_HOSTS": "auth.example.com",
}


# The test environment exports Google credentials; start from none so each test
# states the Google configuration it needs.
_BASE = {**_VALID_SETTINGS, "GOOGLE_CLIENT_ID": None, "GOOGLE_CLIENT_SECRET": None}


def _make(**overrides: object) -> Settings:
    """Construct Settings from kwargs only, bypassing the dotenv file."""
    return Settings(_env_file=None, **{**_BASE, **overrides})


def _startup_error(**overrides: object) -> str:
    """Return the startup failure message for *overrides*."""
    with pytest.raises(ValidationError) as exc:
        _make(**overrides)
    return str(exc.value)


# ── defaults: everything off behaves as 2.2.3 ────────────────────────────────


def test_defaults_turn_every_new_feature_off() -> None:
    s = _make()
    assert s.PASSWORD_LOGIN_ENABLED is True
    assert s.GOOGLE_OAUTH_ENABLED is None
    assert s.PUBLIC_SIGNUP_ENABLED is False
    assert s.PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS == []
    assert s.MAIL_ENABLED is False
    assert s.EMAIL_VERIFICATION_MODE == EmailVerificationMode.OFF
    assert s.PASSWORD_RESET_ENABLED is False
    assert s.PUBLIC_UI_URL == ""
    assert s.SMTP_USER is None and s.SMTP_PASSWORD is None
    assert s.SMTP_TLS_MODE == "starttls"
    assert s.login_providers == (AuthProviderType.PASSWORD,)


def test_documented_defaults_for_budgets_and_expiry() -> None:
    s = _make()
    assert s.UNVERIFIED_SIGNUP_EXPIRY_DAYS == 7
    assert s.MAIL_RECIPIENT_COOLDOWN_SECONDS == 60
    assert s.MAIL_RECIPIENT_DAILY_CAP == 10
    assert s.SMTP_TIMEOUT_SECONDS == 10.0
    assert s.ACCOUNT_ACTION_RATE_LIMIT_WINDOW_MINUTES == 15
    assert s.ACCOUNT_ACTION_IP_RATE_LIMIT_REQUESTS == 20
    assert s.ACCOUNT_ACTION_EMAIL_RATE_LIMIT_REQUESTS == 5


def test_full_mail_configuration_starts_outside_local() -> None:
    s = _make(
        ENVIRONMENT="staging",
        PUBLIC_SIGNUP_ENABLED=True,
        PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS="example.com",
        EMAIL_VERIFICATION_MODE="required",
        PASSWORD_RESET_ENABLED=True,
        SMTP_TLS_MODE="implicit",
        **_MAIL,
    )
    assert s.EMAIL_VERIFICATION_MODE == EmailVerificationMode.REQUIRED
    assert s.PUBLIC_UI_URL == "https://app.example.com"


def test_public_signup_without_mail_runs_with_verification_off() -> None:
    s = _make(PUBLIC_SIGNUP_ENABLED=True)
    assert s.MAIL_ENABLED is False
    assert s.EMAIL_VERIFICATION_MODE == EmailVerificationMode.OFF


# ── startup failures (contract §7) ────────────────────────────────────────────


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        pytest.param(
            {"PASSWORD_LOGIN_ENABLED": False},
            "No login method is enabled",
            id="no-login-method",
        ),
        pytest.param(
            {"PASSWORD_LOGIN_ENABLED": False, "GOOGLE_OAUTH_ENABLED": False, **_GOOGLE},
            "No login method is enabled",
            id="no-login-method-google-forced-off",
        ),
        pytest.param(
            {"PUBLIC_SIGNUP_ENABLED": True, "PASSWORD_LOGIN_ENABLED": False, **_GOOGLE},
            "PUBLIC_SIGNUP_ENABLED=true requires PASSWORD_LOGIN_ENABLED=true",
            id="signup-without-password-login",
        ),
        pytest.param(
            {"EMAIL_VERIFICATION_MODE": "optional"},
            "EMAIL_VERIFICATION_MODE=optional requires MAIL_ENABLED=true",
            id="optional-verification-without-mail",
        ),
        pytest.param(
            {"EMAIL_VERIFICATION_MODE": "required"},
            "EMAIL_VERIFICATION_MODE=required requires MAIL_ENABLED=true",
            id="required-verification-without-mail",
        ),
        pytest.param(
            {"PASSWORD_RESET_ENABLED": True},
            "PASSWORD_RESET_ENABLED=true requires MAIL_ENABLED=true",
            id="reset-without-mail",
        ),
        pytest.param(
            {
                "PASSWORD_RESET_ENABLED": True,
                "PASSWORD_LOGIN_ENABLED": False,
                **_GOOGLE,
                **_MAIL,
            },
            "PASSWORD_RESET_ENABLED=true requires PASSWORD_LOGIN_ENABLED=true",
            id="reset-without-password-login",
        ),
        pytest.param(
            {**_MAIL, "SMTP_HOST": None},
            "MAIL_ENABLED=true requires SMTP_HOST",
            id="mail-without-smtp-host",
        ),
        pytest.param(
            {**_MAIL, "EMAILS_FROM_EMAIL": None},
            "MAIL_ENABLED=true requires EMAILS_FROM_EMAIL",
            id="mail-without-sender",
        ),
        pytest.param(
            {**_MAIL, "PUBLIC_UI_URL": ""},
            "MAIL_ENABLED=true requires PUBLIC_UI_URL",
            id="mail-without-ui-url",
        ),
        pytest.param(
            {
                **_MAIL,
                "ENVIRONMENT": "staging",
                "PUBLIC_UI_URL": "http://app.example.com",
            },
            "PUBLIC_UI_URL must use https",
            id="mail-with-http-ui-url-outside-local",
        ),
        pytest.param(
            {**_MAIL, "ALLOWED_HOSTS": None},
            "requires a non-empty ALLOWED_HOSTS",
            id="mail-without-allowed-hosts",
        ),
        pytest.param(
            {**_MAIL, "ALLOWED_HOSTS": " , "},
            "requires a non-empty ALLOWED_HOSTS",
            id="mail-with-blank-allowed-hosts",
        ),
        pytest.param(
            {"SMTP_TLS_MODE": "none", "ENVIRONMENT": "staging"},
            "SMTP_TLS_MODE=none is allowed only with ENVIRONMENT=local",
            id="plaintext-smtp-outside-local",
        ),
        pytest.param(
            {"GOOGLE_OAUTH_ENABLED": True},
            "GOOGLE_OAUTH_ENABLED=true requires GOOGLE_CLIENT_ID",
            id="google-forced-on-without-credentials",
        ),
        pytest.param(
            {"SMTP_USER": _SMTP_USER},
            "SMTP_USER and SMTP_PASSWORD must be set together",
            id="smtp-user-without-password",
        ),
        pytest.param(
            {"SMTP_PASSWORD": _SMTP_PASSWORD},
            "SMTP_USER and SMTP_PASSWORD must be set together",
            id="smtp-password-without-user",
        ),
    ],
)
def test_invalid_implication_fails_startup_without_naming_a_secret(
    overrides: dict[str, object], match: str
) -> None:
    message = _startup_error(**overrides)
    assert match in message
    for secret in (_SMTP_PASSWORD, _SMTP_USER, _GOOGLE["GOOGLE_CLIENT_SECRET"]):
        assert secret not in message


def test_http_ui_url_is_accepted_under_local() -> None:
    s = _make(**{**_MAIL, "PUBLIC_UI_URL": "http://localhost:4321/"})
    assert s.PUBLIC_UI_URL == "http://localhost:4321"


def test_plaintext_smtp_is_accepted_under_local() -> None:
    assert _make(SMTP_TLS_MODE="none").SMTP_TLS_MODE == "none"


def test_unauthenticated_relay_needs_no_credentials() -> None:
    s = _make(**{**_MAIL, "SMTP_USER": None, "SMTP_PASSWORD": None})
    assert s.SMTP_USER is None and s.SMTP_PASSWORD is None


def test_unknown_tls_mode_is_rejected() -> None:
    assert "SMTP_TLS_MODE" in _startup_error(SMTP_TLS_MODE="ssl")


def test_unknown_verification_mode_is_rejected() -> None:
    assert "EMAIL_VERIFICATION_MODE" in _startup_error(EMAIL_VERIFICATION_MODE="on")


# ── Google tri-state ──────────────────────────────────────────────────────────


def test_google_unset_follows_credentials_as_in_2_2_3() -> None:
    assert _make().google_login_enabled is False
    s = _make(**_GOOGLE)
    assert s.google_login_enabled is True
    assert s.login_providers == (AuthProviderType.PASSWORD, AuthProviderType.GOOGLE)


def test_google_false_turns_google_off_despite_credentials() -> None:
    s = _make(GOOGLE_OAUTH_ENABLED=False, **_GOOGLE)
    assert s.google_login_enabled is False
    assert s.login_providers == (AuthProviderType.PASSWORD,)


def test_google_true_with_credentials_is_on() -> None:
    assert _make(GOOGLE_OAUTH_ENABLED=True, **_GOOGLE).google_login_enabled is True


def test_google_only_deployment_starts() -> None:
    s = _make(PASSWORD_LOGIN_ENABLED=False, **_GOOGLE)
    assert s.login_providers == (AuthProviderType.GOOGLE,)


# ── PUBLIC_UI_URL shape ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("app.example.com", "absolute http(s) URL"),
        ("ftp://app.example.com", "absolute http(s) URL"),
        ("https://", "absolute http(s) URL"),
        ("https://user:pw@app.example.com", "must not contain credentials"),
        ("https://app.example.com/?next=x", "must not contain a query or fragment"),
        ("https://app.example.com/#frag", "must not contain a query or fragment"),
        ("https://app.example.com/?", "must not contain a query or fragment"),
    ],
)
def test_public_ui_url_rejects_unsafe_shapes(value: str, match: str) -> None:
    assert match in _startup_error(PUBLIC_UI_URL=value)


def test_public_ui_url_keeps_a_path_prefix_without_trailing_slash() -> None:
    assert _make(PUBLIC_UI_URL=" https://example.com/app/ ").PUBLIC_UI_URL == (
        "https://example.com/app"
    )


# ── PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS ───────────────────────────────────────


def test_domain_allowlist_is_normalized_and_deduplicated() -> None:
    s = _make(
        PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS=" Example.COM, b.example.org,,example.com"
    )
    assert s.PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS == ["example.com", "b.example.org"]


def test_domain_allowlist_accepts_a_list() -> None:
    s = _make(PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS=["example.com"])
    assert s.PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS == ["example.com"]


def test_domain_allowlist_none_is_empty() -> None:
    assert (
        _make(
            PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS=None
        ).PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS
        == []
    )


def test_domain_allowlist_reads_a_comma_list_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS", "example.com,example.org")
    s = _make()
    assert s.PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS == ["example.com", "example.org"]


@pytest.mark.parametrize(
    "value",
    ["*.example.com", "user@example.com", "localhost", "example.com:25", "-a.com"],
)
def test_domain_allowlist_rejects_non_domains(value: str) -> None:
    assert "PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS" in _startup_error(
        PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS=value
    )


# ── bounds ────────────────────────────────────────────────────────────────────

_TTL_FIELDS = {
    "EMAIL_VERIFICATION_TTL_MINUTES": ChallengePurpose.EMAIL_VERIFICATION,
    "PASSWORD_RESET_TTL_MINUTES": ChallengePurpose.PASSWORD_RESET,
    "EMAIL_CHANGE_TTL_MINUTES": ChallengePurpose.EMAIL_CHANGE,
}


@pytest.mark.parametrize(("field", "purpose"), _TTL_FIELDS.items())
def test_ttl_settings_follow_the_challenge_token_bounds(
    field: str, purpose: ChallengePurpose
) -> None:
    ttl = CHALLENGE_TTLS[purpose]
    minutes = lambda delta: int(delta.total_seconds() // 60)  # noqa: E731
    assert getattr(_make(), field) == minutes(ttl.default)
    assert getattr(_make(**{field: minutes(ttl.minimum)}), field) == minutes(
        ttl.minimum
    )
    assert getattr(_make(**{field: minutes(ttl.maximum)}), field) == minutes(
        ttl.maximum
    )
    assert field in _startup_error(**{field: minutes(ttl.minimum) - 1})
    assert field in _startup_error(**{field: minutes(ttl.maximum) + 1})


@pytest.mark.parametrize(
    ("field", "low", "high"),
    [
        ("UNVERIFIED_SIGNUP_EXPIRY_DAYS", 0, 31),
        ("MAIL_RECIPIENT_COOLDOWN_SECONDS", 9, 3601),
        ("MAIL_RECIPIENT_DAILY_CAP", 0, 101),
        ("SMTP_TIMEOUT_SECONDS", 0, 61),
        ("ACCOUNT_ACTION_RATE_LIMIT_WINDOW_MINUTES", 0, 1441),
        ("ACCOUNT_ACTION_IP_RATE_LIMIT_REQUESTS", 0, 100001),
        ("ACCOUNT_ACTION_EMAIL_RATE_LIMIT_REQUESTS", 0, 1001),
    ],
)
def test_budget_and_limit_bounds(field: str, low: float, high: float) -> None:
    assert field in _startup_error(**{field: low})
    assert field in _startup_error(**{field: high})


# ── secrets ───────────────────────────────────────────────────────────────────


def test_smtp_password_is_a_redacted_secret() -> None:
    s = _make(**_MAIL)
    assert isinstance(s.SMTP_PASSWORD, SecretStr)
    assert s.SMTP_PASSWORD.get_secret_value() == _SMTP_PASSWORD
    assert _SMTP_PASSWORD not in repr(s)
    assert _SMTP_PASSWORD not in str(s.model_dump())


def test_debug_dump_drops_smtp_credentials() -> None:
    s = _make(**_MAIL)
    public = s.model_dump()
    for name in s.secret_fields:
        public.pop(name, None)
    assert "SMTP_USER" not in public and "SMTP_PASSWORD" not in public


@pytest.mark.parametrize("field", ["SMTP_USER", "SMTP_PASSWORD"])
def test_smtp_credentials_reject_the_placeholder(field: str) -> None:
    message = _startup_error(**{**_MAIL, field: "changethis"})
    assert f"Insecure default value for '{field}'" in message


def test_smtp_password_is_file_sourceable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_file = tmp_path / "smtp_password"
    secret_file.write_text(f"{_SMTP_PASSWORD}\n", encoding="utf-8")
    monkeypatch.setenv("SMTP_PASSWORD_FILE", str(secret_file))
    overrides = {k: v for k, v in _MAIL.items() if k != "SMTP_PASSWORD"}
    s = _make(**overrides)
    assert s.SMTP_PASSWORD is not None
    assert s.SMTP_PASSWORD.get_secret_value() == _SMTP_PASSWORD


@pytest.mark.parametrize("value", ["user\r\nMAIL FROM:<x@y>", "user\x00", "user\x7f"])
def test_smtp_user_rejects_control_characters(value: str) -> None:
    assert "SMTP_USER must not contain control characters" in _startup_error(
        **{**_MAIL, "SMTP_USER": value}
    )


def test_no_setting_turns_tls_verification_off() -> None:
    # STARTTLS failure is fatal and certificates are always verified; there is
    # deliberately no knob that could weaken either.
    names = set(Settings.model_fields)
    assert not {n for n in names if n.startswith("SMTP_") and "VERIFY" in n}
    assert not {n for n in names if n.startswith("SMTP_") and "INSECURE" in n}
