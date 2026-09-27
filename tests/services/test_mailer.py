"""M1 — building, addressing, and sending account-lifecycle mail."""

from typing import Optional

import pytest
from pydantic import SecretStr

from auth_user_service.core.challenge_tokens import (
    ChallengePurpose,
    ChallengeTokenRejected,
    mint_challenge_token,
)
from auth_user_service.core.config import Settings
from auth_user_service.core.mail_transport import (
    InMemoryMailTransport,
    MailDeliveryError,
    MailFailure,
    SmtpMailTransport,
)
from auth_user_service.services.mail_templates import MailLocale, MailTemplate
from auth_user_service.services.mailer import (
    CHALLENGE_UI_PATHS,
    MailAddressRejected,
    Mailer,
    MailRequest,
    validate_recipient,
)
from tests.security.test_settings_validators import _VALID_SETTINGS

_BASE = {**_VALID_SETTINGS, "GOOGLE_CLIENT_ID": None, "GOOGLE_CLIENT_SECRET": None}
_MAIL = {
    "MAIL_ENABLED": True,
    "SMTP_HOST": "smtp.example.com",
    "SMTP_PORT": 465,
    "SMTP_TLS_MODE": "implicit",
    "EMAILS_FROM_EMAIL": "no-reply@example.com",
    "EMAILS_FROM_NAME": "M8 Accounts",
    "PUBLIC_UI_URL": "https://app.example.com/portal/",
    "ALLOWED_HOSTS": "auth.example.com",
    "PASSWORD_RESET_TTL_MINUTES": 20,
}


def _settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **{**_BASE, **overrides})


def _mailer(transport: Optional[InMemoryMailTransport] = None) -> Mailer:
    mailer = Mailer.from_settings(
        _settings(**_MAIL), transport=transport or InMemoryMailTransport()
    )
    assert mailer is not None
    return mailer


def _token(purpose: ChallengePurpose) -> SecretStr:
    return mint_challenge_token(purpose).token


# ── construction from settings ───────────────────────────────────────────────


def test_mail_disabled_builds_no_mailer_and_no_transport() -> None:
    assert Mailer.from_settings(_settings()) is None


def test_default_transport_is_smtp_from_settings_without_connecting() -> None:
    credentials = {"SMTP_USER": "relay-user", "SMTP_PASSWORD": f"pw-{id(object())}"}
    mailer = Mailer.from_settings(_settings(**_MAIL, **credentials))
    assert mailer is not None
    transport = mailer.transport
    assert isinstance(transport, SmtpMailTransport)
    assert (transport.host, transport.port, transport.tls_mode) == (
        "smtp.example.com",
        465,
        "implicit",
    )
    assert transport.timeout_seconds == 10.0
    assert transport.username == "relay-user"
    assert transport.password is not None
    assert transport.password.get_secret_value() == credentials["SMTP_PASSWORD"]


def test_mailer_takes_links_and_ttls_from_settings_only() -> None:
    mailer = _mailer()
    assert mailer.public_ui_url == "https://app.example.com/portal"
    assert mailer.sender_email == "no-reply@example.com"
    assert mailer.sender_name == "M8 Accounts"
    assert mailer.ttl_minutes == {
        ChallengePurpose.EMAIL_VERIFICATION: 1440,
        ChallengePurpose.PASSWORD_RESET: 20,
        ChallengePurpose.EMAIL_CHANGE: 60,
    }


def test_incomplete_mail_settings_are_refused_even_if_unvalidated() -> None:
    broken = _settings(**_MAIL).model_copy(update={"SMTP_HOST": None})
    with pytest.raises(ValueError, match="SMTP_HOST"):
        Mailer.from_settings(broken)


# ── composing ────────────────────────────────────────────────────────────────


def test_message_is_multipart_text_and_html_with_configured_headers() -> None:
    message = _mailer().compose(
        MailRequest(MailTemplate.PASSWORD_CHANGED_NOTICE, "User@Example.COM")
    )
    assert message.get_content_type() == "multipart/alternative"
    assert [p.get_content_type() for p in message.iter_parts()] == [
        "text/plain",
        "text/html",
    ]
    assert message["From"] == "M8 Accounts <no-reply@example.com>"
    assert message["To"] == "User@example.com"
    assert message["Subject"] == "Your password was changed"
    assert message["Auto-Submitted"] == "auto-generated"
    assert message["Message-ID"].endswith("@example.com>")
    assert message["Date"].endswith("+0000")


def test_sender_without_a_name_is_the_bare_address() -> None:
    settings = _settings(**{**_MAIL, "EMAILS_FROM_NAME": None})
    mailer = Mailer.from_settings(settings, transport=InMemoryMailTransport())
    assert mailer is not None
    message = mailer.compose(MailRequest(MailTemplate.ACCOUNT_EXISTS, "a@example.com"))
    assert message["From"] == "no-reply@example.com"


@pytest.mark.parametrize("purpose", list(ChallengePurpose))
def test_link_is_ui_base_plus_page_plus_fragment_token(
    purpose: ChallengePurpose,
) -> None:
    template = next(t for t in MailTemplate if t.challenge_purpose is purpose)
    token = _token(purpose)
    message = _mailer().compose(
        MailRequest(template, "user@example.com", MailLocale.ES, token=token)
    )
    expected = (
        f"https://app.example.com/portal{CHALLENGE_UI_PATHS[purpose]}"
        f"#token={token.get_secret_value()}"
    )
    text = message.get_body(("plain",))
    assert text is not None and expected in text.get_content()


def test_ui_pages_are_the_contract_ones() -> None:
    assert CHALLENGE_UI_PATHS == {
        ChallengePurpose.EMAIL_VERIFICATION: "/auth/verify-email",
        ChallengePurpose.PASSWORD_RESET: "/auth/reset-password",
        ChallengePurpose.EMAIL_CHANGE: "/auth/confirm-email-change",
    }


def test_expiry_comes_from_the_configured_ttl() -> None:
    message = _mailer().compose(
        MailRequest(
            MailTemplate.PASSWORD_RESET,
            "user@example.com",
            token=_token(ChallengePurpose.PASSWORD_RESET),
        )
    )
    text = message.get_body(("plain",))
    assert text is not None and "expires in 20 minutes" in text.get_content()


@pytest.mark.parametrize(
    "token",
    [
        None,
        SecretStr("m8vfy_" + "A" * 43),  # another purpose's shape
        SecretStr("eyJhbGciOiJIUzI1NiJ9.e30.sig"),  # a JWT
        SecretStr("m8rst_short"),
    ],
)
def test_link_template_refuses_anything_but_its_own_token(
    token: Optional[SecretStr],
) -> None:
    transport = InMemoryMailTransport()
    with pytest.raises(ChallengeTokenRejected):
        _mailer(transport).send(
            MailRequest(MailTemplate.PASSWORD_RESET, "user@example.com", token=token)
        )
    assert transport.sent == []


# ── sending ──────────────────────────────────────────────────────────────────


def test_send_hands_the_composed_message_to_the_transport() -> None:
    transport = InMemoryMailTransport()
    _mailer(transport).send(
        MailRequest(MailTemplate.EMAIL_CHANGED_NOTICE, "old@example.com", MailLocale.FR)
    )
    [message] = transport.sent
    assert message["To"] == "old@example.com"
    assert message["Subject"] == "Votre adresse e-mail a été modifiée"


def test_transport_failure_propagates_as_delivery_error() -> None:
    transport = InMemoryMailTransport(fail_with=MailFailure.CONNECT)
    with pytest.raises(MailDeliveryError):
        _mailer(transport).send(
            MailRequest(MailTemplate.ACCOUNT_EXISTS, "user@example.com")
        )


# ── recipient validation ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "address",
    [
        "user@example.com\r\nBcc: victim@example.com",
        "user@example.com\nBcc: victim@example.com",
        "Attacker <user@example.com>",
        "user@example.com, other@example.com",
        " user@example.com",
        "usér@example.com",
        "user@exämple.com",
        "not-an-address",
        "",
    ],
)
def test_only_a_bare_ascii_address_is_a_recipient(address: str) -> None:
    with pytest.raises(MailAddressRejected) as exc:
        validate_recipient(address)
    if address:
        assert address not in str(exc.value)


def test_recipient_domain_is_normalized() -> None:
    assert validate_recipient("Ana@Example.COM") == "Ana@example.com"
