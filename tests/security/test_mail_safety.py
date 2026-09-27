"""M1 — mail safety proofs (contract §4, §5.8).

- no header injection: the recipient, the sender name, and the account name
  cannot add a header or a recipient;
- no HTML injection: the account name is escaped in the HTML body;
- the token appears only in the link fragment of the body, never in a header
  or the subject, and never in a ``repr``;
- nothing reads the request: the mail modules do not import FastAPI or
  Starlette, so no link can come from ``Host``;
- nothing logs: sending emits no log record, so no token or address can leak
  through logging.
"""

import ast
import inspect
import logging
from types import ModuleType

import pytest
from pydantic import ValidationError

from auth_user_service.core import mail_transport
from auth_user_service.core.challenge_tokens import (
    ChallengePurpose,
    mint_challenge_token,
)
from auth_user_service.core.config import Settings
from auth_user_service.core.mail_transport import InMemoryMailTransport
from auth_user_service.services import mail_templates, mailer
from auth_user_service.services.mail_templates import MailLocale, MailTemplate
from auth_user_service.services.mailer import (
    MailAddressRejected,
    Mailer,
    MailRequest,
)
from tests.security.test_settings_validators import _VALID_SETTINGS

_MAIL_MODULES = [mail_transport, mail_templates, mailer]
_BASE = {**_VALID_SETTINGS, "GOOGLE_CLIENT_ID": None, "GOOGLE_CLIENT_SECRET": None}


def _mailer(transport: InMemoryMailTransport, sender_name: str = "M8") -> Mailer:
    return Mailer(
        transport=transport,
        sender_email="no-reply@example.com",
        sender_name=sender_name,
        public_ui_url="https://app.example.com",
        ttl_minutes={purpose: 30 for purpose in ChallengePurpose},
    )


def _imports(module: ModuleType) -> set[str]:
    tree = ast.parse(inspect.getsource(module))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


@pytest.mark.parametrize("module", _MAIL_MODULES, ids=lambda m: m.__name__)
def test_mail_modules_never_see_the_request(module: ModuleType) -> None:
    assert not {"fastapi", "starlette"} & _imports(module)


@pytest.mark.parametrize("module", _MAIL_MODULES, ids=lambda m: m.__name__)
def test_mail_modules_never_log(module: ModuleType) -> None:
    assert "logging" not in _imports(module)


@pytest.mark.parametrize("template", list(MailTemplate))
def test_token_only_in_the_body_fragment(
    template: MailTemplate, caplog: pytest.LogCaptureFixture
) -> None:
    purpose = template.challenge_purpose
    issued = None if purpose is None else mint_challenge_token(purpose)
    token = None if issued is None else issued.token
    request = MailRequest(template, "user@example.com", MailLocale.EN, token=token)
    transport = InMemoryMailTransport()
    with caplog.at_level(logging.DEBUG):
        _mailer(transport).send(request)
    assert caplog.records == []
    [message] = transport.sent
    headers = "\n".join(f"{k}: {v}" for k, v in message.items())
    assert "token" not in headers.lower()
    assert "m8vfy_" not in headers and "m8rst_" not in headers
    assert "m8eml_" not in headers
    if token is None:
        return
    raw = token.get_secret_value()
    assert raw not in repr(request)
    for part in message.iter_parts():
        body = part.get_content()
        # Present only as the fragment of a UI link, never as a query or path.
        assert body.count(raw) == body.count(f"#token={raw}") >= 1
        assert f"?token={raw}" not in body and f"/{raw}" not in body


def test_header_injection_through_the_account_name_goes_nowhere() -> None:
    transport = InMemoryMailTransport()
    _mailer(transport).send(
        MailRequest(
            MailTemplate.ACCOUNT_EXISTS,
            "user@example.com",
            full_name="Ana\r\nBcc: victim@example.com\r\n\r\n<script>",
        )
    )
    [message] = transport.sent
    assert message["Bcc"] is None
    assert set(message.keys()) == {
        "Subject",
        "From",
        "To",
        "Date",
        "Message-ID",
        "Auto-Submitted",
        "Content-Type",
        "MIME-Version",
    }


def test_account_name_is_escaped_in_html() -> None:
    transport = InMemoryMailTransport()
    _mailer(transport).send(
        MailRequest(
            MailTemplate.PASSWORD_RESET_COMPLETED,
            "user@example.com",
            full_name='<img src=x onerror="alert(1)"> & <a href="https://evil">',
        )
    )
    html_part = transport.sent[0].get_body(("html",))
    assert html_part is not None
    html_body = html_part.get_content()
    assert "<img" not in html_body and "<a " not in html_body
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt; &amp; &lt;a" in html_body
    assert 'href="https://evil"' not in html_body


@pytest.mark.parametrize(
    "address", ["a@example.com\r\nBcc: b@example.com", "a\x00@x.io"]
)
def test_recipient_injection_is_refused_before_the_transport(address: str) -> None:
    transport = InMemoryMailTransport()
    with pytest.raises(MailAddressRejected):
        _mailer(transport).send(MailRequest(MailTemplate.ACCOUNT_EXISTS, address))
    assert transport.sent == []


@pytest.mark.parametrize("name", ["M8\r\nBcc: victim@example.com", "M8\x7f"])
def test_a_sender_name_with_control_characters_is_refused(name: str) -> None:
    with pytest.raises(MailAddressRejected):
        _mailer(InMemoryMailTransport(), sender_name=name)
    # …and it never gets that far: startup refuses it.
    with pytest.raises(ValidationError, match="EMAILS_FROM_NAME must not contain"):
        Settings(_env_file=None, **{**_BASE, "EMAILS_FROM_NAME": name})


def test_subjects_are_fixed_catalogue_text() -> None:
    """No subject has a placeholder, so nothing user-controlled can reach it."""
    for copies in mail_templates._CATALOGUE.values():
        for copy in copies.values():
            assert "{" not in copy.subject and "\n" not in copy.subject
