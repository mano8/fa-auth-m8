"""Build and send account-lifecycle mail through an injectable transport.

The :class:`Mailer` turns a :class:`MailRequest` into a ``multipart/alternative``
message and hands it to its :class:`~auth_user_service.core.mail_transport.MailTransport`.
Following ``docs/account-lifecycle-contract.md`` §4 and §5.8:

- headers come only from configuration (``EMAILS_FROM_EMAIL``,
  ``EMAILS_FROM_NAME``) and the validated recipient address. The recipient has
  no display name, a control character anywhere is refused, and the subject is
  fixed catalogue text;
- a link is ``PUBLIC_UI_URL`` + the purpose's UI page + ``#token=<token>``: the
  token rides in the fragment, never in a path or query, and never in the
  subject. The request ``Host`` is never read;
- the token is parsed for the template's purpose before it goes into a link, so
  a JWT or another purpose's token cannot be mailed by mistake.

With ``MAIL_ENABLED=false`` :meth:`Mailer.from_settings` returns ``None`` and no
transport is built, so a mail-free deployment needs no SMTP server.

Scheduling a send after commit, budgets, and logging belong to the dispatch
step (M2); this module neither logs nor retries.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Optional

from email_validator import EmailNotValidError, validate_email
from pydantic import SecretStr

from auth_user_service.core.challenge_tokens import (
    ChallengePurpose,
    parse_challenge_token,
)
from auth_user_service.core.config import Settings
from auth_user_service.core.mail_transport import MailTransport, SmtpMailTransport
from auth_user_service.services.mail_templates import (
    DEFAULT_MAIL_LOCALE,
    MailLocale,
    MailTemplate,
    render_mail,
)

#: UI page each challenge link opens, under ``PUBLIC_UI_URL`` (contract §4).
CHALLENGE_UI_PATHS: dict[ChallengePurpose, str] = {
    ChallengePurpose.EMAIL_VERIFICATION: "/auth/verify-email",
    ChallengePurpose.PASSWORD_RESET: "/auth/reset-password",  # nosec B105
    ChallengePurpose.EMAIL_CHANGE: "/auth/confirm-email-change",
}


class MailAddressRejected(ValueError):
    """A recipient or sender value cannot go into a header. Names no address."""


@dataclass(frozen=True)
class MailRequest:
    """One message to send. The address, name, and token never show in ``repr``."""

    template: MailTemplate
    recipient: str = field(repr=False)
    locale: MailLocale = DEFAULT_MAIL_LOCALE
    #: The raw challenge token, for templates that carry a link.
    token: Optional[SecretStr] = field(default=None, repr=False)
    #: The account's name for the greeting; optional, user-controlled.
    full_name: Optional[str] = field(default=None, repr=False)


@dataclass(frozen=True)
class Mailer:
    """Composes messages from configuration and sends them through *transport*."""

    transport: MailTransport
    sender_email: str
    sender_name: Optional[str]
    public_ui_url: str
    ttl_minutes: Mapping[ChallengePurpose, int]

    def __post_init__(self) -> None:
        """Refuse a sender that could break out of its header."""
        _require_header_safe(self.sender_email)
        if self.sender_name is not None:
            _require_header_safe(self.sender_name)

    @classmethod
    def from_settings(
        cls, settings: Settings, transport: Optional[MailTransport] = None
    ) -> Optional["Mailer"]:
        """The configured mailer, or ``None`` when mail is disabled.

        *transport* replaces the SMTP transport (tests inject the in-memory
        fake). The settings validator already guarantees a complete mail
        configuration whenever ``MAIL_ENABLED`` is true.
        """
        if not settings.MAIL_ENABLED:
            return None
        if settings.SMTP_HOST is None or settings.EMAILS_FROM_EMAIL is None:
            raise ValueError(
                "MAIL_ENABLED=true requires SMTP_HOST and EMAILS_FROM_EMAIL"
            )
        return cls(
            transport=transport
            or SmtpMailTransport(
                host=settings.SMTP_HOST,
                port=settings.SMTP_PORT,
                tls_mode=settings.SMTP_TLS_MODE,
                timeout_seconds=settings.SMTP_TIMEOUT_SECONDS,
                username=settings.SMTP_USER,
                password=settings.SMTP_PASSWORD,
            ),
            sender_email=str(settings.EMAILS_FROM_EMAIL),
            sender_name=settings.EMAILS_FROM_NAME or None,
            public_ui_url=settings.PUBLIC_UI_URL,
            ttl_minutes={
                ChallengePurpose.EMAIL_VERIFICATION: (
                    settings.EMAIL_VERIFICATION_TTL_MINUTES
                ),
                ChallengePurpose.PASSWORD_RESET: settings.PASSWORD_RESET_TTL_MINUTES,
                ChallengePurpose.EMAIL_CHANGE: settings.EMAIL_CHANGE_TTL_MINUTES,
            },
        )

    def send(self, request: MailRequest) -> None:
        """Compose *request* and deliver it; transport failures propagate."""
        self.transport.send(self.compose(request))

    def compose(self, request: MailRequest) -> EmailMessage:
        """Build the message for *request* without sending it.

        Raises:
            MailAddressRejected: the recipient is not a plain ASCII address.
            ChallengeTokenRejected: the token is missing or not of the
                template's purpose.
        """
        recipient = validate_recipient(request.recipient)
        purpose = request.template.challenge_purpose
        link = None if purpose is None else self._link(purpose, request.token)
        rendered = render_mail(
            request.template,
            request.locale,
            link=link,
            expires_in_minutes=None if purpose is None else self.ttl_minutes[purpose],
            full_name=request.full_name,
        )
        message = EmailMessage()
        message["Subject"] = rendered.subject
        message["From"] = Address(
            display_name=self.sender_name or "", addr_spec=self.sender_email
        )
        message["To"] = Address(addr_spec=recipient)
        message["Date"] = formatdate(usegmt=True)
        message["Message-ID"] = make_msgid(domain=self.sender_email.rsplit("@", 1)[1])
        message["Auto-Submitted"] = "auto-generated"
        message.set_content(rendered.text)
        message.add_alternative(rendered.html, subtype="html")
        return message

    def _link(self, purpose: ChallengePurpose, token: Optional[SecretStr]) -> SecretStr:
        """``PUBLIC_UI_URL`` + UI page + ``#token=``; the token must parse."""
        raw = "" if token is None else token.get_secret_value()
        parse_challenge_token(raw, purpose)
        return SecretStr(
            f"{self.public_ui_url}{CHALLENGE_UI_PATHS[purpose]}#token={raw}"
        )


def validate_recipient(address: str) -> str:
    """Return *address* normalized if it can be a ``To`` header, else refuse it.

    Only a bare ASCII address is accepted: no display name, no whitespace or
    control character (so no CR/LF header injection), no internationalized
    mailbox that a relay without ``SMTPUTF8`` would bounce.

    Raises:
        MailAddressRejected: with a message that does not repeat the address.
    """
    _require_header_safe(address)
    if not address.isascii() or any(ch.isspace() for ch in address):
        raise MailAddressRejected("recipient is not a plain ASCII address")
    try:
        validated = validate_email(
            address, check_deliverability=False, allow_smtputf8=False
        )
    except EmailNotValidError as exc:
        raise MailAddressRejected("recipient is not a valid address") from exc
    return validated.normalized


def _require_header_safe(value: str) -> None:
    """Refuse a header value holding a control character (CR/LF included)."""
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise MailAddressRejected("header value contains a control character")
