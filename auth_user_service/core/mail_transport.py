"""Injectable mail transports: SMTP for deployments, in memory for tests.

A transport only delivers a fully built :class:`~email.message.EmailMessage`;
what goes into the message (headers, links, templates) belongs to
:mod:`auth_user_service.services.mailer`. Nothing here reads the request, so
no transport can depend on the ``Host`` header.

:class:`SmtpMailTransport` follows ``docs/account-lifecycle-contract.md`` §7:

- ``implicit`` wraps the connection in TLS from the first byte (port 465);
- ``starttls`` upgrades the connection, and a server that does not offer the
  upgrade, or an upgrade that fails, is fatal — never a plaintext fallback;
- ``none`` is plaintext; the settings allow it only under ``ENVIRONMENT=local``;
- certificates and hostnames are always verified (the default SSL context), and
  there is deliberately no way to turn that off;
- one timeout bounds the connection and every SMTP command of a send.

The transport never logs. A failed send raises :class:`MailDeliveryError`
with a bounded :class:`MailFailure` reason and no server text, address, or
credential, so the caller can log and count it safely.
"""

import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from enum import Enum
from typing import Literal, Optional, Protocol

from pydantic import SecretStr

#: ``SMTP_TLS_MODE`` values.
SmtpTlsMode = Literal["implicit", "starttls", "none"]


class MailFailure(str, Enum):
    """Why a send failed — a bounded label, safe for logs and metrics."""

    CONNECT = "connect"
    TLS = "tls"
    AUTH = "auth"
    REJECTED = "rejected"
    TIMEOUT = "timeout"


class MailDeliveryError(Exception):
    """A message could not be delivered. Carries only a bounded reason."""

    def __init__(self, reason: MailFailure) -> None:
        super().__init__(f"mail delivery failed: {reason.value}")
        self.reason = reason


class MailTransport(Protocol):
    """Delivers one built message or raises :class:`MailDeliveryError`."""

    def send(self, message: EmailMessage) -> None:
        """Deliver *message* to its ``To`` recipient."""
        ...  # pragma: no cover


@dataclass
class InMemoryMailTransport:
    """Test transport: keeps every message it was asked to send, in order.

    Needs no server. Set :attr:`fail_with` to make every send raise that
    failure, as a broken relay would.
    """

    sent: list[EmailMessage] = field(default_factory=list)
    fail_with: Optional[MailFailure] = None

    def send(self, message: EmailMessage) -> None:
        """Record *message*, or raise the configured failure."""
        if self.fail_with is not None:
            raise MailDeliveryError(self.fail_with)
        self.sent.append(message)


@dataclass(frozen=True)
class SmtpMailTransport:
    """Sends through one SMTP relay, opening a fresh connection per message.

    Constructing it opens no connection, so a service with mail configured but
    unused never contacts the relay.
    """

    host: str
    port: int
    tls_mode: SmtpTlsMode
    timeout_seconds: float
    username: Optional[str] = None
    password: Optional[SecretStr] = field(default=None, repr=False)

    def send(self, message: EmailMessage) -> None:
        """Deliver *message*; every failure becomes a :class:`MailDeliveryError`."""
        try:
            with self._connect() as client:
                self._secure(client)
                self._login(client)
                client.send_message(message)
        except MailDeliveryError:
            raise
        except smtplib.SMTPAuthenticationError as exc:
            raise MailDeliveryError(MailFailure.AUTH) from exc
        except ssl.SSLError as exc:
            raise MailDeliveryError(MailFailure.TLS) from exc
        except TimeoutError as exc:
            raise MailDeliveryError(MailFailure.TIMEOUT) from exc
        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected) as exc:
            raise MailDeliveryError(MailFailure.CONNECT) from exc
        except smtplib.SMTPException as exc:
            raise MailDeliveryError(MailFailure.REJECTED) from exc
        except OSError as exc:
            raise MailDeliveryError(MailFailure.CONNECT) from exc

    def _connect(self) -> smtplib.SMTP:
        """Open the connection; implicit TLS verifies before any SMTP byte."""
        if self.tls_mode == "implicit":
            return smtplib.SMTP_SSL(
                self.host,
                self.port,
                timeout=self.timeout_seconds,
                context=verified_tls_context(),
            )
        return smtplib.SMTP(self.host, self.port, timeout=self.timeout_seconds)

    def _secure(self, client: smtplib.SMTP) -> None:
        """Upgrade with STARTTLS when configured; refuse to continue without it."""
        if self.tls_mode != "starttls":
            return
        client.ehlo()
        if not client.has_extn("starttls"):
            raise MailDeliveryError(MailFailure.TLS)
        try:
            client.starttls(context=verified_tls_context())
        except smtplib.SMTPResponseException as exc:
            raise MailDeliveryError(MailFailure.TLS) from exc
        client.ehlo()

    def _login(self, client: smtplib.SMTP) -> None:
        """Authenticate when credentials are configured (they come as a pair)."""
        if self.username is None or self.password is None:
            return
        client.login(self.username, self.password.get_secret_value())


def verified_tls_context() -> ssl.SSLContext:
    """The only TLS context a transport uses: certificate and hostname checked."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context
