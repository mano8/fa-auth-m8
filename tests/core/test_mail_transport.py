"""M1 — mail transports (contract §7).

Two layers:

- scripted ``smtplib`` doubles pin the exact call sequence of each TLS mode,
  the verified TLS context, the credentials, and the failure mapping;
- a real socket SMTP server (plain, STARTTLS, implicit TLS with a certificate
  generated for the test) proves on the real ``smtplib`` that a missing or
  unverifiable STARTTLS is fatal before any credential or envelope is sent, and
  that a self-signed certificate is refused.
"""

import datetime
import ipaddress
import smtplib
import socket
import ssl
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import SecretStr

from auth_user_service.core import mail_transport
from auth_user_service.core.mail_transport import (
    InMemoryMailTransport,
    MailDeliveryError,
    MailFailure,
    SmtpMailTransport,
    SmtpTlsMode,
    verified_tls_context,
)

#: The certificate names this address, so only the missing trust can fail it.
_LOOPBACK = ipaddress.ip_address("127.0.0.1")

# Generated per run: never a tracked credential (SEC-NO-TRACKED-SECRETS).
_PASSWORD = f"relay-{id(object())}-pw"


def _message() -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = "no-reply@example.com"
    msg["To"] = "user@example.com"
    msg["Subject"] = "Test"
    msg.set_content("body")
    return msg


def _transport(
    tls_mode: SmtpTlsMode = "starttls",
    *,
    host: str = "smtp.example.com",
    port: int = 587,
    username: Optional[str] = "relay-user",
    password: Optional[SecretStr] = SecretStr(_PASSWORD),
) -> SmtpMailTransport:
    return SmtpMailTransport(
        host=host,
        port=port,
        tls_mode=tls_mode,
        timeout_seconds=3.0,
        username=username,
        password=password,
    )


# ── in-memory fake ───────────────────────────────────────────────────────────


def test_in_memory_transport_records_in_order() -> None:
    fake = InMemoryMailTransport()
    first, second = _message(), _message()
    fake.send(first)
    fake.send(second)
    assert fake.sent == [first, second]


def test_in_memory_transport_can_fail_like_a_relay() -> None:
    fake = InMemoryMailTransport(fail_with=MailFailure.TIMEOUT)
    with pytest.raises(MailDeliveryError) as exc:
        fake.send(_message())
    assert exc.value.reason is MailFailure.TIMEOUT
    assert fake.sent == []


# ── scripted smtplib doubles ─────────────────────────────────────────────────


@dataclass
class _Script:
    """What the fake server offers and how it misbehaves; records the calls."""

    offers_starttls: bool = True
    raise_on: dict[str, BaseException] = field(default_factory=dict)
    calls: list[tuple[str, object]] = field(default_factory=list)


class _FakeSmtp:
    script: _Script

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float,
        context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self._record("connect", (type(self).__name__, host, port, timeout, context))

    def _record(self, name: str, arg: object = None) -> None:
        self.script.calls.append((name, arg))
        if name in self.script.raise_on:
            raise self.script.raise_on[name]

    def __enter__(self) -> "_FakeSmtp":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.script.calls.append(("quit", None))

    def ehlo(self) -> None:
        self._record("ehlo")

    def has_extn(self, name: str) -> bool:
        return name == "starttls" and self.script.offers_starttls

    def starttls(self, context: ssl.SSLContext) -> None:
        self._record("starttls", context)

    def login(self, user: str, password: str) -> None:
        self._record("login", (user, password))

    def send_message(self, message: EmailMessage) -> None:
        self._record("send_message", message)


class _FakeSmtpSsl(_FakeSmtp):
    pass


@pytest.fixture
def script(monkeypatch: pytest.MonkeyPatch) -> _Script:
    scripted = _Script()
    _FakeSmtp.script = scripted
    monkeypatch.setattr(mail_transport.smtplib, "SMTP", _FakeSmtp)
    monkeypatch.setattr(mail_transport.smtplib, "SMTP_SSL", _FakeSmtpSsl)
    return scripted


def _names(script: _Script) -> list[str]:
    return [name for name, _ in script.calls]


def _assert_verified(context: object) -> None:
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_starttls_upgrades_verifies_then_authenticates(script: _Script) -> None:
    message = _message()
    _transport("starttls").send(message)
    assert _names(script) == [
        "connect",
        "ehlo",
        "starttls",
        "ehlo",
        "login",
        "send_message",
        "quit",
    ]
    calls = dict(script.calls)
    assert calls["connect"] == ("_FakeSmtp", "smtp.example.com", 587, 3.0, None)
    _assert_verified(calls["starttls"])
    assert calls["login"] == ("relay-user", _PASSWORD)
    assert calls["send_message"] is message


def test_starttls_not_offered_is_fatal_before_credentials(script: _Script) -> None:
    script.offers_starttls = False
    with pytest.raises(MailDeliveryError) as exc:
        _transport("starttls").send(_message())
    assert exc.value.reason is MailFailure.TLS
    assert "login" not in _names(script)
    assert "send_message" not in _names(script)


def test_starttls_refused_by_the_server_is_a_tls_failure(script: _Script) -> None:
    script.raise_on["starttls"] = smtplib.SMTPResponseException(454, b"TLS not now")
    with pytest.raises(MailDeliveryError) as exc:
        _transport("starttls").send(_message())
    assert exc.value.reason is MailFailure.TLS
    assert "send_message" not in _names(script)


def test_implicit_tls_wraps_the_connection_with_a_verified_context(
    script: _Script,
) -> None:
    _transport("implicit", port=465).send(_message())
    assert _names(script) == ["connect", "login", "send_message", "quit"]
    kind, host, port, timeout, context = dict(script.calls)["connect"]  # type: ignore[misc]
    assert (kind, host, port, timeout) == ("_FakeSmtpSsl", "smtp.example.com", 465, 3.0)
    _assert_verified(context)


def test_plaintext_mode_never_upgrades(script: _Script) -> None:
    _transport("none", port=1025, username=None, password=None).send(_message())
    assert _names(script) == ["connect", "send_message", "quit"]


def test_no_credentials_means_no_login(script: _Script) -> None:
    _transport("starttls", username=None, password=None).send(_message())
    assert "login" not in _names(script)


def test_constructing_a_transport_opens_no_connection(script: _Script) -> None:
    _transport("starttls")
    assert script.calls == []


@pytest.mark.parametrize(
    ("step", "error", "reason"),
    [
        ("connect", ConnectionRefusedError("refused"), MailFailure.CONNECT),
        ("connect", TimeoutError("slow"), MailFailure.TIMEOUT),
        ("connect", smtplib.SMTPConnectError(421, b"busy"), MailFailure.CONNECT),
        ("ehlo", smtplib.SMTPServerDisconnected("gone"), MailFailure.CONNECT),
        ("starttls", ssl.SSLError("bad cert"), MailFailure.TLS),
        ("login", smtplib.SMTPAuthenticationError(535, b"bad"), MailFailure.AUTH),
        (
            "send_message",
            smtplib.SMTPRecipientsRefused({"user@example.com": (550, b"no")}),
            MailFailure.REJECTED,
        ),
        ("send_message", TimeoutError("slow"), MailFailure.TIMEOUT),
    ],
)
def test_failures_map_to_bounded_reasons(
    script: _Script, step: str, error: BaseException, reason: MailFailure
) -> None:
    script.raise_on[step] = error
    with pytest.raises(MailDeliveryError) as exc:
        _transport("starttls").send(_message())
    assert exc.value.reason is reason
    assert str(exc.value) == f"mail delivery failed: {reason.value}"


def test_errors_and_repr_never_carry_the_password_or_server_text(
    script: _Script,
) -> None:
    transport = _transport("starttls")
    assert _PASSWORD not in repr(transport)
    script.raise_on["login"] = smtplib.SMTPAuthenticationError(
        535, f"rejected {_PASSWORD} for user@example.com".encode()
    )
    with pytest.raises(MailDeliveryError) as exc:
        transport.send(_message())
    assert _PASSWORD not in str(exc.value)
    assert "user@example.com" not in str(exc.value)


def test_verified_tls_context_cannot_be_weakened() -> None:
    context = verified_tls_context()
    _assert_verified(context)
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


# ── real socket SMTP server ──────────────────────────────────────────────────


@dataclass
class _Server:
    """A one-connection SMTP server on 127.0.0.1 that records every command."""

    offer_starttls: bool = False
    implicit_tls: bool = False
    tls: Optional[ssl.SSLContext] = None
    commands: list[str] = field(default_factory=list)
    data: list[bytes] = field(default_factory=list)
    port: int = 0

    def __post_init__(self) -> None:
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._listener.close()
        self._thread.join(timeout=5)

    def _serve(self) -> None:
        try:
            conn, _ = self._listener.accept()
        except OSError:
            return
        conn.settimeout(5)
        try:
            if self.implicit_tls:
                assert self.tls is not None
                conn = self.tls.wrap_socket(conn, server_side=True)
            self._session(conn)
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()

    def _session(self, conn: socket.socket) -> None:
        reader = conn.makefile("rb")
        conn.sendall(b"220 test ESMTP\r\n")
        while line := reader.readline():
            command = line.decode().strip()
            verb = command.split(" ")[0].upper()
            self.commands.append(verb)
            if verb == "EHLO":
                extra = b"250-STARTTLS\r\n" if self.offer_starttls else b""
                conn.sendall(b"250-test\r\n" + extra + b"250 8BITMIME\r\n")
            elif verb == "STARTTLS":
                conn.sendall(b"220 go ahead\r\n")
                assert self.tls is not None
                conn = self.tls.wrap_socket(conn, server_side=True)
                reader = conn.makefile("rb")
            elif verb == "DATA":
                conn.sendall(b"354 end with .\r\n")
                body = b""
                while (chunk := reader.readline()) not in (b".\r\n", b""):
                    body += chunk
                self.data.append(body)
                conn.sendall(b"250 queued\r\n")
            elif verb == "QUIT":
                conn.sendall(b"221 bye\r\n")
                return
            else:
                conn.sendall(b"250 ok\r\n")


def _self_signed_context(tmp_path: Path) -> ssl.SSLContext:
    """A server TLS context with a key and certificate made for this test.

    The certificate is valid for the host and in date; it is only untrusted.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(_LOOPBACK)]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    return context


@pytest.fixture
def server_factory() -> Iterator[list[_Server]]:
    servers: list[_Server] = []
    yield servers
    for server in servers:
        server.close()


def _start(servers: list[_Server], **kwargs: object) -> _Server:
    server = _Server(**kwargs)  # type: ignore[arg-type]
    servers.append(server)
    return server


def test_real_plaintext_send_delivers_the_message(
    server_factory: list[_Server],
) -> None:
    server = _start(server_factory)
    _transport(
        "none", host="127.0.0.1", port=server.port, username=None, password=None
    ).send(_message())
    server.close()
    assert server.commands == ["EHLO", "MAIL", "RCPT", "DATA", "QUIT"]
    assert b"Subject: Test" in server.data[0]


def test_real_server_without_starttls_gets_no_credentials_or_envelope(
    server_factory: list[_Server],
) -> None:
    server = _start(server_factory, offer_starttls=False)
    with pytest.raises(MailDeliveryError) as exc:
        _transport("starttls", host="127.0.0.1", port=server.port).send(_message())
    server.close()
    assert exc.value.reason is MailFailure.TLS
    assert "AUTH" not in server.commands and "MAIL" not in server.commands


def test_real_starttls_with_an_untrusted_certificate_is_fatal(
    server_factory: list[_Server], tmp_path: Path
) -> None:
    server = _start(
        server_factory, offer_starttls=True, tls=_self_signed_context(tmp_path)
    )
    with pytest.raises(MailDeliveryError) as exc:
        _transport("starttls", host="127.0.0.1", port=server.port).send(_message())
    server.close()
    assert exc.value.reason is MailFailure.TLS
    assert server.commands == ["EHLO", "STARTTLS"]


def test_real_implicit_tls_with_an_untrusted_certificate_is_fatal(
    server_factory: list[_Server], tmp_path: Path
) -> None:
    server = _start(
        server_factory, implicit_tls=True, tls=_self_signed_context(tmp_path)
    )
    with pytest.raises(MailDeliveryError) as exc:
        _transport("implicit", host="127.0.0.1", port=server.port).send(_message())
    server.close()
    assert exc.value.reason is MailFailure.TLS
    assert server.commands == []
