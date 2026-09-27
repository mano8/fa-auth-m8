"""Account-lifecycle mail templates: seven messages in English, Spanish and French.

Each template renders to a subject, a plain-text body, and an HTML body with
the same content (a ``multipart/alternative`` message is built from them by
:mod:`auth_user_service.services.mailer`).

Safety rules (``docs/account-lifecycle-contract.md`` §4):

- a subject is fixed catalogue text: it never carries a token, a name, or an
  address;
- every value interpolated into the HTML body — the link and the account name
  included — goes through :func:`html.escape`;
- the account name is the only user-controlled value. It is optional, stripped
  of control and format characters (no line breaks or bidi overrides), and
  capped at the ``full_name`` column length;
- the link is built by the mailer from ``PUBLIC_UI_URL``; this module never
  sees the request.

An unknown locale falls back to English (:func:`resolve_mail_locale`).
"""

import html
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from pydantic import SecretStr

from auth_user_service.core.challenge_tokens import ChallengePurpose

#: Same bound as ``User.full_name``; a longer value is cut, never rejected.
MAX_NAME_LENGTH = 100


class MailTemplate(str, Enum):
    """Every message the account lifecycle sends."""

    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"  # nosec B105
    PASSWORD_RESET_COMPLETED = "password_reset_completed"  # nosec B105
    #: Sent to the **new** address; carries the confirmation link.
    EMAIL_CHANGE = "email_change"
    #: Sent to the **old** address; a notice without a link.
    EMAIL_CHANGED_NOTICE = "email_changed_notice"
    PASSWORD_CHANGED_NOTICE = "password_changed_notice"  # nosec B105
    #: Sent when someone asks to use an address that already has an account.
    ACCOUNT_EXISTS = "account_exists"

    @property
    def challenge_purpose(self) -> Optional[ChallengePurpose]:
        """The challenge whose link this template carries, if any."""
        return _LINK_PURPOSES.get(self)


_LINK_PURPOSES: dict[MailTemplate, ChallengePurpose] = {
    MailTemplate.EMAIL_VERIFICATION: ChallengePurpose.EMAIL_VERIFICATION,
    MailTemplate.PASSWORD_RESET: ChallengePurpose.PASSWORD_RESET,
    MailTemplate.EMAIL_CHANGE: ChallengePurpose.EMAIL_CHANGE,
}


class MailLocale(str, Enum):
    """Languages the templates are written in."""

    EN = "en"
    ES = "es"
    FR = "fr"


DEFAULT_MAIL_LOCALE = MailLocale.EN


def resolve_mail_locale(value: Optional[str]) -> MailLocale:
    """Pick the first supported language of a tag or ``Accept-Language`` value.

    Accepts ``"es"``, ``"fr-CA"``, ``"es_ES"`` or ``"fr-CH, fr;q=0.9, en;q=0.8"``
    (entries are taken in the order given). Anything else is English.
    """
    for entry in (value or "").split(","):
        primary = entry.split(";")[0].strip().replace("_", "-").split("-")[0]
        try:
            return MailLocale(primary.lower())
        except ValueError:
            continue
    return DEFAULT_MAIL_LOCALE


@dataclass(frozen=True)
class RenderedMail:
    """A rendered message. The bodies may hold a live link, so no ``repr``."""

    subject: str
    text: str = field(repr=False)
    html: str = field(repr=False)


def render_mail(
    template: MailTemplate,
    locale: MailLocale,
    *,
    link: Optional[SecretStr] = None,
    expires_in_minutes: Optional[int] = None,
    full_name: Optional[str] = None,
) -> RenderedMail:
    """Render *template* in *locale*.

    A template with a challenge takes *link* and *expires_in_minutes*; a notice
    takes neither.

    Raises:
        ValueError: the link arguments do not match the template.
    """
    has_link = template.challenge_purpose is not None
    if has_link != (link is not None) or has_link != (expires_in_minutes is not None):
        raise ValueError(f"{template.value} link arguments do not match the template")
    words = _LOCALE_WORDS[locale]
    copy = _CATALOGUE[locale][template]
    name = clean_display_name(full_name)
    greeting = words.greeting_named.format(name=name) if name else words.greeting
    expiry = (
        words.expiry.format(duration=_duration(words, expires_in_minutes))
        if expires_in_minutes is not None
        else None
    )
    raw_link = link.get_secret_value() if link is not None else None
    return RenderedMail(
        subject=copy.subject,
        text=_render_text(words, copy, greeting, raw_link, expiry),
        html=_render_html(locale, words, copy, greeting, raw_link, expiry),
    )


def clean_display_name(value: Optional[str]) -> Optional[str]:
    """Return the account name safe to show in a greeting, or ``None``.

    Control and format characters (line breaks, bidi overrides, zero-width
    marks) are removed, whitespace runs collapse to one space, and the result is
    capped at :data:`MAX_NAME_LENGTH`.
    """
    if not value:
        return None
    kept = "".join(
        " " if ch.isspace() else ch
        for ch in value
        if ch.isspace() or unicodedata.category(ch) not in {"Cc", "Cf"}
    )
    cleaned = " ".join(kept.split())[:MAX_NAME_LENGTH].strip()
    return cleaned or None


def _duration(words: "_LocaleWords", minutes: int) -> str:
    """Whole hours read as hours, anything else as minutes."""
    if minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours} {words.hour if hours == 1 else words.hours}"
    return f"{minutes} {words.minutes}"


def _render_text(
    words: "_LocaleWords",
    copy: "_Copy",
    greeting: str,
    link: Optional[str],
    expiry: Optional[str],
) -> str:
    """The plain-text body."""
    blocks = [greeting, *copy.paragraphs]
    if link is not None:
        blocks.append(link)
    blocks.extend(line for line in (expiry, copy.closing) if line)
    blocks.append(f"-- \n{words.footer}")
    return "\n\n".join(blocks) + "\n"


def _render_html(
    locale: MailLocale,
    words: "_LocaleWords",
    copy: "_Copy",
    greeting: str,
    link: Optional[str],
    expiry: Optional[str],
) -> str:
    """The HTML body. Every interpolated value is escaped here, none earlier."""
    esc = html.escape
    parts = [f"<p>{esc(greeting)}</p>"]
    parts.extend(f"<p>{esc(p)}</p>" for p in copy.paragraphs)
    if link is not None and copy.action is not None:
        href = esc(link, quote=True)
        parts.append(
            f'<p><a href="{href}" style="{_BUTTON_STYLE}">{esc(copy.action)}</a></p>'
        )
        parts.append(
            f'<p style="{_SMALL_STYLE}">{esc(words.link_fallback)}<br>'
            f'<a href="{href}">{esc(link)}</a></p>'
        )
    parts.extend(f"<p>{esc(line)}</p>" for line in (expiry, copy.closing) if line)
    parts.append(f'<p style="{_SMALL_STYLE}">{esc(words.footer)}</p>')
    body = "\n".join(parts)
    return (
        f'<!DOCTYPE html>\n<html lang="{locale.value}">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="referrer" content="no-referrer">\n'
        f"<title>{esc(copy.subject)}</title>\n</head>\n"
        f'<body style="{_BODY_STYLE}">\n<h1 style="{_H1_STYLE}">{esc(copy.heading)}'
        f"</h1>\n{body}\n</body>\n</html>\n"
    )


_BODY_STYLE = "font-family:sans-serif;line-height:1.5;color:#222;max-width:560px"
_H1_STYLE = "font-size:20px"
_BUTTON_STYLE = (
    "display:inline-block;padding:10px 18px;background:#1f5fbf;color:#fff;"
    "text-decoration:none;border-radius:4px"
)
_SMALL_STYLE = "font-size:12px;color:#666;word-break:break-all"


@dataclass(frozen=True)
class _Copy:
    """The fixed text of one template in one language."""

    subject: str
    heading: str
    paragraphs: tuple[str, ...]
    #: Button label; set exactly for templates that carry a link.
    action: Optional[str] = None
    #: Last line, after the link and its expiry.
    closing: Optional[str] = None


@dataclass(frozen=True)
class _LocaleWords:
    """Text shared by every template of one language."""

    greeting: str
    greeting_named: str
    expiry: str
    minutes: str
    hour: str
    hours: str
    link_fallback: str
    footer: str


_LOCALE_WORDS: dict[MailLocale, _LocaleWords] = {
    MailLocale.EN: _LocaleWords(
        greeting="Hello,",
        greeting_named="Hello {name},",
        expiry="This link expires in {duration}.",
        minutes="minutes",
        hour="hour",
        hours="hours",
        link_fallback="If the button does not work, copy this address into your "
        "browser:",
        footer="This is an automated message; please do not reply.",
    ),
    MailLocale.ES: _LocaleWords(
        greeting="Hola:",
        greeting_named="Hola, {name}:",
        expiry="Este enlace caduca en {duration}.",
        minutes="minutos",
        hour="hora",
        hours="horas",
        link_fallback="Si el botón no funciona, copia esta dirección en tu navegador:",
        footer="Este es un mensaje automático; por favor, no respondas.",
    ),
    MailLocale.FR: _LocaleWords(
        greeting="Bonjour,",
        greeting_named="Bonjour {name},",
        expiry="Ce lien expire dans {duration}.",
        minutes="minutes",
        hour="heure",
        hours="heures",
        link_fallback="Si le bouton ne fonctionne pas, copiez cette adresse dans "
        "votre navigateur :",
        footer="Ceci est un message automatique ; merci de ne pas y répondre.",
    ),
}

_CATALOGUE: dict[MailLocale, dict[MailTemplate, _Copy]] = {
    MailLocale.EN: {
        MailTemplate.EMAIL_VERIFICATION: _Copy(
            subject="Confirm your email address",
            heading="Confirm your email address",
            paragraphs=(
                "Confirm that this email address belongs to you by opening the "
                "link below.",
            ),
            action="Confirm email address",
            closing="If you did not create an account or ask for this email, you "
            "can ignore it.",
        ),
        MailTemplate.PASSWORD_RESET: _Copy(
            subject="Reset your password",
            heading="Reset your password",
            paragraphs=(
                "We received a request to reset the password of your account. "
                "Open the link below to choose a new password.",
            ),
            action="Choose a new password",
            closing="If you did not ask for a password reset, you can ignore this "
            "email; your password stays the same.",
        ),
        MailTemplate.PASSWORD_RESET_COMPLETED: _Copy(
            subject="Your password was reset",
            heading="Your password was reset",
            paragraphs=(
                "The password of your account was just reset, and every session "
                "was signed out.",
                "If you did not do this, reset your password again right away and "
                "contact your administrator.",
            ),
        ),
        MailTemplate.EMAIL_CHANGE: _Copy(
            subject="Confirm your new email address",
            heading="Confirm your new email address",
            paragraphs=(
                "Someone asked to use this address as the new email of an account. "
                "Open the link below to confirm the change.",
            ),
            action="Confirm new email address",
            closing="If you did not ask for this change, you can ignore this "
            "email; nothing changes.",
        ),
        MailTemplate.EMAIL_CHANGED_NOTICE: _Copy(
            subject="Your email address was changed",
            heading="Your email address was changed",
            paragraphs=(
                "The email address of your account was changed.",
                "If you did not make this change, contact your administrator right "
                "away.",
            ),
        ),
        MailTemplate.PASSWORD_CHANGED_NOTICE: _Copy(
            subject="Your password was changed",
            heading="Your password was changed",
            paragraphs=(
                "The password of your account was changed, and every session was "
                "signed out.",
                "If you did not make this change, reset your password right away "
                "and contact your administrator.",
            ),
        ),
        MailTemplate.ACCOUNT_EXISTS: _Copy(
            subject="An account already uses this email address",
            heading="An account already uses this email address",
            paragraphs=(
                "Someone asked to use this email address for an account, but an "
                "account with this address already exists.",
                "If this was you, sign in with your existing account, or reset your "
                "password if you forgot it. If it was not you, you can ignore this "
                "email.",
            ),
        ),
    },
    MailLocale.ES: {
        MailTemplate.EMAIL_VERIFICATION: _Copy(
            subject="Confirma tu dirección de correo electrónico",
            heading="Confirma tu dirección de correo electrónico",
            paragraphs=(
                "Confirma que esta dirección de correo te pertenece abriendo el "
                "enlace de abajo.",
            ),
            action="Confirmar dirección de correo",
            closing="Si no creaste una cuenta ni solicitaste este correo, puedes "
            "ignorarlo.",
        ),
        MailTemplate.PASSWORD_RESET: _Copy(
            subject="Restablece tu contraseña",
            heading="Restablece tu contraseña",
            paragraphs=(
                "Recibimos una solicitud para restablecer la contraseña de tu "
                "cuenta. Abre el enlace de abajo para elegir una nueva contraseña.",
            ),
            action="Elegir una nueva contraseña",
            closing="Si no solicitaste restablecer la contraseña, puedes ignorar "
            "este correo; tu contraseña no cambia.",
        ),
        MailTemplate.PASSWORD_RESET_COMPLETED: _Copy(
            subject="Tu contraseña se ha restablecido",
            heading="Tu contraseña se ha restablecido",
            paragraphs=(
                "La contraseña de tu cuenta acaba de restablecerse y se han cerrado "
                "todas las sesiones.",
                "Si no fuiste tú, restablece tu contraseña de nuevo de inmediato y "
                "contacta con tu administrador.",
            ),
        ),
        MailTemplate.EMAIL_CHANGE: _Copy(
            subject="Confirma tu nueva dirección de correo",
            heading="Confirma tu nueva dirección de correo",
            paragraphs=(
                "Alguien ha solicitado usar esta dirección como nuevo correo de una "
                "cuenta. Abre el enlace de abajo para confirmar el cambio.",
            ),
            action="Confirmar nueva dirección de correo",
            closing="Si no solicitaste este cambio, puedes ignorar este correo; no "
            "cambiará nada.",
        ),
        MailTemplate.EMAIL_CHANGED_NOTICE: _Copy(
            subject="Tu dirección de correo ha cambiado",
            heading="Tu dirección de correo ha cambiado",
            paragraphs=(
                "La dirección de correo de tu cuenta ha cambiado.",
                "Si no hiciste este cambio, contacta con tu administrador de "
                "inmediato.",
            ),
        ),
        MailTemplate.PASSWORD_CHANGED_NOTICE: _Copy(
            subject="Tu contraseña ha cambiado",
            heading="Tu contraseña ha cambiado",
            paragraphs=(
                "La contraseña de tu cuenta ha cambiado y se han cerrado todas las "
                "sesiones.",
                "Si no hiciste este cambio, restablece tu contraseña de inmediato y "
                "contacta con tu administrador.",
            ),
        ),
        MailTemplate.ACCOUNT_EXISTS: _Copy(
            subject="Ya existe una cuenta con esta dirección de correo",
            heading="Ya existe una cuenta con esta dirección de correo",
            paragraphs=(
                "Alguien ha solicitado usar esta dirección de correo para una "
                "cuenta, pero ya existe una cuenta con esta dirección.",
                "Si fuiste tú, inicia sesión con tu cuenta existente o restablece "
                "tu contraseña si la has olvidado. Si no fuiste tú, puedes ignorar "
                "este correo.",
            ),
        ),
    },
    MailLocale.FR: {
        MailTemplate.EMAIL_VERIFICATION: _Copy(
            subject="Confirmez votre adresse e-mail",
            heading="Confirmez votre adresse e-mail",
            paragraphs=(
                "Confirmez que cette adresse e-mail vous appartient en ouvrant le "
                "lien ci-dessous.",
            ),
            action="Confirmer l'adresse e-mail",
            closing="Si vous n'avez pas créé de compte ni demandé cet e-mail, vous "
            "pouvez l'ignorer.",
        ),
        MailTemplate.PASSWORD_RESET: _Copy(
            subject="Réinitialisez votre mot de passe",
            heading="Réinitialisez votre mot de passe",
            paragraphs=(
                "Nous avons reçu une demande de réinitialisation du mot de passe de "
                "votre compte. Ouvrez le lien ci-dessous pour choisir un nouveau "
                "mot de passe.",
            ),
            action="Choisir un nouveau mot de passe",
            closing="Si vous n'avez pas demandé de réinitialisation, vous pouvez "
            "ignorer cet e-mail ; votre mot de passe reste inchangé.",
        ),
        MailTemplate.PASSWORD_RESET_COMPLETED: _Copy(
            subject="Votre mot de passe a été réinitialisé",
            heading="Votre mot de passe a été réinitialisé",
            paragraphs=(
                "Le mot de passe de votre compte vient d'être réinitialisé et "
                "toutes les sessions ont été fermées.",
                "Si ce n'était pas vous, réinitialisez de nouveau votre mot de "
                "passe immédiatement et contactez votre administrateur.",
            ),
        ),
        MailTemplate.EMAIL_CHANGE: _Copy(
            subject="Confirmez votre nouvelle adresse e-mail",
            heading="Confirmez votre nouvelle adresse e-mail",
            paragraphs=(
                "Quelqu'un a demandé à utiliser cette adresse comme nouvelle "
                "adresse e-mail d'un compte. Ouvrez le lien ci-dessous pour "
                "confirmer le changement.",
            ),
            action="Confirmer la nouvelle adresse e-mail",
            closing="Si vous n'avez pas demandé ce changement, vous pouvez ignorer "
            "cet e-mail ; rien ne changera.",
        ),
        MailTemplate.EMAIL_CHANGED_NOTICE: _Copy(
            subject="Votre adresse e-mail a été modifiée",
            heading="Votre adresse e-mail a été modifiée",
            paragraphs=(
                "L'adresse e-mail de votre compte a été modifiée.",
                "Si vous n'êtes pas à l'origine de ce changement, contactez "
                "immédiatement votre administrateur.",
            ),
        ),
        MailTemplate.PASSWORD_CHANGED_NOTICE: _Copy(
            subject="Votre mot de passe a été modifié",
            heading="Votre mot de passe a été modifié",
            paragraphs=(
                "Le mot de passe de votre compte a été modifié et toutes les "
                "sessions ont été fermées.",
                "Si vous n'êtes pas à l'origine de ce changement, réinitialisez "
                "immédiatement votre mot de passe et contactez votre "
                "administrateur.",
            ),
        ),
        MailTemplate.ACCOUNT_EXISTS: _Copy(
            subject="Un compte utilise déjà cette adresse e-mail",
            heading="Un compte utilise déjà cette adresse e-mail",
            paragraphs=(
                "Quelqu'un a demandé à utiliser cette adresse e-mail pour un "
                "compte, mais un compte existe déjà avec cette adresse.",
                "Si c'était vous, connectez-vous avec votre compte existant, ou "
                "réinitialisez votre mot de passe si vous l'avez oublié. Sinon, "
                "vous pouvez ignorer cet e-mail.",
            ),
        ),
    },
}
