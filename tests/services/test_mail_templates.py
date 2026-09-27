"""M1 — account-lifecycle mail templates: catalogue, locales, rendering."""

import pytest
from pydantic import SecretStr

from auth_user_service.core.challenge_tokens import ChallengePurpose
from auth_user_service.services import mail_templates
from auth_user_service.services.mail_templates import (
    MAX_NAME_LENGTH,
    MailLocale,
    MailTemplate,
    clean_display_name,
    render_mail,
    resolve_mail_locale,
)

_LINK = SecretStr("https://app.example.com/auth/verify-email#token=m8vfy_x")
_LINK_TEMPLATES = [t for t in MailTemplate if t.challenge_purpose is not None]
_NOTICES = [t for t in MailTemplate if t.challenge_purpose is None]


def _render(
    template: MailTemplate, locale: MailLocale = MailLocale.EN, **kwargs: object
) -> mail_templates.RenderedMail:
    if template.challenge_purpose is not None:
        kwargs.setdefault("link", _LINK)
        kwargs.setdefault("expires_in_minutes", 30)
    return render_mail(template, locale, **kwargs)  # type: ignore[arg-type]


def test_the_seven_templates_of_the_plan() -> None:
    assert {t.value for t in MailTemplate} == {
        "email_verification",
        "password_reset",
        "password_reset_completed",
        "email_change",
        "email_changed_notice",
        "password_changed_notice",
        "account_exists",
    }
    assert {t: t.challenge_purpose for t in _LINK_TEMPLATES} == {
        MailTemplate.EMAIL_VERIFICATION: ChallengePurpose.EMAIL_VERIFICATION,
        MailTemplate.PASSWORD_RESET: ChallengePurpose.PASSWORD_RESET,
        MailTemplate.EMAIL_CHANGE: ChallengePurpose.EMAIL_CHANGE,
    }


@pytest.mark.parametrize("locale", list(MailLocale))
def test_every_locale_has_every_template(locale: MailLocale) -> None:
    catalogue = mail_templates._CATALOGUE[locale]
    assert set(catalogue) == set(MailTemplate)
    for template, copy in catalogue.items():
        # A button exactly where there is a link.
        assert (copy.action is not None) == (template.challenge_purpose is not None)


def test_translations_differ_from_english() -> None:
    english = {t: _render(t).subject for t in MailTemplate}
    for locale in (MailLocale.ES, MailLocale.FR):
        for template in MailTemplate:
            assert _render(template, locale).subject != english[template]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("es", MailLocale.ES),
        ("fr-CA", MailLocale.FR),
        ("ES_es", MailLocale.ES),
        ("de-DE, fr;q=0.9, en;q=0.8", MailLocale.FR),
        ("de", MailLocale.EN),
        ("", MailLocale.EN),
        (None, MailLocale.EN),
        ("*", MailLocale.EN),
    ],
)
def test_locale_resolution_falls_back_to_english(
    value: str | None, expected: MailLocale
) -> None:
    assert resolve_mail_locale(value) is expected


@pytest.mark.parametrize("locale", list(MailLocale))
@pytest.mark.parametrize("template", _LINK_TEMPLATES)
def test_link_templates_carry_the_link_in_both_bodies(
    template: MailTemplate, locale: MailLocale
) -> None:
    rendered = _render(template, locale)
    raw = _LINK.get_secret_value()
    assert raw in rendered.text
    assert f'href="{raw}"' in rendered.html
    assert f'<html lang="{locale.value}">' in rendered.html


@pytest.mark.parametrize("locale", list(MailLocale))
@pytest.mark.parametrize("template", _NOTICES)
def test_notices_have_no_link(template: MailTemplate, locale: MailLocale) -> None:
    rendered = _render(template, locale)
    assert "href" not in rendered.html
    assert "http" not in rendered.text


@pytest.mark.parametrize(
    ("locale", "minutes", "phrase"),
    [
        (MailLocale.EN, 30, "30 minutes"),
        (MailLocale.EN, 60, "1 hour."),
        (MailLocale.EN, 1440, "24 hours"),
        (MailLocale.ES, 90, "90 minutos"),
        (MailLocale.ES, 60, "1 hora."),
        (MailLocale.FR, 120, "2 heures"),
    ],
)
def test_expiry_is_stated_in_the_locale(
    locale: MailLocale, minutes: int, phrase: str
) -> None:
    rendered = _render(MailTemplate.PASSWORD_RESET, locale, expires_in_minutes=minutes)
    assert phrase in rendered.text
    assert phrase in rendered.html


@pytest.mark.parametrize(
    "kwargs",
    [
        {"link": None, "expires_in_minutes": 30},
        {"link": _LINK, "expires_in_minutes": None},
    ],
)
def test_a_link_template_needs_both_link_and_expiry(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="link arguments"):
        render_mail(MailTemplate.EMAIL_CHANGE, MailLocale.EN, **kwargs)  # type: ignore[arg-type]


def test_a_notice_takes_no_link() -> None:
    with pytest.raises(ValueError, match="link arguments"):
        render_mail(
            MailTemplate.PASSWORD_CHANGED_NOTICE,
            MailLocale.EN,
            link=_LINK,
            expires_in_minutes=30,
        )


def test_greeting_uses_the_name_when_there_is_one() -> None:
    assert _render(MailTemplate.ACCOUNT_EXISTS).text.startswith("Hello,\n")
    named = _render(MailTemplate.ACCOUNT_EXISTS, MailLocale.ES, full_name="Ana")
    assert named.text.startswith("Hola, Ana:\n")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("", None),
        ("  \r\n\t ", None),
        ("Ana\r\nBcc: x@example.com", "Ana Bcc: x@example.com"),
        ("A‮B​C\x00D", "ABCD"),
        ("Zoé  Ñandú", "Zoé Ñandú"),
        ("x" * (MAX_NAME_LENGTH + 20), "x" * MAX_NAME_LENGTH),
    ],
)
def test_display_name_is_cleaned(value: str | None, expected: str | None) -> None:
    assert clean_display_name(value) == expected


def test_rendered_bodies_stay_out_of_repr() -> None:
    rendered = _render(MailTemplate.EMAIL_VERIFICATION)
    assert _LINK.get_secret_value() not in repr(rendered)
