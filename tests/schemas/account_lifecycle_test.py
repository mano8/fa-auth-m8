"""Tests for schemas.account_lifecycle — the frozen capability document."""

import pytest
from pydantic import ValidationError

from auth_sdk_m8.schemas.base import AuthProviderType

from auth_user_service.schemas.account_lifecycle import (
    CAPABILITIES_VERSION,
    EMAIL_CHANGE_CONFIRM_PATH,
    GOOGLE_LOGIN_PATH,
    PASSWORD_LOGIN_PATH,
    PASSWORD_RESET_CONFIRM_PATH,
    PASSWORD_RESET_REQUEST_PATH,
    REGISTER_PATH,
    VERIFY_EMAIL_CONFIRM_PATH,
    VERIFY_EMAIL_REQUEST_PATH,
    AccountActionResponse,
    AccountCapabilities,
    AccountCapabilityPaths,
    AccountErrorCode,
    EmailVerificationMode,
)

_LEGACY_PATHS = AccountCapabilityPaths(password_login=PASSWORD_LOGIN_PATH)


def _legacy() -> AccountCapabilities:
    """The document of a deployment with every new flag off (2.2.3 behavior)."""
    return AccountCapabilities(
        login_providers=(AuthProviderType.PASSWORD,),
        public_signup=False,
        email_verification=EmailVerificationMode.OFF,
        password_reset=False,
        email_change_confirmation=False,
        paths=_LEGACY_PATHS,
    )


def _everything() -> AccountCapabilities:
    return AccountCapabilities(
        login_providers=(AuthProviderType.PASSWORD, AuthProviderType.GOOGLE),
        public_signup=True,
        email_verification=EmailVerificationMode.REQUIRED,
        password_reset=True,
        email_change_confirmation=True,
        unverified_signup_expiry_days=7,
        paths=AccountCapabilityPaths(
            password_login=PASSWORD_LOGIN_PATH,
            google_login=GOOGLE_LOGIN_PATH,
            signup=REGISTER_PATH,
            verify_email_request=VERIFY_EMAIL_REQUEST_PATH,
            verify_email_confirm=VERIFY_EMAIL_CONFIRM_PATH,
            password_reset_request=PASSWORD_RESET_REQUEST_PATH,
            password_reset_confirm=PASSWORD_RESET_CONFIRM_PATH,
            email_change_confirm=EMAIL_CHANGE_CONFIRM_PATH,
        ),
    )


def test_legacy_document_serializes_to_the_frozen_shape() -> None:
    assert _legacy().model_dump(mode="json") == {
        "capabilities_version": "1.0",
        "login_providers": ["password"],
        "public_signup": False,
        "email_verification": "off",
        "password_reset": False,
        "email_change_confirmation": False,
        "unverified_signup_expiry_days": None,
        "paths": {
            "password_login": "/login/access-token",
            "google_login": None,
            "signup": None,
            "verify_email_request": None,
            "verify_email_confirm": None,
            "password_reset_request": None,
            "password_reset_confirm": None,
            "email_change_confirm": None,
        },
    }


def test_full_document_is_valid() -> None:
    doc = _everything()
    assert doc.capabilities_version == CAPABILITIES_VERSION
    assert doc.paths.signup == "/account/register"


@pytest.mark.parametrize(
    "change",
    [
        {"public_signup": True},
        {"password_reset": True},
        {"email_change_confirmation": True},
        {"email_verification": EmailVerificationMode.OPTIONAL},
        {"login_providers": (AuthProviderType.GOOGLE,)},
        {"login_providers": (AuthProviderType.PASSWORD, AuthProviderType.GOOGLE)},
    ],
    ids=["signup", "reset", "email-change", "verification", "no-password", "google"],
)
def test_feature_without_matching_path_is_rejected(change: dict[str, object]) -> None:
    fields = _legacy().model_dump() | change
    with pytest.raises(ValidationError, match="paths do not match"):
        AccountCapabilities.model_validate(fields)


def test_path_for_disabled_feature_is_rejected() -> None:
    fields = _legacy().model_dump()
    fields["paths"]["signup"] = REGISTER_PATH
    with pytest.raises(ValidationError, match="paths do not match"):
        AccountCapabilities.model_validate(fields)


def test_expiry_only_with_signup_and_verification() -> None:
    fields = _legacy().model_dump() | {"unverified_signup_expiry_days": 7}
    with pytest.raises(ValidationError, match="unverified_signup_expiry_days"):
        AccountCapabilities.model_validate(fields)
    fields = _everything().model_dump() | {"unverified_signup_expiry_days": None}
    with pytest.raises(ValidationError, match="unverified_signup_expiry_days"):
        AccountCapabilities.model_validate(fields)


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.example/account/register",
        "//evil.example/x",
        "/account/../private/x",
        "/account/register?next=x",
        "/account/register#x",
        "account/register",
        "/Account/Register",
        "/account\\register",
        "/" + "a" * 128,
    ],
)
def test_unsafe_paths_are_rejected(path: str) -> None:
    with pytest.raises(ValidationError):
        AccountCapabilityPaths(password_login=path)


def test_unknown_fields_are_rejected() -> None:
    fields = _legacy().model_dump() | {"smtp_host": "mail.internal"}
    with pytest.raises(ValidationError):
        AccountCapabilities.model_validate(fields)
    with pytest.raises(ValidationError):
        AccountCapabilityPaths.model_validate({"admin": "/users/"})


def test_capabilities_version_is_pinned() -> None:
    fields = _legacy().model_dump() | {"capabilities_version": "2.0"}
    with pytest.raises(ValidationError):
        AccountCapabilities.model_validate(fields)


def test_error_codes_and_action_response() -> None:
    assert {code.value for code in AccountErrorCode} == {
        "feature_unavailable",
        "challenge_invalid",
        "email_unverified",
        "rate_limited",
    }
    assert AccountActionResponse(status="accepted").model_dump() == {
        "status": "accepted"
    }
    with pytest.raises(ValidationError):
        AccountActionResponse.model_validate({"status": "sent"})
