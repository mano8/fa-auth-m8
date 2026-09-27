"""Account-lifecycle public contract types.

Frozen by ``docs/account-lifecycle-contract.md``. These are the browser-facing
shapes of the optional account-lifecycle features: the capability document
(§2), the error codes (§5), and the generic action response (§5). They carry
no configuration value beyond what a sign-in page must know — no SMTP host,
domain allowlist, internal URL, or key material (``SEC-NO-SECRET-DISCLOSURE``).
"""

from enum import Enum
from typing import Annotated, Final, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from auth_sdk_m8.schemas.base import AuthProviderType

#: Version of the capability document itself, independent of the issuer
#: ``CONTRACT_VERSION`` (which stays ``"2.0"``). A new optional field is a
#: minor bump; removing or retyping one is a major bump.
CAPABILITIES_VERSION: Final = "1.0"

#: A route path relative to ``API_PREFIX``: lowercase slug segments only, so it
#: can never carry a scheme, host, ``//``, ``..``, query, or fragment.
SafeRelativePath = Annotated[
    str, Field(pattern=r"^/[a-z0-9-]+(?:/[a-z0-9-]+)*/?$", max_length=128)
]

# Frozen route paths (contract §3), relative to ``API_PREFIX``.
PASSWORD_LOGIN_PATH = "/login/access-token"  # nosec B105
GOOGLE_LOGIN_PATH = "/google-api/login-url/"
CAPABILITIES_PATH = "/account/capabilities"
REGISTER_PATH = "/account/register"
VERIFY_EMAIL_REQUEST_PATH = "/account/verify-email/request"
VERIFY_EMAIL_CONFIRM_PATH = "/account/verify-email/confirm"
PASSWORD_RESET_REQUEST_PATH = "/account/password-reset/request"  # nosec B105
PASSWORD_RESET_CONFIRM_PATH = "/account/password-reset/confirm"  # nosec B105
EMAIL_CHANGE_CONFIRM_PATH = "/account/email-change/confirm"


class EmailVerificationMode(str, Enum):
    """``EMAIL_VERIFICATION_MODE`` (decision ``D-f``)."""

    OFF = "off"
    OPTIONAL = "optional"
    REQUIRED = "required"


class AccountErrorCode(str, Enum):
    """Machine-readable ``detail`` values of the account-lifecycle routes."""

    FEATURE_UNAVAILABLE = "feature_unavailable"
    CHALLENGE_INVALID = "challenge_invalid"
    EMAIL_UNVERIFIED = "email_unverified"
    RATE_LIMITED = "rate_limited"


class AccountCapabilityPaths(BaseModel):
    """Where each enabled action lives; ``None`` exactly when it is disabled."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    password_login: Optional[SafeRelativePath] = None
    google_login: Optional[SafeRelativePath] = None
    signup: Optional[SafeRelativePath] = None
    verify_email_request: Optional[SafeRelativePath] = None
    verify_email_confirm: Optional[SafeRelativePath] = None
    password_reset_request: Optional[SafeRelativePath] = None
    password_reset_confirm: Optional[SafeRelativePath] = None
    email_change_confirm: Optional[SafeRelativePath] = None


class AccountCapabilities(BaseModel):
    """The public capability document served at ``CAPABILITIES_PATH``.

    The UI's source of truth for which controls to show; every backend route
    still enforces its own flag. The validator pins the implication that a
    path is published if and only if its feature is on, so a document can
    never advertise a disabled route or hide an enabled one.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    capabilities_version: Literal["1.0"] = CAPABILITIES_VERSION
    login_providers: tuple[AuthProviderType, ...]
    public_signup: bool
    email_verification: EmailVerificationMode
    password_reset: bool
    email_change_confirmation: bool
    unverified_signup_expiry_days: Optional[int] = Field(default=None, ge=1, le=30)
    paths: AccountCapabilityPaths

    @model_validator(mode="after")
    def _paths_match_features(self) -> "AccountCapabilities":
        verification_on = self.email_verification is not EmailVerificationMode.OFF
        expected = {
            "password_login": AuthProviderType.PASSWORD in self.login_providers,
            "google_login": AuthProviderType.GOOGLE in self.login_providers,
            "signup": self.public_signup,
            "verify_email_request": verification_on,
            "verify_email_confirm": verification_on,
            "password_reset_request": self.password_reset,
            "password_reset_confirm": self.password_reset,
            "email_change_confirm": self.email_change_confirmation,
        }
        published = {name: getattr(self.paths, name) is not None for name in expected}
        mismatched = sorted(
            name for name in expected if expected[name] != published[name]
        )
        if mismatched:
            raise ValueError(f"paths do not match enabled features: {mismatched}")
        expiry_expected = self.public_signup and verification_on
        if (self.unverified_signup_expiry_days is not None) != expiry_expected:
            raise ValueError(
                "unverified_signup_expiry_days is set exactly when public signup "
                "runs with verification on"
            )
        return self


class AccountActionResponse(BaseModel):
    """Body of every accepted or completed account-lifecycle action.

    ``accepted`` (``202``) is the one response of the non-disclosing request
    routes; ``completed`` (``200``) answers a consumed challenge.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["accepted", "completed"]
