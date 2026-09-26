"""Google identity binding for login (S1).

A Google login enters an account only through the identity it is bound to,
``(provider=GOOGLE, oauth_user_id=<Google sub>)`` — never through the email
address Google asserts. There is no implicit linking between Google and
password identities (``D-g``): an email another account already holds is
refused, never entered.

:class:`GoogleIdentityController` owns that decision and raises
:class:`GoogleLoginRefused` with a :class:`GoogleLoginRefusal` reason. The
route maps every reason to one generic response, so the reason is for audit
and metrics only and must never reach the client.
"""

import uuid
from enum import Enum
from typing import Optional

from sqlmodel import Session

from auth_sdk_m8.schemas.base import AuthProviderType
from auth_sdk_m8.utils.email import normalize_email

from auth_user_service.db_models.users import User, UserCreate
from auth_user_service.schemas.google import OAuthGoogleToken
from auth_user_service.services.generation import GenerationController
from auth_user_service.services.users import UserController


class GoogleLoginRefusal(str, Enum):
    """Why a Google login was refused — a small, metric-label-safe vocabulary."""

    EMAIL_UNVERIFIED = "email_unverified"
    SUBJECT_MISSING = "subject_missing"
    EMAIL_IN_USE = "email_in_use"
    SUBJECT_MISMATCH = "subject_mismatch"
    INACTIVE = "inactive"
    TOMBSTONED = "tombstoned"


class GoogleLoginRefused(Exception):
    """A Google login that must not create or enter any account.

    ``user_id`` is the matched account, when there is one — a non-secret
    identifier for the audit log. The asserted email and Google ``sub`` are
    deliberately not carried.
    """

    def __init__(
        self, reason: GoogleLoginRefusal, user_id: Optional[uuid.UUID] = None
    ) -> None:
        super().__init__(reason.value)
        self.reason = reason
        self.user_id = user_id


class GoogleIdentityController:
    """Resolve a verified Google identity to the one account it may enter."""

    @staticmethod
    def resolve(session: Session, oauth_token: OAuthGoogleToken) -> User:
        """Return the account bound to this Google identity, provisioning it if new.

        Google must assert ``email_verified is True`` to create or enter an
        account, and the account must be active and not tombstoned. Every check
        runs before the caller mints any token or session.

        Raises:
            GoogleLoginRefused: when any rule refuses the login.
        """
        if oauth_token.email_verified is not True:
            raise GoogleLoginRefused(GoogleLoginRefusal.EMAIL_UNVERIFIED)
        if not oauth_token.user_id:
            raise GoogleLoginRefused(GoogleLoginRefusal.SUBJECT_MISSING)
        user = UserController.get_user_by_oauth_identity(
            session=session,
            provider=AuthProviderType.GOOGLE,
            oauth_user_id=oauth_token.user_id,
        )
        if user is None:
            user = GoogleIdentityController._provision(session, oauth_token)
        if not user.is_active:
            raise GoogleLoginRefused(GoogleLoginRefusal.INACTIVE, user.id)
        if GenerationController.subject_is_tombstoned(session, user.id):
            raise GoogleLoginRefused(GoogleLoginRefusal.TOMBSTONED, user.id)
        return user

    @staticmethod
    def _provision(session: Session, oauth_token: OAuthGoogleToken) -> User:
        """Create a GOOGLE account, refusing an email another account holds.

        A PASSWORD holder (the first superuser included) and a Google holder
        bound to a different ``sub`` are both refused; neither is linked.
        """
        email = normalize_email(oauth_token.email)
        holder = UserController.get_user_by_email(session=session, email=email)
        if holder is not None:
            reason = (
                GoogleLoginRefusal.SUBJECT_MISMATCH
                if holder.provider == AuthProviderType.GOOGLE
                else GoogleLoginRefusal.EMAIL_IN_USE
            )
            raise GoogleLoginRefused(reason, holder.id)
        user_in = UserCreate(
            provider=AuthProviderType.GOOGLE,
            oauth_user_id=oauth_token.user_id,
            email=email,
            email_verified=True,
            full_name=oauth_token.name.strip(),
        )
        return UserController.create_user(session=session, user_create=user_in)
