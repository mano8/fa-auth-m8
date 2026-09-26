"""Self-service profile update with a re-authenticated email change (S1A).

Changing the email of an account changes who can recover it, so a stolen access
token must not be enough (``N3``, ``N17``):

- a GOOGLE account cannot change its email here: the address is Google's, and
  letting it move would let one Google account squat an address whose real
  owner's Google sign-in is then refused;
- a PASSWORD account must send its ``current_password``, checked with constant
  work, **before** the new address is looked up, so a caller without the
  password cannot use the conflict answer to learn which addresses exist;
- an applied change clears ``email_verified``, bumps ``auth_generation``,
  revokes every session (the caller's included) with the same durable outbox
  effects as a role change, and is audited.

A mail-confirmed ``pending_email`` flow is a later step (``A2``).
"""

import logging
from dataclasses import dataclass
from typing import Final, Optional

from sqlmodel import Session

from auth_sdk_m8.schemas.base import AuthProviderType

from auth_user_service.db_models.outbox import RevocationOutbox
from auth_user_service.db_models.users import User, UserUpdateMe
from auth_user_service.services.auth import AuthController
from auth_user_service.services.role_admin import (
    record_enqueued_metrics,
    revoke_and_enqueue_authorization_change,
)
from auth_user_service.services.users import UserController

logger = logging.getLogger(__name__)

# Explicit allowlist for self-service profile updates — must never include
# is_superuser, and never current_password (a credential, not a profile field).
SELF_SERVICE_FIELDS: Final[frozenset[str]] = frozenset({"email", "full_name", "avatar"})


class ProfileUpdateError(Exception):
    """Base class for a refused self-service profile update."""


class EmailChangeNotAllowed(ProfileUpdateError):
    """A GOOGLE account tried to change its email. Mapped to ``403``."""


class CurrentPasswordRequired(ProfileUpdateError):
    """An email change arrived without ``current_password``. Mapped to ``400``."""


class IncorrectCurrentPassword(ProfileUpdateError):
    """``current_password`` did not match. Mapped to ``400``."""


class EmailAlreadyInUse(ProfileUpdateError):
    """Another account holds the requested email. Mapped to ``409``."""


@dataclass(frozen=True)
class ProfileUpdateResult:
    """The refreshed user and whether its email (and so its sessions) changed."""

    user: User
    email_changed: bool


def _authorize_email_change(db_user: User, current_password: Optional[str]) -> None:
    """Refuse an email change the account holder has not re-authenticated."""
    if db_user.provider == AuthProviderType.GOOGLE:
        raise EmailChangeNotAllowed("email_change_not_allowed")
    if current_password is None:
        raise CurrentPasswordRequired("current_password_required")
    if not AuthController.verify_password_constant_work(
        current_password, db_user.hashed_password
    ):
        raise IncorrectCurrentPassword("incorrect_password")


class ProfileController:
    """Self-service profile mutations."""

    @staticmethod
    def update_me(
        session: Session, db_user: User, user_in: UserUpdateMe
    ) -> ProfileUpdateResult:
        """Apply an allowlisted self-service update, committing once.

        Raises a :class:`ProfileUpdateError` subclass when the email change is
        refused; nothing is written in that case.
        """
        # ``email`` is non-nullable, so an explicit null means "unchanged".
        user_data = {
            field: value
            for field, value in user_in.model_dump(exclude_unset=True).items()
            if field in SELF_SERVICE_FIELDS and not (field == "email" and value is None)
        }
        new_email = user_in.email
        email_changed = False
        if new_email is not None and new_email != db_user.email:
            email_changed = True
            _authorize_email_change(db_user, user_in.current_password)
            holder = UserController.get_user_by_email(session=session, email=new_email)
            if holder is not None and holder.id != db_user.id:
                raise EmailAlreadyInUse("email_in_use")

        for field, value in user_data.items():
            setattr(db_user, field, value)
        enqueued: list[RevocationOutbox] = []
        if email_changed:
            db_user.email_verified = False
            enqueued = revoke_and_enqueue_authorization_change(session, db_user)
        session.add(db_user)
        session.commit()
        session.refresh(db_user)

        if email_changed:
            record_enqueued_metrics(enqueued)
            logger.info(
                "event=profile.email_changed user_id=%s auth_generation=%d",
                db_user.id,
                db_user.auth_generation,
            )
        return ProfileUpdateResult(user=db_user, email_changed=email_changed)
