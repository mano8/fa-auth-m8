"""The one password mutation service (A4, ACCT-G5).

Every write of an existing account's ``hashed_password`` goes through here, so
each one follows the same policy:

- only a PASSWORD account has a password. A GOOGLE account is refused with a
  typed :class:`PasswordNotAllowed`; the check reads the **stored** provider,
  never a client-supplied one, and no code path matches identities by email;
- a mutation bumps ``auth_generation``, revokes every session — the caller's
  included (``D-c``) — and enqueues the durable outbox effects, in the same
  transaction as the new hash, so a client signs in again with the new password;
- a mutation is audited: the self-service change logs
  ``event=password.changed``; an admin set also writes the ``edit`` audit row of
  ``services.role_admin.change_user_authorization``.

The self-service change (:meth:`PasswordController.change_own_password`) owns
its commit. An admin set composes :func:`apply_new_password` into the
route-owned superuser-set transaction, which then revokes once for all the
changes it applies. Account creation sets the first hash elsewhere; it is not a
mutation of an existing credential.

Wave 2 extends this service (challenge invalidation, password-changed notice,
recovery reset).
"""

import logging
from dataclasses import dataclass


from sqlmodel import Session

from auth_sdk_m8.schemas.base import AuthProviderType

from auth_user_service.core.security import SecurityHelper
from auth_user_service.db_models.users import User
from auth_user_service.services.auth import AuthController
from auth_user_service.services.revocation import (
    record_enqueued_metrics,
    revoke_and_enqueue_authorization_change,
)

logger = logging.getLogger(__name__)

# The one client-facing detail for a refused password operation (``403``).
PASSWORD_NOT_ALLOWED_DETAIL = "Password operations are not available for this account"


class PasswordMutationError(Exception):
    """Base class for a refused password mutation. Nothing is written."""


class PasswordNotAllowed(PasswordMutationError):
    """The account does not sign in with a password. Mapped to ``403``."""


class IncorrectCurrentPassword(PasswordMutationError):
    """``current_password`` did not match. Mapped to ``400``."""


class PasswordUnchanged(PasswordMutationError):
    """The new password equals the current one. Mapped to ``400``."""


@dataclass(frozen=True)
class PasswordChangeResult:
    """The refreshed user after a committed password change."""

    user: User
    auth_generation: int


def ensure_password_account(db_user: User) -> None:
    """Refuse any password operation on an account that is not PASSWORD."""
    if db_user.provider != AuthProviderType.PASSWORD:
        raise PasswordNotAllowed("password_not_allowed")


def apply_new_password(db_user: User, new_password: str) -> None:
    """Hash *new_password* onto *db_user* in memory, after the provider check.

    Transaction-neutral: the caller revokes (bump, sessions, outbox) and
    commits in the same unit of work.
    """
    ensure_password_account(db_user)
    db_user.hashed_password = SecurityHelper.get_password_hash(new_password)


def log_password_changed(db_user: User, *, actor_id: object) -> None:
    """Record a committed password mutation. Never logs a password or hash."""
    actor = "self" if str(actor_id) == str(db_user.id) else "admin"
    logger.info(
        "event=password.changed user_id=%s actor=%s actor_id=%s auth_generation=%d",
        db_user.id,
        actor,
        actor_id,
        db_user.auth_generation,
    )


class PasswordController:
    """Self-service password mutation."""

    @staticmethod
    def change_own_password(
        session: Session,
        db_user: User,
        *,
        current_password: str,
        new_password: str,
    ) -> PasswordChangeResult:
        """Replace the caller's password and revoke every session, committing once.

        The current password is checked with constant work (the same check as
        login) after the provider check. Raises a
        :class:`PasswordMutationError` subclass when refused; nothing is
        written in that case.
        """
        ensure_password_account(db_user)
        if not AuthController.verify_password_constant_work(
            current_password, db_user.hashed_password
        ):
            raise IncorrectCurrentPassword("incorrect_password")
        if current_password == new_password:
            raise PasswordUnchanged("password_unchanged")

        apply_new_password(db_user, new_password)
        enqueued = revoke_and_enqueue_authorization_change(session, db_user)
        session.add(db_user)
        session.commit()
        session.refresh(db_user)

        record_enqueued_metrics(enqueued)
        log_password_changed(db_user, actor_id=db_user.id)
        return PasswordChangeResult(
            user=db_user, auth_generation=db_user.auth_generation
        )
