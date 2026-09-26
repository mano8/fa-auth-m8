"""Block markers for external identities an administrator deleted (``D-j``).

Every deletion tombstones and revokes; only an **admin** deletion of a GOOGLE
account also blocks its Google identity, so the same ``sub`` cannot provision a
new account until an audited unblock (``scripts/google_identity_unblock``). A
self-deleted user is not blocked and may come back.

The marker is keyed by the SHA-256 of ``"<provider>:<subject>"``; the raw
subject is never stored or logged.
"""

import hashlib
import logging
import uuid

from sqlmodel import Session, col, delete, select

from auth_sdk_m8.schemas.base import AuthProviderType

from auth_user_service.db_models.identity_blocks import IdentityBlock

logger = logging.getLogger(__name__)


def identity_digest(provider: AuthProviderType, subject: str) -> str:
    """Return the SHA-256 hex digest that stands for one external identity."""
    return hashlib.sha256(f"{provider.value}:{subject}".encode("utf-8")).hexdigest()


class IdentityBlockController:
    """Write, check, and lift external-identity block markers."""

    @staticmethod
    def block(
        session: Session,
        *,
        provider: AuthProviderType,
        subject: str,
        user_id: uuid.UUID,
    ) -> None:
        """Record a block for this identity — transaction-neutral, idempotent.

        The caller owns the commit, so the block commits atomically with the
        deletion that caused it. An identity that is already blocked keeps its
        first marker.
        """
        digest = identity_digest(provider, subject)
        if session.get(IdentityBlock, digest) is None:
            session.add(IdentityBlock(identity_digest=digest, user_id=user_id))
        logger.info(
            "event=identity.blocked provider=%s user_id=%s", provider.value, user_id
        )

    @staticmethod
    def is_blocked(
        session: Session, *, provider: AuthProviderType, subject: str
    ) -> bool:
        """Whether this identity carries a block marker."""
        return (
            session.get(IdentityBlock, identity_digest(provider, subject)) is not None
        )

    @staticmethod
    def unblock_deleted_user(session: Session, user_id: uuid.UUID) -> int:
        """Lift every block that came from deleting *user_id*; commit; return the count.

        Idempotent: a second call finds nothing and returns ``0``.
        """
        found = session.exec(
            select(IdentityBlock.identity_digest).where(
                col(IdentityBlock.user_id) == user_id
            )
        ).all()
        if not found:
            return 0
        session.exec(delete(IdentityBlock).where(col(IdentityBlock.user_id) == user_id))
        session.commit()
        return len(found)
