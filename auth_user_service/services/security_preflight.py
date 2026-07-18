"""Read-only mismatch/last-superuser preflight (4.1 ``MIG-PREFLIGHT-01``).

Reports existing-row consistency ahead of the Expand -> repair -> Enforce
migration sequence (4.1). SDK 3 models and the strict issuer ``User`` model
reject an inconsistent ``role``/``is_superuser`` pair (mirroring the DB check
constraint that is only added in Enforce), so scanning for exactly the rows
that need fixing must never construct a ``User``/validating ORM entity for one
of them -- every query here selects individual scalar columns only. This
module performs no writes; the audited repair command is a separate item.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Tuple

from sqlmodel import Session, col, func, select

from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.users import User


@dataclass(frozen=True)
class SecurityPreflightReport:
    """Read-only mismatch/last-superuser preflight result (4.1).

    Carries only user ids and counts -- never email, token, JTI,
    password/provider secret, or session-payload data, per 4.1's
    no-sensitive-output rule.
    """

    flagged_not_superadmin_ids: Tuple[uuid.UUID, ...]
    superadmin_not_flagged_ids: Tuple[uuid.UUID, ...]
    active_canonical_superuser_count: int
    inconsistent_ids_with_active_sessions: Tuple[uuid.UUID, ...]

    @property
    def flagged_not_superadmin_count(self) -> int:
        """Count where ``is_superuser=true`` and ``role`` is not SUPERADMIN."""
        return len(self.flagged_not_superadmin_ids)

    @property
    def superadmin_not_flagged_count(self) -> int:
        """Count where ``role`` is SUPERADMIN and ``is_superuser=false``."""
        return len(self.superadmin_not_flagged_ids)

    @property
    def clean(self) -> bool:
        """Whether zero mismatches were found (migration may proceed, 4.1)."""
        return (
            not self.flagged_not_superadmin_ids and not self.superadmin_not_flagged_ids
        )


class SecurityPreflightController:
    """Raw-column read-only mismatch/last-superuser preflight (4.1)."""

    @staticmethod
    def run(session: Session) -> SecurityPreflightReport:
        """Scan existing rows and report mismatches; performs no writes.

        Every ``User``-touching query selects individual scalar columns (never
        ``select(User)`` or ``User.model_validate``), so a row this preflight
        exists to find can never itself raise while being found.
        """
        flagged_not_superadmin = tuple(
            session.exec(
                select(User.id).where(
                    col(User.is_superuser) == True,  # noqa: E712
                    col(User.role) != RoleType.SUPERADMIN,
                )
            ).all()
        )
        superadmin_not_flagged = tuple(
            session.exec(
                select(User.id).where(
                    col(User.role) == RoleType.SUPERADMIN,
                    col(User.is_superuser) == False,  # noqa: E712
                )
            ).all()
        )
        active_superuser_count = session.exec(
            select(func.count())  # pylint: disable=not-callable
            .select_from(User)
            .where(
                col(User.role) == RoleType.SUPERADMIN,
                col(User.is_superuser) == True,  # noqa: E712
                col(User.is_active) == True,  # noqa: E712
            )
        ).one()
        inconsistent_ids = flagged_not_superadmin + superadmin_not_flagged
        with_active_sessions = SecurityPreflightController._ids_with_active_sessions(
            session, inconsistent_ids
        )
        return SecurityPreflightReport(
            flagged_not_superadmin_ids=flagged_not_superadmin,
            superadmin_not_flagged_ids=superadmin_not_flagged,
            active_canonical_superuser_count=active_superuser_count,
            inconsistent_ids_with_active_sessions=with_active_sessions,
        )

    @staticmethod
    def _ids_with_active_sessions(
        session: Session, user_ids: Tuple[uuid.UUID, ...]
    ) -> Tuple[uuid.UUID, ...]:
        """Distinct owner ids among *user_ids* holding an active session.

        "Active" matches ``SessionController.get_user_active_sessions``:
        non-revoked and not yet past ``refresh_expires_at``.
        """
        if not user_ids:
            return ()
        now = datetime.now(timezone.utc)
        rows = session.exec(
            select(ClientSession.user_id)
            .where(
                col(ClientSession.user_id).in_(user_ids),
                col(ClientSession.revoked) == False,  # noqa: E712
                col(ClientSession.refresh_expires_at) > now,
            )
            .distinct()
        ).all()
        return tuple(rows)
