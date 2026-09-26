"""Read-only report of accounts that relied on the implicit Google email link (S1).

Before S1, a Google login entered **any** existing account whose email matched
the address Google asserted, whatever that account's provider. A PASSWORD
account signed into that way got a session carrying the Google tokens; S1 now
refuses such a login (no implicit linking, ``D-g``), so these users lose their
Google sign-in and must use their password.

:class:`GoogleLinkReportController` lists that population so an operator can
reach them before or after the upgrade. It reads scalar columns only, writes
nothing, and reports ids and counts only -- never email, Google subject, token,
JTI, or session-payload data.

Evidence limit: an account keeps a single session row that every login
overwrites, and a password login clears the Google token columns. The report is
therefore a **lower bound** -- an account whose most recent login was a
password login is not listed even if it used Google earlier.
"""

import uuid
from dataclasses import dataclass
from typing import Tuple

from sqlmodel import Session, col, or_, select

from auth_sdk_m8.schemas.base import AuthProviderType, RoleType

from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.users import User


@dataclass(frozen=True)
class GoogleLinkReport:
    """Non-GOOGLE accounts whose session shows a Google sign-in.

    Carries only user ids -- never email, subject, token, or session data.
    """

    user_ids: Tuple[uuid.UUID, ...]
    superadmin_ids: Tuple[uuid.UUID, ...]

    @property
    def count(self) -> int:
        """Number of affected accounts."""
        return len(self.user_ids)

    @property
    def clean(self) -> bool:
        """Whether no account relied on the implicit link."""
        return not self.user_ids


class GoogleLinkReportController:
    """Read-only query behind :mod:`auth_user_service.scripts.google_link_report`."""

    @staticmethod
    def run(session: Session) -> GoogleLinkReport:
        """Return the non-GOOGLE accounts with a Google-bearing session.

        A session shows a Google sign-in when it holds Google tokens or was
        recorded under the GOOGLE provider; the account itself is anything but
        a GOOGLE account (PASSWORD today). Revoked sessions count: they are
        still evidence of how the account was entered.
        """
        statement = (
            select(User.id, User.role)
            .join(ClientSession, col(ClientSession.user_id) == col(User.id))
            .where(
                col(User.provider) != AuthProviderType.GOOGLE,
                or_(
                    col(ClientSession.provider) == AuthProviderType.GOOGLE,
                    col(ClientSession.external_access_token).is_not(None),
                    col(ClientSession.external_refresh_token).is_not(None),
                ),
            )
            .distinct()
        )
        rows = sorted(session.exec(statement).all(), key=lambda row: str(row[0]))
        return GoogleLinkReport(
            user_ids=tuple(user_id for user_id, _ in rows),
            superadmin_ids=tuple(
                user_id for user_id, role in rows if role == RoleType.SUPERADMIN
            ),
        )
