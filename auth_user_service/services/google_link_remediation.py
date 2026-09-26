"""Evict the sessions obtained through the implicit Google email link (S1A, N16).

S1 closed the implicit link — a Google login no longer enters a PASSWORD
account by email — but it evicts nobody: a session and refresh token obtained
through the link before the upgrade stay valid until they expire.
:class:`GoogleLinkRemediationController` revokes them the way a role change
does: bump the owner's ``auth_generation``, delete the owner's session rows, and
enqueue the durable outbox effects (Redis blacklist per access JTI plus the
user-wide v2 session-revoked event for consumer caches), one transaction per
account.

Two scopes:

* ``reported`` — the accounts the read-only S1 report lists
  (:mod:`auth_user_service.services.google_link_report`). A refresh needs the
  account's current session row, and that row is the one the report reads, so
  every refreshable session obtained through the link is in scope. The report
  can still miss an account whose row a later password login overwrote; the
  access token obtained through the link is then already refused by
  ``jti-status`` (its row is gone) and stays wire-valid for stateless
  validation only until its own expiry.
* ``all_sessions`` — every account that holds a session row, fleet-wide, for an
  operator who does not want to rely on that evidence.

Both are idempotent: revoked accounts no longer hold a session row, so a repeat
run finds nothing to do. Results carry ids and counts only.
"""

import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from sqlmodel import Session, col, select

from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.users import User
from auth_user_service.services.client_sessions import SessionController
from auth_user_service.services.generation import GenerationController
from auth_user_service.services.google_link_report import GoogleLinkReportController
from auth_user_service.services.outbox import OutboxController
from auth_user_service.services.role_admin import record_enqueued_metrics


class RemediationScope(str, Enum):
    """Which accounts a remediation run revokes."""

    REPORTED = "reported"
    ALL_SESSIONS = "all_sessions"


@dataclass(frozen=True)
class RemediationResult:
    """Accounts revoked by one run, and how many session rows went with them."""

    scope: RemediationScope
    user_ids: tuple[uuid.UUID, ...]
    revoked_session_count: int

    @property
    def account_count(self) -> int:
        """Number of accounts revoked."""
        return len(self.user_ids)


def _accounts_with_sessions(session: Session) -> tuple[uuid.UUID, ...]:
    """Every account that holds at least one session row, in a stable order."""
    rows = session.exec(select(ClientSession.user_id).distinct()).all()
    return tuple(sorted(rows, key=str))


def _revoke_account(session: Session, user_id: uuid.UUID) -> int:
    """Bump, revoke, and enqueue for one account; commit; return the rows deleted."""
    # Session rows cascade with their user, so the account exists.
    user = session.exec(
        select(User).where(col(User.id) == user_id).with_for_update()
    ).one()
    generation = GenerationController.bump_user_generation(user)
    targets, deleted = SessionController.capture_and_delete_user_sessions(
        session, user_id
    )
    enqueued = OutboxController.enqueue_role_change_effects(
        session, user_id=user_id, auth_generation=generation, targets=targets
    )
    session.add(user)
    session.commit()
    record_enqueued_metrics(enqueued)
    return deleted


def _revoke_accounts(
    session: Session, scope: RemediationScope, user_ids: Iterable[uuid.UUID]
) -> RemediationResult:
    revoked: list[uuid.UUID] = []
    deleted = 0
    for user_id in user_ids:
        deleted += _revoke_account(session, user_id)
        revoked.append(user_id)
    return RemediationResult(
        scope=scope, user_ids=tuple(revoked), revoked_session_count=deleted
    )


class GoogleLinkRemediationController:
    """Service behind :mod:`auth_user_service.scripts.google_link_remediation`."""

    @staticmethod
    def run(session: Session, scope: RemediationScope) -> RemediationResult:
        """Revoke every session of the accounts in *scope*."""
        if scope is RemediationScope.ALL_SESSIONS:
            user_ids = _accounts_with_sessions(session)
        else:
            user_ids = GoogleLinkReportController.run(session).user_ids
        return _revoke_accounts(session, scope, user_ids)
