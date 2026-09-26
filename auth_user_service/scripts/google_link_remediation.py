#!/usr/bin/env python
"""Audited operator command: evict sessions from the implicit Google link (S1A).

Run right after deploying the release that contains S1. S1 stops a Google
login from entering a PASSWORD account by email, but sessions obtained that way
before the upgrade stay valid until they expire. This command revokes them
exactly like a role change (generation bump, session revocation, durable outbox
effects); see :mod:`auth_user_service.services.google_link_remediation`.

Two scopes, each with its own confirmation token:

* ``--scope reported`` (default) — the accounts the read-only
  ``google_link_report`` lists; ``--confirm REVOKE-GOOGLE-LINKED-SESSIONS``;
* ``--scope all-sessions`` — every account holding a session, fleet-wide
  (everyone signs in again); ``--confirm REVOKE-ALL-SESSIONS``.

Idempotent: a repeat run finds nothing left to revoke. Logs the actor, the
reason, the scope, account ids, and counts -- never email, Google subject,
token, JTI, or session-payload data.

Run::

    python -m auth_user_service.scripts.google_link_remediation \\
        --confirm REVOKE-GOOGLE-LINKED-SESSIONS --actor <who> --reason <why>
"""

from __future__ import annotations

import argparse
import logging
from typing import List, Optional

from sqlmodel import Session

from auth_user_service.core.engine_sync import engine
from auth_user_service.services.google_link_remediation import (
    GoogleLinkRemediationController,
    RemediationResult,
    RemediationScope,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

#: CLI scope name -> (service scope, confirmation token it requires).
_SCOPES = {
    "reported": (RemediationScope.REPORTED, "REVOKE-GOOGLE-LINKED-SESSIONS"),
    "all-sessions": (RemediationScope.ALL_SESSIONS, "REVOKE-ALL-SESSIONS"),
}


def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="google_link_remediation",
        description=(
            "Revoke the sessions obtained through the implicit Google email link "
            "(audited, S1A)."
        ),
    )
    parser.add_argument(
        "--scope",
        choices=sorted(_SCOPES),
        default="reported",
        help="'reported' (the google_link_report accounts) or 'all-sessions'.",
    )
    parser.add_argument(
        "--confirm",
        required=True,
        help=(
            "Must be exactly the scope's token: "
            + ", ".join(f"{name}={token}" for name, (_, token) in _SCOPES.items())
            + "."
        ),
    )
    parser.add_argument(
        "--actor", required=True, help="Who is performing the change (audit)."
    )
    parser.add_argument(
        "--reason", required=True, help="Why the change is made (audit)."
    )
    return parser.parse_args(argv)


def _log_result(result: RemediationResult, *, actor: str, reason: str) -> None:
    """Log only the actor, reason, scope, ids, and counts."""
    logger.info(
        "security.google_link_remediation outcome=revoked actor=%s reason=%s "
        "scope=%s account_count=%d revoked_session_count=%d",
        actor,
        reason,
        result.scope.value,
        result.account_count,
        result.revoked_session_count,
    )
    if result.user_ids:
        logger.info(
            "security.google_link_remediation revoked_user_ids=%s",
            [str(uid) for uid in result.user_ids],
        )


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point: exit ``2`` when the confirmation token does not match."""
    args = _parse_args(argv)
    scope, token = _SCOPES[args.scope]
    if args.confirm != token:
        logger.error(
            "Refusing to proceed: --scope %s needs --confirm exactly '%s'",
            args.scope,
            token,
        )
        return 2
    with Session(engine) as session:
        result = GoogleLinkRemediationController.run(session, scope)
    _log_result(result, actor=args.actor, reason=args.reason)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
