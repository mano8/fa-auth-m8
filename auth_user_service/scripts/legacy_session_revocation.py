#!/usr/bin/env python
"""Audited operator command: global legacy-session revocation (4.1 step 5).

Runs once, inside the write-quiescent maintenance window, **after** the
Expand migration and the preflight/repair pass and **before** the Enforce
migration (4.1): deletes every ``ClientSession`` row that still carries no
``auth_generation`` (every pre-existing access and refresh session), never
backfilling a generation onto them. This is a one-time, all-users, forced
global logout -- users must sign in again after cutover (4.2) -- and it is
what allows ``ClientSession.auth_generation`` to become ``NOT NULL`` in
Enforce. Idempotent: repeating the sweep finds zero remaining legacy rows.

Because this is a destructive, all-users action, it requires an explicit
``--confirm REVOKE-ALL-LEGACY-SESSIONS`` acknowledgement in addition to the
usual ``--actor``/``--reason`` audit fields.

Run::

    python -m auth_user_service.scripts.legacy_session_revocation \\
        --confirm REVOKE-ALL-LEGACY-SESSIONS --actor <who> --reason <why>
"""

from __future__ import annotations

import argparse
import logging
from typing import List, Optional

from sqlmodel import Session

from auth_user_service.core.engine_sync import engine
from auth_user_service.services.legacy_session_revocation import (
    GlobalLegacyRevocationResult,
    GlobalLegacySessionRevocationController,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_CONFIRMATION_TOKEN = "REVOKE-ALL-LEGACY-SESSIONS"  # nosec B105


def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="legacy_session_revocation",
        description=(
            "Revoke every pre-existing access and refresh session at cutover "
            "(audited, 4.1 step 5)."
        ),
    )
    parser.add_argument(
        "--confirm",
        required=True,
        help=f"Must be exactly '{_CONFIRMATION_TOKEN}' to proceed.",
    )
    parser.add_argument(
        "--actor", required=True, help="Who is performing the change (audit)."
    )
    parser.add_argument(
        "--reason", required=True, help="Why the change is made (audit)."
    )
    return parser.parse_args(argv)


def _log_result(
    result: GlobalLegacyRevocationResult, *, actor: str, reason: str
) -> None:
    """Log only the actor, reason, and a count -- never an id or session payload."""
    logger.info(
        "security.global_legacy_revocation cli_outcome=revoked actor=%s reason=%s "
        "revoked_count=%d",
        actor,
        reason,
        result.revoked_count,
    )


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point: exit ``2`` when the confirmation token does not match."""
    args = _parse_args(argv)
    if args.confirm != _CONFIRMATION_TOKEN:
        logger.error(
            "Refusing to proceed: --confirm must be exactly '%s'", _CONFIRMATION_TOKEN
        )
        return 2
    with Session(engine) as session:
        result = GlobalLegacySessionRevocationController.revoke_legacy_sessions(session)
    _log_result(result, actor=args.actor, reason=args.reason)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
