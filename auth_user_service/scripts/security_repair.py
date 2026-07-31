#!/usr/bin/env python
"""Audited operator command: repair one role/flag-mismatched user (4.1).

Resolves exactly one mismatch the read-only preflight
(``python -m auth_user_service.scripts.security_preflight``) reported. The
operator supplies the intended role explicitly for the given user id -- this
command never auto-promotes/demotes and never guesses. On a real change it
propagates exactly like the runtime role-change transaction (generation bump,
session revocation, durable outbox effects, 3.5.1-3.5.2); API-key
authorization needs no separate revocation step (3.11). Idempotent: repeating
the same repair is a no-op. Reads and writes raw columns only, never a
``User`` ORM entity, so the inconsistent row this command exists to fix is
never rejected by the model layer.

Run::

    python -m auth_user_service.scripts.security_repair \\
        --user-id <uuid> --intended-role superadmin --actor <who> --reason <why>
"""

from __future__ import annotations

import argparse
import logging
import uuid
from typing import List, Optional

from sqlmodel import Session

from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.core.engine_sync import engine
from auth_user_service.services.security_preflight import (
    NotMismatchedError,
    RepairResult,
    SecurityRepairController,
    UserNotFoundError,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="security_repair",
        description="Repair one role/flag-mismatched user row (audited, 4.1).",
    )
    parser.add_argument("--user-id", required=True, help="Target user id (UUID).")
    parser.add_argument(
        "--intended-role",
        required=True,
        choices=[role.value for role in RoleType],
        help="The role the operator has explicitly chosen for this user.",
    )
    parser.add_argument(
        "--actor", required=True, help="Who is performing the change (audit)."
    )
    parser.add_argument(
        "--reason", required=True, help="Why the change is made (audit)."
    )
    return parser.parse_args(argv)


def _log_result(result: RepairResult) -> None:
    """Log only ids, roles, and counters -- never email, token, or session data."""
    logger.info(
        "security.repair cli_outcome=%s user_id=%s previous_role=%s "
        "intended_role=%s auth_generation=%d revocation_enqueued=%s",
        "already_repaired" if result.already_repaired else "repaired",
        result.user_id,
        result.previous_role,
        result.intended_role,
        result.auth_generation,
        result.revocation_enqueued,
    )


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point: exit ``2`` on bad input, ``1`` on a domain failure."""
    args = _parse_args(argv)
    try:
        user_id = uuid.UUID(args.user_id)
    except ValueError:
        logger.error("Invalid --user-id: not a UUID")
        return 2
    intended_role = RoleType(args.intended_role)
    try:
        with Session(engine) as session:
            result = SecurityRepairController.repair_user(
                session,
                user_id=user_id,
                intended_role=intended_role,
                actor=args.actor,
                reason=args.reason,
            )
    except (UserNotFoundError, NotMismatchedError) as exc:
        logger.error("Repair failed: %s", exc)
        return 1
    _log_result(result)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
