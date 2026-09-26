#!/usr/bin/env python
"""Audited operator command: lift the Google identity block of a deleted account.

When an administrator deletes a GOOGLE account, its Google identity is blocked:
the same Google account cannot sign in again and get a new account (``D-j``).
This command lifts that block. It takes the **deleted account's id** (from the
deletion's privileged-action audit row), never the Google subject, which the
service does not store.

Idempotent: lifting a block that is not there is a no-op (exit ``0``, count
``0``). Logs the actor, the reason, the id, and the count only.

Run::

    python -m auth_user_service.scripts.google_identity_unblock \\
        --user-id <deleted-account-uuid> --actor <who> --reason <why>
"""

from __future__ import annotations

import argparse
import logging
import uuid
from typing import List, Optional

from sqlmodel import Session

from auth_user_service.core.engine_sync import engine
from auth_user_service.services.identity_blocks import IdentityBlockController

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="google_identity_unblock",
        description="Lift the Google identity block of a deleted account (audited).",
    )
    parser.add_argument(
        "--user-id", required=True, help="Id of the deleted account (UUID)."
    )
    parser.add_argument(
        "--actor", required=True, help="Who is performing the change (audit)."
    )
    parser.add_argument(
        "--reason", required=True, help="Why the change is made (audit)."
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point: exit ``2`` when ``--user-id`` is not a UUID."""
    args = _parse_args(argv)
    try:
        user_id = uuid.UUID(args.user_id)
    except ValueError:
        logger.error("Invalid --user-id: not a UUID")
        return 2
    with Session(engine) as session:
        lifted = IdentityBlockController.unblock_deleted_user(session, user_id)
    logger.info(
        "security.google_identity_unblock outcome=%s actor=%s reason=%s "
        "user_id=%s lifted_count=%d",
        "unblocked" if lifted else "not_blocked",
        args.actor,
        args.reason,
        user_id,
        lifted,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
