#!/usr/bin/env python
"""Audited operator command: bind introspection audiences to an existing API key.

Keys created before audiences existed carry none, so remote introspection answers
``active: false`` for them (issuer-local only — the §3.12 fail-closed cutover that
stops any legacy key silently becoming a cross-service credential). This audited
command binds audiences to such a key so an approved consumer may introspect it —
**audiences only** (``access_mode`` is immutable and existing keys are
``READ_ONLY``).

The audience set is immutable after issuance, so this command:

* binds when the key currently carries **no** audience,
* is an **idempotent no-op** when the identical set is already bound, and
* **refuses** to change a different non-empty set (issue a replacement key).

Each audience must be an enabled consumer explicitly granted the
``api-key-introspection`` scope, and at most ``API_KEY_MAX_AUDIENCES`` may be
bound. A structured audit line (actor, reason, key ref, audiences, outcome) is
emitted; the key material is never read or printed.

Run::

    python -m auth_user_service.scripts.bind_api_key_audiences \
        --key-id <uuid> --actor <who> --reason <why> \
        --audience prompt-engine-m8 --audience media-worker-m8
"""

from __future__ import annotations

import argparse
import logging
import uuid
from typing import List, Optional

from sqlmodel import Session

from auth_user_service.core.engine_sync import engine
from auth_user_service.db_models.api_keys import ApiKey
from auth_user_service.services.api_keys import ApiKeyAudienceError, ApiKeyService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bind_api_key_audiences",
        description="Bind introspection audiences to an existing API key (audited).",
    )
    parser.add_argument("--key-id", required=True, help="Target API key id (UUID).")
    parser.add_argument(
        "--actor", required=True, help="Who is performing the change (audit)."
    )
    parser.add_argument(
        "--reason", required=True, help="Why the change is made (audit)."
    )
    parser.add_argument(
        "--audience",
        action="append",
        dest="audiences",
        default=[],
        metavar="CONSUMER_ID",
        help="A registered consumer id to bind (repeatable).",
    )
    return parser.parse_args(argv)


def bind_audiences(
    session: Session,
    key_id: uuid.UUID,
    audiences: List[str],
    *,
    actor: str,
    reason: str,
) -> List[str]:
    """Bind *audiences* to the key *key_id*, committing on success.

    Returns the normalized bound set. Raises ``KeyError`` when the key does not
    exist and ``ApiKeyAudienceError`` on invalid/immutable audiences; the audit
    line records the outcome either way. Never logs the key material.
    """
    api_key = session.get(ApiKey, key_id)
    if api_key is None:
        logger.warning(
            "apikey.audience_bind outcome=not_found actor=%s reason=%s ref=%s",
            actor,
            reason,
            key_id,
        )
        raise KeyError(f"API key {key_id} not found")
    try:
        bound = ApiKeyService.bind_existing_key_audiences(session, api_key, audiences)
    except ApiKeyAudienceError as exc:
        session.rollback()
        logger.warning(
            "apikey.audience_bind outcome=rejected actor=%s reason=%s ref=%s error=%s",
            actor,
            reason,
            key_id,
            exc,
        )
        raise
    session.commit()
    logger.info(
        "apikey.audience_bind outcome=ok actor=%s reason=%s ref=%s audiences=%s",
        actor,
        reason,
        key_id,
        ",".join(bound),
    )
    return bound


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point: exit non-zero on any failure."""
    args = _parse_args(argv)
    try:
        key_id = uuid.UUID(args.key_id)
    except ValueError:
        logger.error("Invalid --key-id: not a UUID")
        return 2
    try:
        with Session(engine) as session:
            bind_audiences(
                session,
                key_id,
                args.audiences,
                actor=args.actor,
                reason=args.reason,
            )
    except (KeyError, ApiKeyAudienceError) as exc:
        logger.error("Audience binding failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
