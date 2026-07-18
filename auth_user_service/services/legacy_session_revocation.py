"""Global legacy-session revocation for cutover (4.1 step 5, ``MIG-LEGACY-01``).

Runs once, inside the write-quiescent maintenance window, between the Expand
and Enforce migrations (4.1): with old issuer writers already stopped, every
``ClientSession`` row still carrying a ``NULL`` ``auth_generation`` predates
the cutover. It is revoked by deletion -- never by backfilling a generation,
which could bless a stale role carried by an old canonical token (3.5.1, 4.2).
This is what allows ``ClientSession.auth_generation`` to become ``NOT NULL``
in Enforce.

Deletion alone is authoritative for the stateful validation path (a missing
row is treated as revoked). Hybrid/stateless access tokens that are still
wire-valid keep working only until their own natural expiry -- the documented
bounded window (3.6, 4.2) -- so no Redis blacklist push is attempted here;
that accelerator exists for per-user revocation of sessions a live consumer
may still have cached, which does not apply to a one-time offline sweep run
while writers are stopped.
"""

import logging
from dataclasses import dataclass

from sqlmodel import Session, col, delete

from auth_user_service.db_models.sessions import ClientSession

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GlobalLegacyRevocationResult:
    """Outcome of one global legacy-session revocation sweep (4.1 step 5)."""

    revoked_count: int


class GlobalLegacySessionRevocationController:
    """One-time, all-users revocation of every pre-Expand session (4.1 step 5)."""

    @staticmethod
    def revoke_legacy_sessions(session: Session) -> GlobalLegacyRevocationResult:
        """Delete every ``ClientSession`` row with no authorization generation.

        Scoped to ``auth_generation IS NULL`` rather than an unconditional
        table wipe so the sweep is idempotent and safely repeatable: a row
        already carrying a real generation (for example one just deleted and
        recreated by the audited repair command, 4.1) was never a legacy
        session and is left untouched. Commits on success and returns the
        number of rows removed; logs only the count, never an id, JTI, or
        session payload.
        """
        stmt = delete(ClientSession).where(col(ClientSession.auth_generation).is_(None))
        result = session.exec(stmt)
        revoked_count = result.rowcount or 0
        session.commit()
        logger.info(
            "security.global_legacy_revocation outcome=revoked revoked_count=%d",
            revoked_count,
        )
        return GlobalLegacyRevocationResult(revoked_count=revoked_count)
