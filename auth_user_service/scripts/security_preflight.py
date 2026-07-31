#!/usr/bin/env python
"""Read-only mismatch/last-superuser preflight CLI (4.1 ``MIG-PREFLIGHT-01``).

Run before the Expand migration's Enforce phase (and, per 4.4 step 1, as the
first step of the coordinated release) to report existing-row
``is_superuser``/``role`` mismatches and the active canonical-superuser count.
Read-only: it writes nothing and never auto-promotes/demotes. Only ids and
counts are reported -- never email, token, JTI, or session-payload data.

Run::

    python -m auth_user_service.scripts.security_preflight

Exit codes: ``0`` when no mismatch exists, ``1`` when any mismatch is found
(the operator must then run the audited repair command or reset disposable
development data before the Enforce migration may proceed, 4.1).
"""

from __future__ import annotations

import logging
from typing import List, Optional

from sqlmodel import Session

from auth_user_service.core.engine_sync import engine
from auth_user_service.services.security_preflight import (
    SecurityPreflightController,
    SecurityPreflightReport,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _log_report(report: SecurityPreflightReport) -> None:
    """Log only counts and ids -- never email, token, JTI, or session data."""
    logger.info(
        "security.preflight flagged_not_superadmin_count=%d "
        "superadmin_not_flagged_count=%d active_canonical_superuser_count=%d "
        "inconsistent_with_active_sessions_count=%d clean=%s",
        report.flagged_not_superadmin_count,
        report.superadmin_not_flagged_count,
        report.active_canonical_superuser_count,
        len(report.inconsistent_ids_with_active_sessions),
        report.clean,
    )
    if report.flagged_not_superadmin_ids:
        logger.warning(
            "security.preflight mismatch=flagged_not_superadmin ids=%s",
            [str(uid) for uid in report.flagged_not_superadmin_ids],
        )
    if report.superadmin_not_flagged_ids:
        logger.warning(
            "security.preflight mismatch=superadmin_not_flagged ids=%s",
            [str(uid) for uid in report.superadmin_not_flagged_ids],
        )
    if report.inconsistent_ids_with_active_sessions:
        logger.warning(
            "security.preflight mismatch_with_active_sessions ids=%s",
            [str(uid) for uid in report.inconsistent_ids_with_active_sessions],
        )
    if report.active_canonical_superuser_count == 0:
        logger.warning("security.preflight no_active_canonical_superuser=true")


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point: exit ``1`` when any mismatch is found."""
    del argv  # no arguments: the preflight is read-only and takes none
    with Session(engine) as session:
        report = SecurityPreflightController.run(session)
    _log_report(report)
    return 0 if report.clean else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
