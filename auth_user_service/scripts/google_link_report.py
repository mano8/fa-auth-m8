#!/usr/bin/env python
"""Read-only report of accounts that relied on the implicit Google email link (S1).

Lists the PASSWORD accounts whose session shows a Google sign-in: the users who
signed in with Google through the email match that S1 removed, and who must now
use their password. Read-only: it writes nothing. Only ids and counts are
reported -- never email, Google subject, token, JTI, or session-payload data.
The list is a lower bound (see
:mod:`auth_user_service.services.google_link_report`).

Run::

    python -m auth_user_service.scripts.google_link_report

Exit codes: ``0`` when no account is affected, ``1`` when at least one is (the
operator should follow the "Google sign-in refused for a password account"
runbook entry in the README).
"""

from __future__ import annotations

import logging
from typing import List, Optional

from sqlmodel import Session

from auth_user_service.core.engine_sync import engine
from auth_user_service.services.google_link_report import (
    GoogleLinkReport,
    GoogleLinkReportController,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _log_report(report: GoogleLinkReport) -> None:
    """Log only counts and ids -- never email, subject, token, or session data."""
    logger.info(
        "google_link.report affected_count=%d superadmin_count=%d clean=%s",
        report.count,
        len(report.superadmin_ids),
        report.clean,
    )
    if report.user_ids:
        logger.warning(
            "google_link.report password_accounts_with_google_sessions ids=%s",
            [str(uid) for uid in report.user_ids],
        )
    if report.superadmin_ids:
        logger.warning(
            "google_link.report superadmin_ids=%s",
            [str(uid) for uid in report.superadmin_ids],
        )


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point: exit ``1`` when any account is affected."""
    del argv  # no arguments: the report is read-only and takes none
    with Session(engine) as session:
        report = GoogleLinkReportController.run(session)
    _log_report(report)
    return 0 if report.clean else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
