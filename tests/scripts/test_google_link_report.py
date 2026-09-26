"""Tests for the read-only implicit-Google-link report CLI (S1).

The CLI is a thin wrapper: it opens a session, delegates to
``GoogleLinkReportController.run``, logs only counts/ids, and maps
``report.clean`` to the exit code. Query logic is covered by
``tests/services/test_google_link_report.py``.
"""

import uuid
from unittest.mock import MagicMock, patch

from auth_user_service.scripts import google_link_report as cli
from auth_user_service.services.google_link_report import GoogleLinkReport


def _run(report: GoogleLinkReport) -> int:
    with (
        patch.object(cli, "Session", return_value=MagicMock()),
        patch.object(cli.GoogleLinkReportController, "run", return_value=report),
    ):
        return cli.main([])


def test_clean_report_returns_0():
    assert _run(GoogleLinkReport(user_ids=(), superadmin_ids=())) == 0


def test_affected_accounts_return_1():
    uid = uuid.uuid4()
    assert _run(GoogleLinkReport(user_ids=(uid,), superadmin_ids=())) == 1


def test_log_names_ids_and_superadmins(caplog):
    uid, admin = uuid.uuid4(), uuid.uuid4()
    report = GoogleLinkReport(user_ids=(uid, admin), superadmin_ids=(admin,))

    with caplog.at_level("INFO", logger=cli.logger.name):
        cli._log_report(report)

    messages = "\n".join(r.getMessage() for r in caplog.records)
    assert "affected_count=2 superadmin_count=1 clean=False" in messages
    assert str(uid) in messages
    assert f"superadmin_ids=['{admin}']" in messages


def test_clean_log_has_no_warnings(caplog):
    with caplog.at_level("INFO", logger=cli.logger.name):
        cli._log_report(GoogleLinkReport(user_ids=(), superadmin_ids=()))

    assert [r.levelname for r in caplog.records] == ["INFO"]
