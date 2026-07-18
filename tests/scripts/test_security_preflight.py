"""Tests for the read-only mismatch/last-superuser preflight CLI (4.1).

The CLI is a thin wrapper: it opens a session, delegates to
``SecurityPreflightController.run``, logs only counts/ids (never sensitive
data), and maps ``report.clean`` to the exit code the release sequence (4.4
step 1) gates on. Business logic is covered by
``tests/services/test_security_preflight.py``; these tests cover wiring, exit
codes, and the log-only-safe-fields contract.
"""

import uuid
from unittest.mock import MagicMock, patch

from auth_user_service.scripts import security_preflight as cli
from auth_user_service.services.security_preflight import SecurityPreflightReport


def _report(**overrides) -> SecurityPreflightReport:
    base = dict(
        flagged_not_superadmin_ids=(),
        superadmin_not_flagged_ids=(),
        active_canonical_superuser_count=1,
        inconsistent_ids_with_active_sessions=(),
    )
    base.update(overrides)
    return SecurityPreflightReport(**base)


class TestMain:
    def test_clean_report_returns_0(self):
        with (
            patch.object(cli, "Session", return_value=MagicMock()),
            patch.object(
                cli.SecurityPreflightController, "run", return_value=_report()
            ),
        ):
            assert cli.main([]) == 0

    def test_flagged_mismatch_returns_1(self):
        report = _report(flagged_not_superadmin_ids=(uuid.uuid4(),))
        with (
            patch.object(cli, "Session", return_value=MagicMock()),
            patch.object(cli.SecurityPreflightController, "run", return_value=report),
        ):
            assert cli.main([]) == 1

    def test_superadmin_not_flagged_mismatch_returns_1(self):
        report = _report(superadmin_not_flagged_ids=(uuid.uuid4(),))
        with (
            patch.object(cli, "Session", return_value=MagicMock()),
            patch.object(cli.SecurityPreflightController, "run", return_value=report),
        ):
            assert cli.main([]) == 1

    def test_no_active_superuser_alone_still_returns_0(self):
        # Surfaced as a warning so the operator notices before Enforce, but it
        # is not itself a mismatch the migration must abort for.
        report = _report(active_canonical_superuser_count=0)
        with (
            patch.object(cli, "Session", return_value=MagicMock()),
            patch.object(cli.SecurityPreflightController, "run", return_value=report),
        ):
            assert cli.main([]) == 0


class TestLogReport:
    def test_logs_warnings_for_every_mismatch_kind(self, caplog):
        report = _report(
            flagged_not_superadmin_ids=(uuid.uuid4(),),
            superadmin_not_flagged_ids=(uuid.uuid4(),),
            inconsistent_ids_with_active_sessions=(uuid.uuid4(),),
            active_canonical_superuser_count=0,
        )
        with caplog.at_level("WARNING", logger=cli.logger.name):
            cli._log_report(report)
        messages = "\n".join(r.getMessage() for r in caplog.records)
        assert "mismatch=flagged_not_superadmin" in messages
        assert "mismatch=superadmin_not_flagged" in messages
        assert "mismatch_with_active_sessions" in messages
        assert "no_active_canonical_superuser=true" in messages

    def test_no_warnings_when_clean(self, caplog):
        with caplog.at_level("WARNING", logger=cli.logger.name):
            cli._log_report(_report())
        assert not any(r.levelname == "WARNING" for r in caplog.records)

    def test_no_sensitive_fields_in_log_output(self, caplog):
        report = _report(
            flagged_not_superadmin_ids=(uuid.uuid4(),),
            superadmin_not_flagged_ids=(uuid.uuid4(),),
            inconsistent_ids_with_active_sessions=(uuid.uuid4(),),
        )
        with caplog.at_level("INFO", logger=cli.logger.name):
            cli._log_report(report)
        combined = "\n".join(r.getMessage() for r in caplog.records).lower()
        for forbidden in ("@", "email", "jwt", "token", "password", "jti"):
            assert forbidden not in combined
