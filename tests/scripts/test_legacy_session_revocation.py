"""Tests for the global legacy-session revocation CLI (4.1 step 5).

Business logic is covered by
``tests/services/test_legacy_session_revocation.py``; these tests cover
argument parsing, the confirmation-token guard, wiring, and exit codes.
"""

from unittest.mock import MagicMock, patch

from auth_user_service.scripts import legacy_session_revocation as cli
from auth_user_service.services.legacy_session_revocation import (
    GlobalLegacyRevocationResult,
)


class TestMain:
    def test_wrong_confirmation_token_returns_2_without_touching_the_db(self):
        with patch.object(cli, "Session") as session_cls:
            rc = cli.main(["--confirm", "yes", "--actor", "ops", "--reason", "cutover"])
        assert rc == 2
        session_cls.assert_not_called()

    def test_success_returns_0(self):
        with (
            patch.object(cli, "Session", return_value=MagicMock()),
            patch.object(
                cli.GlobalLegacySessionRevocationController,
                "revoke_legacy_sessions",
                return_value=GlobalLegacyRevocationResult(revoked_count=42),
            ) as revoke,
        ):
            rc = cli.main(
                [
                    "--confirm",
                    "REVOKE-ALL-LEGACY-SESSIONS",
                    "--actor",
                    "ops",
                    "--reason",
                    "cutover",
                ]
            )
        assert rc == 0
        revoke.assert_called_once()


class TestLogResult:
    def test_logs_no_sensitive_fields(self, caplog):
        result = GlobalLegacyRevocationResult(revoked_count=7)
        with caplog.at_level("INFO", logger=cli.logger.name):
            cli._log_result(result, actor="ops", reason="cutover")
        combined = "\n".join(r.getMessage() for r in caplog.records).lower()
        for forbidden in ("@", "email", "jwt", "token", "password", "jti"):
            assert forbidden not in combined
        assert "revoked" in combined
        assert "7" in combined
