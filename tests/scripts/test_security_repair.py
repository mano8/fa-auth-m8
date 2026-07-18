"""Tests for the audited role/flag-mismatch repair CLI (4.1).

Business logic is covered by ``tests/services/test_security_repair.py``; these
tests cover argument parsing, wiring, and exit codes.
"""

import uuid
from unittest.mock import MagicMock, patch

import pytest

from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.scripts import security_repair as cli
from auth_user_service.services.security_preflight import (
    NotMismatchedError,
    RepairResult,
    UserNotFoundError,
)


def _result(**overrides) -> RepairResult:
    base = dict(
        user_id=uuid.uuid4(),
        previous_role=RoleType.USER,
        previous_is_superuser=True,
        intended_role=RoleType.USER,
        auth_generation=2,
        revocation_enqueued=True,
        already_repaired=False,
    )
    base.update(overrides)
    return RepairResult(**base)


class TestParseArgs:
    def test_invalid_intended_role_is_rejected_before_main_runs(self):
        # argparse `choices` raises SystemExit(2) directly for an invalid role.
        with pytest.raises(SystemExit):
            cli._parse_args(
                [
                    "--user-id",
                    str(uuid.uuid4()),
                    "--intended-role",
                    "not-a-role",
                    "--actor",
                    "o",
                    "--reason",
                    "r",
                ]
            )


class TestMain:
    def test_invalid_uuid_returns_2(self):
        assert (
            cli.main(
                [
                    "--user-id",
                    "not-a-uuid",
                    "--intended-role",
                    "user",
                    "--actor",
                    "o",
                    "--reason",
                    "r",
                ]
            )
            == 2
        )

    def test_success_returns_0(self):
        with (
            patch.object(cli, "Session", return_value=MagicMock()),
            patch.object(
                cli.SecurityRepairController,
                "repair_user",
                return_value=_result(),
            ),
        ):
            rc = cli.main(
                [
                    "--user-id",
                    str(uuid.uuid4()),
                    "--intended-role",
                    "user",
                    "--actor",
                    "ops",
                    "--reason",
                    "why",
                ]
            )
        assert rc == 0

    def test_not_found_returns_1(self):
        with (
            patch.object(cli, "Session", return_value=MagicMock()),
            patch.object(
                cli.SecurityRepairController,
                "repair_user",
                side_effect=UserNotFoundError("nope"),
            ),
        ):
            rc = cli.main(
                [
                    "--user-id",
                    str(uuid.uuid4()),
                    "--intended-role",
                    "user",
                    "--actor",
                    "o",
                    "--reason",
                    "r",
                ]
            )
        assert rc == 1

    def test_not_mismatched_returns_1(self):
        with (
            patch.object(cli, "Session", return_value=MagicMock()),
            patch.object(
                cli.SecurityRepairController,
                "repair_user",
                side_effect=NotMismatchedError("already consistent"),
            ),
        ):
            rc = cli.main(
                [
                    "--user-id",
                    str(uuid.uuid4()),
                    "--intended-role",
                    "user",
                    "--actor",
                    "o",
                    "--reason",
                    "r",
                ]
            )
        assert rc == 1


class TestLogResult:
    def test_logs_no_sensitive_fields(self, caplog):
        result = _result()
        with caplog.at_level("INFO", logger=cli.logger.name):
            cli._log_result(result)
        combined = "\n".join(r.getMessage() for r in caplog.records).lower()
        for forbidden in ("@", "email", "jwt", "token", "password", "jti"):
            assert forbidden not in combined
        assert "repaired" in combined
