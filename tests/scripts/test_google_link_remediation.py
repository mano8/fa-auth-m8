"""Tests for the audited implicit-Google-link remediation CLI (S1A).

The CLI is a thin wrapper: it checks the scope's confirmation token, opens a
session, delegates to ``GoogleLinkRemediationController.run``, and logs the
actor, reason, scope, ids, and counts. The revocation itself is covered by
``tests/services/test_google_link_remediation.py``.
"""

import uuid
from unittest.mock import MagicMock, patch

import pytest

from auth_user_service.scripts import google_link_remediation as cli
from auth_user_service.services.google_link_remediation import (
    RemediationResult,
    RemediationScope,
)

_AUDIT = ["--actor", "ops", "--reason", "S1 rollout"]


def _run(argv: list[str], result: RemediationResult | None = None):
    result = result or RemediationResult(
        scope=RemediationScope.REPORTED, user_ids=(), revoked_session_count=0
    )
    with (
        patch.object(cli, "Session", return_value=MagicMock()),
        patch.object(
            cli.GoogleLinkRemediationController, "run", return_value=result
        ) as run,
    ):
        return cli.main(argv), run


@pytest.mark.parametrize(
    "scope,token,expected",
    [
        (None, "REVOKE-GOOGLE-LINKED-SESSIONS", RemediationScope.REPORTED),
        ("reported", "REVOKE-GOOGLE-LINKED-SESSIONS", RemediationScope.REPORTED),
        ("all-sessions", "REVOKE-ALL-SESSIONS", RemediationScope.ALL_SESSIONS),
    ],
)
def test_matching_token_runs_the_scope(scope, token, expected) -> None:
    argv = (["--scope", scope] if scope else []) + ["--confirm", token, *_AUDIT]

    code, run = _run(argv)

    assert code == 0
    assert run.call_args.args[1] is expected


@pytest.mark.parametrize(
    "scope,token",
    [
        ("reported", "REVOKE-ALL-SESSIONS"),
        ("all-sessions", "REVOKE-GOOGLE-LINKED-SESSIONS"),
        ("reported", "yes"),
    ],
)
def test_wrong_token_refuses_without_touching_the_database(scope, token) -> None:
    code, run = _run(["--scope", scope, "--confirm", token, *_AUDIT])

    assert code == 2
    run.assert_not_called()


def test_log_carries_audit_fields_ids_and_counts(caplog) -> None:
    uid = uuid.uuid4()
    result = RemediationResult(
        scope=RemediationScope.REPORTED, user_ids=(uid,), revoked_session_count=3
    )

    with caplog.at_level("INFO", logger=cli.logger.name):
        _run(["--confirm", "REVOKE-GOOGLE-LINKED-SESSIONS", *_AUDIT], result)

    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "actor=ops reason=S1 rollout scope=reported" in logged
    assert "account_count=1 revoked_session_count=3" in logged
    assert str(uid) in logged


def test_empty_run_logs_no_id_list(caplog) -> None:
    with caplog.at_level("INFO", logger=cli.logger.name):
        _run(["--confirm", "REVOKE-GOOGLE-LINKED-SESSIONS", *_AUDIT])

    assert not any("revoked_user_ids" in r.getMessage() for r in caplog.records)
