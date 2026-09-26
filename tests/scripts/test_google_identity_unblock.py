"""Tests for the audited Google identity unblock CLI (S1A, D-j).

The CLI validates the id, delegates to
``IdentityBlockController.unblock_deleted_user``, and logs the actor, reason,
id, and count only. The block itself is proven on the real deletion path in
``tests/security/test_google_identity_binding.py``.
"""

import uuid
from unittest.mock import MagicMock, patch

import pytest

from auth_user_service.scripts import google_identity_unblock as cli

_AUDIT = ["--actor", "ops", "--reason", "appeal granted"]


def _run(argv: list[str], lifted: int = 1):
    with (
        patch.object(cli, "Session", return_value=MagicMock()),
        patch.object(
            cli.IdentityBlockController, "unblock_deleted_user", return_value=lifted
        ) as unblock,
    ):
        return cli.main(argv), unblock


@pytest.mark.parametrize("lifted,outcome", [(1, "unblocked"), (0, "not_blocked")])
def test_unblock_is_audited_and_idempotent(caplog, lifted, outcome) -> None:
    user_id = uuid.uuid4()

    with caplog.at_level("INFO", logger=cli.logger.name):
        code, unblock = _run(["--user-id", str(user_id), *_AUDIT], lifted)

    assert code == 0
    assert unblock.call_args.args[1] == user_id
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert f"outcome={outcome} actor=ops reason=appeal granted" in logged
    assert f"user_id={user_id} lifted_count={lifted}" in logged


def test_invalid_user_id_exits_2() -> None:
    code, unblock = _run(["--user-id", "not-a-uuid", *_AUDIT])

    assert code == 2
    unblock.assert_not_called()
