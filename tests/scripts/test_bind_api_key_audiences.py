"""Tests for the audited operator command binding audiences to existing keys.

The command is the only path that binds audiences to a key created before
audiences existed (§3.12). It is audited, idempotent, and refuses to change an
immutable already-bound set; it never reads or prints the key material.
"""

import uuid
from unittest.mock import MagicMock, patch

import pytest

from auth_user_service.db_models.api_keys import ApiKey
from auth_user_service.scripts import bind_api_key_audiences as cli
from auth_user_service.services.api_keys import ApiKeyAudienceError

_PERMITTED = frozenset({"prompt-engine-m8"})


def _patch_registry():
    return patch(
        "auth_user_service.core.consumer_registry.get_introspection_audiences",
        return_value=_PERMITTED,
    )


def _make_key(db_session, owner) -> ApiKey:
    api_key = ApiKey(
        id=uuid.uuid4(),
        key_hash=(uuid.uuid4().hex + uuid.uuid4().hex),
        user_id=owner.id,
        name="k",
    )
    db_session.add(api_key)
    db_session.commit()
    db_session.refresh(api_key)
    return api_key


class TestBindAudiences:
    def test_binds_and_commits(self, db_session, sample_user):
        api_key = _make_key(db_session, sample_user)
        with _patch_registry():
            bound = cli.bind_audiences(
                db_session,
                api_key.id,
                ["prompt-engine-m8"],
                actor="ops",
                reason="migrate legacy key",
            )
        db_session.refresh(api_key)
        assert bound == ["prompt-engine-m8"]
        assert [a.audience_id for a in api_key.audiences] == ["prompt-engine-m8"]

    def test_missing_key_raises_keyerror(self, db_session):
        with pytest.raises(KeyError):
            cli.bind_audiences(
                db_session, uuid.uuid4(), ["prompt-engine-m8"], actor="o", reason="r"
            )

    def test_invalid_audience_rejected_and_rolled_back(self, db_session, sample_user):
        api_key = _make_key(db_session, sample_user)
        with _patch_registry():
            with pytest.raises(ApiKeyAudienceError):
                cli.bind_audiences(
                    db_session,
                    api_key.id,
                    ["not-a-consumer"],
                    actor="o",
                    reason="r",
                )
        db_session.refresh(api_key)
        assert list(api_key.audiences) == []


class TestMain:
    def test_invalid_uuid_returns_2(self):
        assert (
            cli.main(["--key-id", "not-a-uuid", "--actor", "o", "--reason", "r"]) == 2
        )

    def test_success_returns_0(self):
        session_cm = MagicMock()
        with (
            patch.object(cli, "Session", return_value=session_cm),
            patch.object(cli, "bind_audiences", return_value=["prompt-engine-m8"]),
        ):
            rc = cli.main(
                [
                    "--key-id",
                    str(uuid.uuid4()),
                    "--actor",
                    "ops",
                    "--reason",
                    "why",
                    "--audience",
                    "prompt-engine-m8",
                ]
            )
        assert rc == 0

    def test_failure_returns_1(self):
        session_cm = MagicMock()
        with (
            patch.object(cli, "Session", return_value=session_cm),
            patch.object(cli, "bind_audiences", side_effect=KeyError("nope")),
        ):
            rc = cli.main(
                ["--key-id", str(uuid.uuid4()), "--actor", "o", "--reason", "r"]
            )
        assert rc == 1
