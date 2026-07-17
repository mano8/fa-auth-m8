"""Event-emission tests for services.client_sessions.SessionController.

Verify that the revoke/delete operations push best-effort ``session-revoked``
events with the correct payload (and stay silent when no owner is known), using
a recording stand-in for the process-global hub.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

import auth_user_service.events.hub as hubmod
from auth_user_service.services.client_sessions import SessionController


class _RecordingHub:
    def __init__(self):
        self.events = []

    def publish(self, event_type, payload):
        self.events.append((event_type, payload))


@pytest.fixture
def recording_hub(monkeypatch):
    hub = _RecordingHub()
    monkeypatch.setattr(hubmod, "_hub", hub)
    return hub


def _future() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=1)


class TestRevokeSessionJtiEvents:
    def test_emits_when_user_id_supplied(self, recording_hub):
        SessionController.revoke_session_jti(
            "jti-1", _future(), MagicMock(), user_id="u1"
        )
        # auth-sdk-m8 >= 3.0.0 adds the additive ``auth_generation``/``event_id``
        # fields to the session-revoked event (defaulting to ``None`` until the
        # issuer populates them via the generation/outbox work). Version stays
        # ``v1`` for rolling compatibility.
        assert recording_hub.events == [
            (
                "session-revoked",
                {
                    "event_type": "session.revoked",
                    "version": "v1",
                    "user_id": "u1",
                    "jti": "jti-1",
                    "auth_generation": None,
                    "event_id": None,
                },
            )
        ]

    def test_silent_without_user_id(self, recording_hub):
        SessionController.revoke_session_jti("jti-1", _future(), MagicMock())
        assert recording_hub.events == []


class TestDeleteSessionByJtiEvents:
    def test_emits_when_user_id_supplied(self, recording_hub, db_session):
        SessionController.delete_session_by_jti(db_session, "jti-x", user_id="u2")
        assert len(recording_hub.events) == 1
        event_type, payload = recording_hub.events[0]
        assert event_type == "session-revoked"
        assert payload["user_id"] == "u2"
        assert payload["jti"] == "jti-x"

    def test_silent_without_user_id(self, recording_hub, db_session):
        SessionController.delete_session_by_jti(db_session, "jti-x")
        assert recording_hub.events == []


class TestRevokeAllUserSessionsEvents:
    def test_emits_all_sessions_event(self, recording_hub, db_session, sample_user):
        SessionController.revoke_all_user_sessions(db_session, sample_user.id, None)
        assert len(recording_hub.events) == 1
        event_type, payload = recording_hub.events[0]
        assert event_type == "session-revoked"
        assert payload["user_id"] == str(sample_user.id)
        # jti=None signals "all of this user's sessions".
        assert payload["jti"] is None

    def test_emits_even_with_active_sessions(
        self, recording_hub, db_session, sample_client_session, sample_user
    ):
        redis = MagicMock()
        SessionController.revoke_all_user_sessions(db_session, sample_user.id, redis)
        assert recording_hub.events[0][0] == "session-revoked"
        assert recording_hub.events[0][1]["jti"] is None
