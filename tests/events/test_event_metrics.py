"""Unit tests for auth_user_service.events.metrics."""

from prometheus_client import generate_latest

from auth_sdk_m8.observability.metrics import REGISTRY
from auth_user_service.events import metrics


class TestNormPrefix:
    def test_strips_and_normalises(self):
        assert metrics._norm_prefix("/user") == "user_"
        assert metrics._norm_prefix("/api/v1") == "api_v1_"
        assert metrics._norm_prefix("a-b") == "a_b_"

    def test_empty_prefix(self):
        assert metrics._norm_prefix("") == ""
        assert metrics._norm_prefix("/") == ""


class TestSetup:
    def test_disabled_returns_none(self):
        metrics.setup(False, "/user")
        assert metrics.get() is None

    def test_enabled_registers_collectors(self):
        metrics.setup(True, "/user")
        m = metrics.get()
        assert m is not None
        m.published_total.labels(event_type="session-revoked").inc()
        m.connections.inc()
        m.disconnects_total.labels(reason="client").inc()

        rendered = generate_latest(REGISTRY).decode()
        assert "user_auth_events_published_total" in rendered
        assert "user_auth_event_stream_connections" in rendered
        assert "user_auth_event_stream_disconnects_total" in rendered

    def test_idempotent_reregisters(self):
        metrics.setup(True, "/user")
        first = metrics.get()
        metrics.setup(True, "/user")
        second = metrics.get()
        assert first is not None and second is not None
        assert second is not first

    def test_enabled_then_disabled_unregisters(self):
        metrics.setup(True, "/user")
        metrics.setup(False, "/user")
        assert metrics.get() is None
        # The names are gone from the shared registry.
        rendered = generate_latest(REGISTRY).decode()
        assert "user_auth_events_published_total" not in rendered
