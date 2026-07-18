"""Unit tests for auth_user_service.services.outbox_metrics."""

from prometheus_client import generate_latest

from auth_sdk_m8.observability.metrics import REGISTRY
from auth_user_service.db_models.outbox import EFFECT_BLACKLIST, EFFECT_PUBLISH
from auth_user_service.services import outbox_metrics


class TestNormPrefix:
    def test_strips_and_normalises(self):
        assert outbox_metrics._norm_prefix("/user") == "user_"
        assert outbox_metrics._norm_prefix("a-b") == "a_b_"

    def test_empty_prefix(self):
        assert outbox_metrics._norm_prefix("") == ""
        assert outbox_metrics._norm_prefix("/") == ""


class TestSetup:
    def test_disabled_returns_none(self):
        outbox_metrics.setup(False, "/user")
        assert outbox_metrics.get() is None

    def test_enabled_registers_collectors(self):
        outbox_metrics.setup(True, "/user")
        m = outbox_metrics.get()
        assert m is not None
        rendered = generate_latest(REGISTRY).decode()
        assert "user_revocation_outbox_enqueued_total" in rendered
        assert "user_revocation_outbox_completed_total" in rendered
        assert "user_revocation_outbox_retried_total" in rendered
        assert "user_revocation_outbox_dead_total" in rendered
        assert "user_revocation_outbox_propagation_seconds" in rendered
        outbox_metrics.setup(False, "/user")

    def test_idempotent_reregisters(self):
        outbox_metrics.setup(True, "/user")
        first = outbox_metrics.get()
        outbox_metrics.setup(True, "/user")
        second = outbox_metrics.get()
        assert first is not None and second is not None
        assert second is not first
        outbox_metrics.setup(False, "/user")

    def test_enabled_then_disabled_unregisters(self):
        outbox_metrics.setup(True, "/user")
        outbox_metrics.setup(False, "/user")
        assert outbox_metrics.get() is None
        rendered = generate_latest(REGISTRY).decode()
        assert "user_revocation_outbox_enqueued_total" not in rendered


class TestEmitHelpersDisabled:
    def test_helpers_noop_when_disabled(self):
        outbox_metrics.setup(False, "/user")
        # None container → every helper is a safe no-op.
        outbox_metrics.record_enqueued(EFFECT_BLACKLIST, 2)
        outbox_metrics.record_completed(EFFECT_PUBLISH, 1.0)
        outbox_metrics.record_retried(EFFECT_BLACKLIST)
        outbox_metrics.record_dead(EFFECT_BLACKLIST)
        assert outbox_metrics.get() is None


class TestEmitHelpersEnabled:
    def test_helpers_increment_and_observe(self):
        outbox_metrics.setup(True, "/user")
        try:
            outbox_metrics.record_enqueued(EFFECT_BLACKLIST, 3)
            outbox_metrics.record_enqueued(EFFECT_PUBLISH, 0)  # zero → skipped
            outbox_metrics.record_completed(EFFECT_PUBLISH, 0.5)
            outbox_metrics.record_completed(EFFECT_BLACKLIST, None)  # no observe
            outbox_metrics.record_completed(EFFECT_BLACKLIST, -1.0)  # negative skip
            outbox_metrics.record_retried(EFFECT_BLACKLIST)
            outbox_metrics.record_dead(EFFECT_BLACKLIST)

            m = outbox_metrics.get()
            assert (
                m.enqueued_total.labels(effect_type=EFFECT_BLACKLIST)._value.get() == 3
            )
            assert (
                m.completed_total.labels(effect_type=EFFECT_PUBLISH)._value.get() == 1
            )
            assert (
                m.retried_total.labels(effect_type=EFFECT_BLACKLIST)._value.get() == 1
            )
            assert m.dead_total.labels(effect_type=EFFECT_BLACKLIST)._value.get() == 1
        finally:
            outbox_metrics.setup(False, "/user")
