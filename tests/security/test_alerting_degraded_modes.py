"""11.12 — Alerting for degraded security modes.

Codifies the alerting/logging invariants for every degraded-security control
in fa-auth-m8 so they cannot silently regress:

- The ``auth_degradation_mode_active`` gauge is initialised at startup for all
  four controls (rate_limit / refresh_validation / session_write /
  access_revocation) with the actual effective mode from settings.
- Every degraded-decision path emits a ``degraded_decision_total`` metric
  sample labelled with the control, effective mode, and reason.
- Degraded-mode log lines never contain raw API keys, JWTs, refresh tokens,
  or internal service tokens — only opaque reference IDs.
- Redis-unavailability startup log contains the TOKEN_MODE but no secrets.
- Revocation fail-open decisions are logged explicitly with the mode label so
  they are observable in production log aggregation.
- API-key strict-rate-limit denial log lines are structured and do not leak
  the raw key value.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from auth_user_service.core.deps import (
    _handle_api_key_redis_degraded,
    _check_jti_revocation,
)
from auth_user_service.core.config import Settings

# ── shared Settings construction ──────────────────────────────────────────────

_VALID_SETTINGS: dict = {
    "DOMAIN": "localhost",
    "ENVIRONMENT": "local",
    "API_PREFIX": "/user",
    "PROJECT_NAME": "TestApp",
    "STACK_NAME": "test-stack",
    "BACKEND_HOST": "http://localhost:9000",
    "FRONTEND_HOST": "http://localhost:5173",
    "BACKEND_CORS_ORIGINS": "http://localhost",
    "ACCESS_TOKEN_ALGORITHM": "HS256",
    "ACCESS_SECRET_KEY": "Aa1-test-access-secret-key-32chars!!",
    "REFRESH_SECRET_KEY": "Aa1-test-refresh-secret-key-32chars!",
    "DB_HOST": "localhost",
    "DB_PORT": 3306,
    "DB_DATABASE": "test_db",
    "DB_USER": "test_user",
    "DB_PASSWORD": "TestPass1@#!",
    "REDIS_HOST": "localhost",
    "REDIS_PORT": 6379,
    "REDIS_USER": "testuser",
    "REDIS_PASSWORD": "TestRedis1@#!",
    "FIRST_SUPERUSER": "admin@example.com",
    "FIRST_SUPERUSER_PASSWORD": "TestAdmin1@#!",
    "PRIVATE_API_SECRET": "Aa1-test-private-api-secret-32chars!!",
    "SESSION_SECRET": "Aa1-test-session-secret-32chars-here!",
    "TOKENS_ENCRYPTION_KEY": "Aa1-test-encryption-key-32chars-here!",
    "EVENT_SIGNING_KEY": "Aa1-test-event-signing-key-32chars!!",
    "TOKEN_STRICT_VALIDATION": False,
}

_CONTROLS = ("refresh_validation", "session_write", "rate_limit", "access_revocation")


def _make(**overrides) -> Settings:
    return Settings(_env_file=None, **{**_VALID_SETTINGS, **overrides})


# ── 11.12a: degradation_mode_active gauge initialised at startup ──────────────


class TestDegradationGaugeInitialisation:
    """_init_degradation_gauges sets the gauge for all four controls at startup."""

    def test_all_four_controls_get_gauge_set(self):
        """Startup initialises degradation_mode_active for every control."""
        from auth_user_service.main import _init_degradation_gauges

        mock_m = MagicMock()
        mock_m.degradation_mode_active = MagicMock()

        with (
            patch("auth_user_service.main._metrics.get", return_value=mock_m),
            patch("auth_user_service.main.settings", _make()),
        ):
            _init_degradation_gauges()

        label_calls = mock_m.degradation_mode_active.labels.call_args_list
        # All four controls must receive a gauge set.
        for control in _CONTROLS:
            assert any(
                (
                    c.kwargs.get("control") == control
                    or (c.args and c.args[0] == control)
                )
                for c in label_calls
            ), f"degradation_mode_active not initialised for control={control}"

    def test_strict_mode_gauge_reports_fail_closed_for_all(self):
        """Under AUTH_STRICT_MODE, every control's gauge is set to fail_closed."""
        from auth_user_service.main import _init_degradation_gauges

        strict_settings = _make(
            AUTH_STRICT_MODE=True,
            PRIVATE_API_CONSUMERS={
                "test-svc": {"secret": "plain-test-secret", "scopes": ["introspection"]}
            },
            RATE_LIMIT_FAILURE_MODE="fail_open",
            ACCESS_REVOCATION_FAILURE_MODE="fail_open",
        )
        mock_m = MagicMock()
        mock_m.degradation_mode_active = MagicMock()

        with (
            patch("auth_user_service.main._metrics.get", return_value=mock_m),
            patch("auth_user_service.main.settings", strict_settings),
        ):
            _init_degradation_gauges()

        # Every mode arg passed to labels() must be fail_closed.
        for c in mock_m.degradation_mode_active.labels.call_args_list:
            mode = c.kwargs.get("mode") or (c.args[1] if len(c.args) > 1 else None)
            assert mode == "fail_closed", (
                f"Strict mode gauge should be fail_closed, got {mode!r}"
            )

    def test_no_gauge_call_when_metrics_disabled(self):
        """When metrics are off (_metrics.get returns None), no gauge is set."""
        from auth_user_service.main import _init_degradation_gauges

        with patch("auth_user_service.main._metrics.get", return_value=None):
            # Must not raise.
            _init_degradation_gauges()


# ── 11.12b: API-key strict denial logging ─────────────────────────────────────


class TestApiKeyDenialLogging:
    """API-key strict-rate-limit denial logs are structured and secret-free."""

    def _make_api_key(self, *, key_id: str = "00000000-0000-0000-0000-000000000001"):
        api_key = MagicMock()
        api_key.id = key_id
        return api_key

    def test_strict_denial_logs_decision_deny(self, caplog):
        """Strict mode denial emits a warning with decision=deny."""
        api_key = self._make_api_key()
        strict_settings = _make(
            AUTH_STRICT_MODE=True,
            PRIVATE_API_CONSUMERS={
                "test-svc": {"secret": "plain-test-secret", "scopes": ["introspection"]}
            },
        )
        with (
            patch("auth_user_service.core.deps.settings", strict_settings),
            patch("auth_user_service.core.deps._get_metrics", return_value=None),
            caplog.at_level(logging.WARNING, logger="auth_user_service.core.deps"),
        ):
            from fastapi import HTTPException

            with pytest.raises(HTTPException):
                _handle_api_key_redis_degraded(api_key)

        assert "decision=deny" in caplog.text
        assert "mode=fail_closed" in caplog.text

    def test_fail_open_logs_decision_allow_unsafe(self, caplog):
        """Non-strict fail-open path logs decision=allow and unsafe=true."""
        api_key = self._make_api_key()
        open_settings = _make(AUTH_STRICT_MODE=False)
        with (
            patch("auth_user_service.core.deps.settings", open_settings),
            patch("auth_user_service.core.deps._get_metrics", return_value=None),
            caplog.at_level(logging.WARNING, logger="auth_user_service.core.deps"),
        ):
            _handle_api_key_redis_degraded(api_key)  # no raise in fail-open

        assert "decision=allow" in caplog.text
        assert "unsafe=true" in caplog.text

    def test_denial_log_never_contains_raw_api_key(self, caplog):
        """The raw API-key string is never written to the log in strict mode."""
        api_key = self._make_api_key()
        raw_key_value = "ak_super_secret_raw_key_12345_unique"
        # Attach the raw key to the mock so a buggy implementation could log it.
        api_key.key = raw_key_value
        strict_settings = _make(
            AUTH_STRICT_MODE=True,
            PRIVATE_API_CONSUMERS={
                "test-svc": {"secret": "plain-test-secret", "scopes": ["introspection"]}
            },
        )
        with (
            patch("auth_user_service.core.deps.settings", strict_settings),
            patch("auth_user_service.core.deps._get_metrics", return_value=None),
            caplog.at_level(logging.DEBUG, logger="auth_user_service.core.deps"),
        ):
            from fastapi import HTTPException

            with pytest.raises(HTTPException):
                _handle_api_key_redis_degraded(api_key)

        assert raw_key_value not in caplog.text, (
            "Raw API key value leaked into log output"
        )

    def test_denial_log_never_contains_raw_api_key_fail_open(self, caplog):
        """The raw API-key string is never written to the log in fail-open mode."""
        api_key = self._make_api_key()
        raw_key_value = "ak_fail_open_raw_key_abc_12345_unique"
        api_key.key = raw_key_value
        open_settings = _make(AUTH_STRICT_MODE=False)
        with (
            patch("auth_user_service.core.deps.settings", open_settings),
            patch("auth_user_service.core.deps._get_metrics", return_value=None),
            caplog.at_level(logging.DEBUG, logger="auth_user_service.core.deps"),
        ):
            _handle_api_key_redis_degraded(api_key)

        assert raw_key_value not in caplog.text, (
            "Raw API key value leaked into fail-open log output"
        )


# ── 11.12c: revocation fail-open logging ──────────────────────────────────────


class TestRevocationFailOpenLogging:
    """Revocation fail-open decisions emit structured log output observable in prod."""

    def test_fail_open_revocation_increments_metric_with_mode_label(self):
        """fail_open revocation increments degraded_decision_total(mode=fail_open)."""
        fail_open_settings = _make(
            AUTH_STRICT_MODE=False, ACCESS_REVOCATION_FAILURE_MODE="fail_open"
        )
        mock_m = MagicMock()
        with (
            patch("auth_user_service.core.deps.settings", fail_open_settings),
            patch("auth_user_service.core.deps.get_redis_client", return_value=None),
            patch("auth_user_service.core.deps._get_metrics", return_value=mock_m),
        ):
            result = _check_jti_revocation("some-jti")

        assert result is None  # no raise in fail-open
        mock_m.degraded_decision_total.labels.assert_called_once_with(
            control="access_revocation", mode="fail_open", reason="redis_unavailable"
        )

    def test_fail_closed_revocation_increments_metric_with_mode_label(self):
        """fail_closed revocation increments degraded_decision_total(mode=fail_closed)."""
        from fastapi import HTTPException

        fail_closed_settings = _make(
            AUTH_STRICT_MODE=False, ACCESS_REVOCATION_FAILURE_MODE="fail_closed"
        )
        mock_m = MagicMock()
        with (
            patch("auth_user_service.core.deps.settings", fail_closed_settings),
            patch("auth_user_service.core.deps.get_redis_client", return_value=None),
            patch("auth_user_service.core.deps._get_metrics", return_value=mock_m),
        ):
            with pytest.raises(HTTPException) as exc_info:
                _check_jti_revocation("some-jti")

        assert exc_info.value.status_code == 503
        mock_m.degraded_decision_total.labels.assert_called_once_with(
            control="access_revocation", mode="fail_closed", reason="redis_unavailable"
        )


# ── 11.12d: log redaction — no JWT / refresh-token / service-token leak ───────


class TestLogRedactionSecretMaterial:
    """Degraded-mode log lines must not contain JWT, refresh, or service-token strings."""

    def test_redis_degraded_log_contains_no_jwt_string(self, caplog):
        """The Redis-unavailable warning emitted by get_redis_client contains no JWT."""
        from redis.exceptions import ConnectionError as RedisConnectionError
        from auth_user_service.core.deps import get_redis_client
        import auth_user_service.core.deps as _deps

        _deps._redis_degraded_since = None
        fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
        mock_client = MagicMock()
        mock_client.ping.side_effect = RedisConnectionError("Connection refused")
        with (
            patch("auth_user_service.core.deps._redis_pool", MagicMock()),
            patch("auth_user_service.core.deps.Redis", return_value=mock_client),
            patch("auth_user_service.core.deps._get_metrics", return_value=None),
            caplog.at_level(logging.WARNING, logger="auth_user_service.core.deps"),
        ):
            get_redis_client()

        assert fake_jwt not in caplog.text
        # The log must mention the degraded mode state.
        assert "redis.unavailable" in caplog.text or "degraded_mode" in caplog.text

    def test_api_key_degraded_log_no_service_token(self, caplog):
        """The api_key.rate_limit_unavailable log line contains no service-token value."""
        api_key = MagicMock()
        api_key.id = "00000000-0000-0000-0000-000000000099"
        fake_service_token = "svc_token_internal_secret_abc123xyz"
        # A buggy implementation might log request headers or body including tokens.
        api_key.token = fake_service_token
        open_settings = _make(AUTH_STRICT_MODE=False)
        with (
            patch("auth_user_service.core.deps.settings", open_settings),
            patch("auth_user_service.core.deps._get_metrics", return_value=None),
            caplog.at_level(logging.DEBUG, logger="auth_user_service.core.deps"),
        ):
            _handle_api_key_redis_degraded(api_key)

        assert fake_service_token not in caplog.text, (
            "Internal service token leaked into degraded-mode log output"
        )

    def test_api_key_degraded_log_no_refresh_token(self, caplog):
        """The api_key degraded log contains no refresh-token value."""
        api_key = MagicMock()
        api_key.id = "00000000-0000-0000-0000-000000000088"
        fake_refresh = "refresh_tok_secret_abc123xyz_unique_value"
        api_key.refresh_token = fake_refresh
        open_settings = _make(AUTH_STRICT_MODE=False)
        with (
            patch("auth_user_service.core.deps.settings", open_settings),
            patch("auth_user_service.core.deps._get_metrics", return_value=None),
            caplog.at_level(logging.DEBUG, logger="auth_user_service.core.deps"),
        ):
            _handle_api_key_redis_degraded(api_key)

        assert fake_refresh not in caplog.text, (
            "Refresh token leaked into degraded-mode log output"
        )


# ── 11.12e: API-key strict denial emits metric ───────────────────────────────


class TestApiKeyDenialMetric:
    """API-key Redis-degraded paths emit the correct degraded_decision_total sample."""

    def test_strict_denial_emits_fail_closed_metric(self):
        """Strict denial increments degraded_decision_total(mode=fail_closed)."""
        from fastapi import HTTPException

        api_key = MagicMock()
        api_key.id = "00000000-0000-0000-0000-000000000002"
        strict_settings = _make(
            AUTH_STRICT_MODE=True,
            PRIVATE_API_CONSUMERS={
                "test-svc": {"secret": "plain-test-secret", "scopes": ["introspection"]}
            },
        )
        mock_m = MagicMock()
        with (
            patch("auth_user_service.core.deps.settings", strict_settings),
            patch("auth_user_service.core.deps._get_metrics", return_value=mock_m),
        ):
            with pytest.raises(HTTPException):
                _handle_api_key_redis_degraded(api_key)

        mock_m.degraded_decision_total.labels.assert_called_once_with(
            control="api_key_rate_limit", mode="fail_closed", reason="redis_unavailable"
        )

    def test_fail_open_emits_fail_open_metric(self):
        """Fail-open path increments degraded_decision_total(mode=fail_open)."""
        api_key = MagicMock()
        api_key.id = "00000000-0000-0000-0000-000000000003"
        open_settings = _make(AUTH_STRICT_MODE=False)
        mock_m = MagicMock()
        with (
            patch("auth_user_service.core.deps.settings", open_settings),
            patch("auth_user_service.core.deps._get_metrics", return_value=mock_m),
        ):
            _handle_api_key_redis_degraded(api_key)

        mock_m.degraded_decision_total.labels.assert_called_once_with(
            control="api_key_rate_limit", mode="fail_open", reason="redis_unavailable"
        )
        mock_m.degraded_decision_total.labels.return_value.inc.assert_called_once()
