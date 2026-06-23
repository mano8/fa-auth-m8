"""Phase 5.5 — fa-auth-m8 degradation-policy tests.

Codifies the auth service's fail-open/fail-closed degradation contract so it
cannot silently regress. No new production code is introduced; every assertion
exercises existing behaviour.

The existing resilience suites (``tests/core/deps_test.py``,
``tests/routes/health_test.py``, ``tests/security/test_redis_resilience.py``)
verify that each enforcement point *honours whatever* ``effective_failure_mode``
returns — but they do so by **mocking** that method. This suite closes the
remaining gap: it exercises the **real** ``AUTH_STRICT_MODE`` override on a
genuine ``Settings`` instance and proves the override actually drives
fail-closed end to end at the enforcement points and in the health body.

Invariants locked in (per plan item 5.5):
- ``AUTH_STRICT_MODE=true`` forces every per-control mode to ``fail_closed``,
  overriding explicit per-control ``fail_open`` settings (the documented
  override, inherited from ``auth-sdk-m8`` ``CommonSettings``).
- The documented defaults hold when not strict: refresh-validation and
  session-write fail **closed**, rate-limit and access-revocation are
  configurable and ship with the documented defaults; an explicit per-control
  ``fail_open`` is honoured (a conscious, configurable opt-out) when not strict.
- Strict mode, with Redis down, makes ``_check_jti_revocation`` return 503 even
  when ``ACCESS_REVOCATION_FAILURE_MODE=fail_open`` — the override wins.
- A fail-open opt-out is a *recorded* decision: the degraded path increments
  ``degraded_decision_total`` labelled with the **real** effective mode.
- The health body surfaces the real degradation posture (all ``fail_closed``
  under strict), so silent degradation is observable.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from auth_user_service.core.config import Settings
from auth_user_service.core.deps import _check_jti_revocation
from auth_user_service.routes.health import _degradation_modes

# ── isolated settings construction ────────────────────────────────────────────
# Minimal valid kwargs for a Settings instance, bypassing the dotenv file.
# Mirrors _VALID_SETTINGS in tests/security/test_settings_validators.py.

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
    """Construct a real Settings from kwargs only, bypassing the dotenv file."""
    return Settings(_env_file=None, **{**_VALID_SETTINGS, **overrides})


class TestStrictModeOverridesFailureModes:
    """The real AUTH_STRICT_MODE override on a genuine Settings instance."""

    def test_documented_defaults_when_not_strict(self):
        """Out of the box (not strict), the documented defaults hold."""
        settings = _make()
        assert settings.AUTH_STRICT_MODE is False
        assert settings.effective_failure_mode("refresh_validation") == "fail_closed"
        assert settings.effective_failure_mode("session_write") == "fail_closed"
        assert settings.effective_failure_mode("rate_limit") == "fail_open"
        assert settings.effective_failure_mode("access_revocation") == "fail_closed"

    def test_strict_mode_forces_every_control_fail_closed(self):
        """AUTH_STRICT_MODE=true overrides explicit per-control fail_open."""
        settings = _make(
            AUTH_STRICT_MODE=True,
            REFRESH_VALIDATION_FAILURE_MODE="fail_open",
            SESSION_WRITE_FAILURE_MODE="fail_open",
            RATE_LIMIT_FAILURE_MODE="fail_open",
            ACCESS_REVOCATION_FAILURE_MODE="fail_open",
        )
        for control in _CONTROLS:
            assert settings.effective_failure_mode(control) == "fail_closed", control

    def test_per_control_fail_open_honored_when_not_strict(self):
        """A conscious per-control fail_open opt-out is configurable when not strict."""
        settings = _make(
            AUTH_STRICT_MODE=False,
            REFRESH_VALIDATION_FAILURE_MODE="fail_open",
            ACCESS_REVOCATION_FAILURE_MODE="fail_open",
        )
        assert settings.effective_failure_mode("refresh_validation") == "fail_open"
        assert settings.effective_failure_mode("access_revocation") == "fail_open"
        # Untouched controls keep their defaults.
        assert settings.effective_failure_mode("session_write") == "fail_closed"


class TestStrictModeEnforcedAtRevocation:
    """The strict override actually drives the access-revocation enforcement point."""

    def test_strict_redis_down_revocation_raises_503_over_fail_open(self):
        """Strict + Redis down → 503 even though ACCESS_REVOCATION_FAILURE_MODE=fail_open."""
        settings = _make(
            AUTH_STRICT_MODE=True, ACCESS_REVOCATION_FAILURE_MODE="fail_open"
        )
        mock_metrics = MagicMock()
        with (
            patch("auth_user_service.core.deps.settings", settings),
            patch("auth_user_service.core.deps.get_redis_client", return_value=None),
            patch(
                "auth_user_service.core.deps._get_metrics", return_value=mock_metrics
            ),
        ):
            with pytest.raises(HTTPException) as exc_info:
                _check_jti_revocation("jti-under-strict")

        assert exc_info.value.status_code == 503
        # The decision is recorded with the *real* effective mode (fail_closed),
        # proving the strict override — not the per-control fail_open — drove it.
        mock_metrics.degraded_decision_total.labels.assert_called_once_with(
            control="access_revocation", mode="fail_closed", reason="redis_unavailable"
        )

    def test_fail_open_opt_out_proceeds_and_is_recorded(self):
        """Non-strict fail_open opt-out: allow through, but record the conscious decision."""
        settings = _make(
            AUTH_STRICT_MODE=False, ACCESS_REVOCATION_FAILURE_MODE="fail_open"
        )
        mock_metrics = MagicMock()
        with (
            patch("auth_user_service.core.deps.settings", settings),
            patch("auth_user_service.core.deps.get_redis_client", return_value=None),
            patch(
                "auth_user_service.core.deps._get_metrics", return_value=mock_metrics
            ),
        ):
            # No raise — fail_open lets the request proceed.
            assert _check_jti_revocation("jti-fail-open") is None

        mock_metrics.degraded_decision_total.labels.assert_called_once_with(
            control="access_revocation", mode="fail_open", reason="redis_unavailable"
        )
        mock_metrics.degraded_decision_total.labels.return_value.inc.assert_called_once()


class TestHealthReportsDegradationPolicy:
    """The health body surfaces the real degradation posture (observable, not silent)."""

    def test_degradation_modes_reflect_strict_override(self):
        """Under strict, the health body reports every control as fail_closed."""
        settings = _make(
            AUTH_STRICT_MODE=True,
            RATE_LIMIT_FAILURE_MODE="fail_open",
            ACCESS_REVOCATION_FAILURE_MODE="fail_open",
        )
        with patch("auth_user_service.routes.health.settings", settings):
            modes = _degradation_modes()

        assert modes == {control: "fail_closed" for control in _CONTROLS}

    def test_degradation_modes_reflect_configured_opt_outs(self):
        """Not strict, the health body reports the real per-control opt-outs."""
        settings = _make(
            AUTH_STRICT_MODE=False, ACCESS_REVOCATION_FAILURE_MODE="fail_open"
        )
        with patch("auth_user_service.routes.health.settings", settings):
            modes = _degradation_modes()

        assert modes["access_revocation"] == "fail_open"
        assert modes["rate_limit"] == "fail_open"
        assert modes["refresh_validation"] == "fail_closed"
        assert modes["session_write"] == "fail_closed"
