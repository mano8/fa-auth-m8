"""Tests for routes/security.py — the non-disclosing superuser-probe canary (3.9)."""

import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from auth_user_service.routes.security import _enforce_probe_rate_limit, superuser_probe


def _user() -> MagicMock:
    m = MagicMock()
    m.id = uuid.uuid4()
    return m


class TestSuperuserProbe:
    def test_returns_only_authorized_true(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 1
        result = superuser_probe(redis=redis, current_user=_user())
        assert result == {"authorized": True}

    def test_response_has_no_extra_keys(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 1
        result = superuser_probe(redis=redis, current_user=_user())
        assert set(result.keys()) == {"authorized"}


class TestEnforceProbeRateLimit:
    def test_allows_within_limit(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 1
        _enforce_probe_rate_limit(redis, "user-1")
        redis.expire.assert_called_once()

    def test_rejects_over_limit_with_429(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 31
        with pytest.raises(HTTPException) as exc_info:
            _enforce_probe_rate_limit(redis, "user-1")
        assert exc_info.value.status_code == 429

    def test_redis_unavailable_fail_closed_raises_503(self) -> None:
        mock_metrics = MagicMock()
        with (
            patch("auth_user_service.routes.security.settings") as mock_settings,
            patch(
                "auth_user_service.routes.security._get_metrics",
                return_value=mock_metrics,
            ),
        ):
            mock_settings.effective_failure_mode.return_value = "fail_closed"
            with pytest.raises(HTTPException) as exc_info:
                _enforce_probe_rate_limit(None, "user-1")
        assert exc_info.value.status_code == 503
        mock_metrics.degraded_decision_total.labels.assert_called_once_with(
            control="rate_limit", mode="fail_closed", reason="redis_unavailable"
        )

    def test_redis_unavailable_fail_open_does_not_raise(self) -> None:
        with patch("auth_user_service.routes.security.settings") as mock_settings:
            mock_settings.effective_failure_mode.return_value = "fail_open"
            _enforce_probe_rate_limit(None, "user-1")

    def test_keys_by_user_id_not_shared_across_users(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 1
        _enforce_probe_rate_limit(redis, "user-a")
        _enforce_probe_rate_limit(redis, "user-b")
        called_keys = {call.args[0] for call in redis.incr.call_args_list}
        assert called_keys == {
            "security:superuser_probe:user-a",
            "security:superuser_probe:user-b",
        }


class TestRouterRegistration:
    def test_router_prefix_and_path(self) -> None:
        from auth_user_service.routes.security import router

        route = next(r for r in router.routes if r.path == "/security/superuser-probe")
        assert route.include_in_schema is False
        assert "GET" in route.methods

    def test_route_uses_canonical_superuser_guard(self) -> None:
        from auth_user_service.core.deps import get_current_active_superuser
        from auth_user_service.routes.security import router

        route = next(r for r in router.routes if r.path == "/security/superuser-probe")
        dependants = [
            d.call for d in route.dependant.dependencies if d.call is not None
        ]
        assert get_current_active_superuser in dependants
