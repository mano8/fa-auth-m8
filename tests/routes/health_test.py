"""Unit tests for the health check endpoint."""

from contextlib import ExitStack
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth_user_service.routes.health import _collect_health, router


class TestCollectHealth:
    def _mock_db_ok(self):
        """Return a context manager that simulates a successful DB SELECT 1."""
        mock_conn = MagicMock()
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=mock_conn)
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_engine = MagicMock()
        mock_engine.connect.return_value = mock_ctx
        return mock_engine

    def test_all_healthy_returns_ok(self):
        mock_engine = self._mock_db_ok()
        with (
            patch("auth_user_service.routes.health.settings") as mock_cfg,
            patch(
                "auth_user_service.routes.health.get_redis_client",
                return_value=MagicMock(),
            ),
            patch(
                "auth_user_service.routes.health.get_redis_degraded_since",
                return_value=None,
            ),
            patch("auth_user_service.routes.health.engine", mock_engine),
        ):
            mock_cfg.requires_redis = True
            mock_cfg.TOKEN_MODE = "stateful"
            mock_cfg.effective_failure_mode.side_effect = lambda c: "fail_closed"

            result = _collect_health()

        assert result["status"] == "ok"
        assert result["redis"] == "ok"
        assert result["database"] == "ok"
        assert result["circuit_breaker"] == "closed"
        assert result["effective_mode"] == "stateful"

    def test_redis_unavailable_opens_circuit_breaker(self):
        mock_engine = self._mock_db_ok()
        with (
            patch("auth_user_service.routes.health.settings") as mock_cfg,
            patch(
                "auth_user_service.routes.health.get_redis_client", return_value=None
            ),
            patch(
                "auth_user_service.routes.health.get_redis_degraded_since",
                return_value=None,
            ),
            patch("auth_user_service.routes.health.engine", mock_engine),
        ):
            mock_cfg.requires_redis = True
            mock_cfg.TOKEN_MODE = "stateful"
            mock_cfg.effective_failure_mode.side_effect = lambda c: "fail_closed"

            result = _collect_health()

        assert result["status"] == "degraded"
        assert result["redis"] == "unavailable"
        assert result["circuit_breaker"] == "open"
        assert result["effective_mode"] == "stateless_degraded"
        assert result["revocation_available"] is False
        assert result["rate_limiting_available"] is False

    def test_redis_not_required_circuit_breaker_closed(self):
        mock_engine = self._mock_db_ok()
        with (
            patch("auth_user_service.routes.health.settings") as mock_cfg,
            patch("auth_user_service.routes.health.get_redis_client") as mock_get_redis,
            patch(
                "auth_user_service.routes.health.get_redis_degraded_since",
                return_value=None,
            ),
            patch("auth_user_service.routes.health.engine", mock_engine),
        ):
            mock_cfg.requires_redis = False
            mock_cfg.TOKEN_MODE = "stateless"
            mock_cfg.effective_failure_mode.side_effect = lambda c: "fail_open"

            result = _collect_health()

        mock_get_redis.assert_not_called()
        assert result["circuit_breaker"] == "closed"
        assert result["status"] == "ok"

    def test_degradation_modes_included_in_response(self):
        mock_engine = self._mock_db_ok()
        with (
            patch("auth_user_service.routes.health.settings") as mock_cfg,
            patch(
                "auth_user_service.routes.health.get_redis_client",
                return_value=MagicMock(),
            ),
            patch(
                "auth_user_service.routes.health.get_redis_degraded_since",
                return_value=None,
            ),
            patch("auth_user_service.routes.health.engine", mock_engine),
        ):
            mock_cfg.requires_redis = True
            mock_cfg.TOKEN_MODE = "stateful"
            mock_cfg.effective_failure_mode.side_effect = lambda c: (
                "fail_closed"
                if c in ("refresh_validation", "session_write")
                else "fail_open"
            )

            result = _collect_health()

        modes = result["degradation_modes"]
        assert modes["rate_limit"] == "fail_open"
        assert modes["refresh_validation"] == "fail_closed"
        assert modes["session_write"] == "fail_closed"
        assert modes["access_revocation"] == "fail_open"

    def test_database_unavailable_returns_degraded(self):
        mock_engine = MagicMock()
        mock_engine.connect.side_effect = Exception("DB down")
        with (
            patch("auth_user_service.routes.health.settings") as mock_cfg,
            patch(
                "auth_user_service.routes.health.get_redis_client",
                return_value=MagicMock(),
            ),
            patch(
                "auth_user_service.routes.health.get_redis_degraded_since",
                return_value=None,
            ),
            patch("auth_user_service.routes.health.engine", mock_engine),
        ):
            mock_cfg.requires_redis = True
            mock_cfg.TOKEN_MODE = "stateful"
            mock_cfg.effective_failure_mode.side_effect = lambda c: "fail_open"

            result = _collect_health()

        assert result["status"] == "degraded"
        assert result["database"] == "unavailable"
        assert result["circuit_breaker"] == "closed"


_INTERNAL_SECRET = "Aa1-test-private-api-secret-32chars!!"

# Keys present only in the gated infrastructure detail body, never in the
# shallow public response.
_DETAIL_ONLY_KEYS = (
    "token_mode",
    "effective_mode",
    "redis",
    "circuit_breaker",
    "database",
    "revocation_available",
    "rate_limiting_available",
    "degraded_since",
    "degradation_modes",
)


class TestHealthDetailGating:
    """1.4 — deep /health detail is token-gated at the app layer.

    Shallow ``{"status": ...}`` answers everyone; the infrastructure detail is
    revealed only to callers presenting the ``X-Internal-Token`` shared secret.
    """

    def _client(self) -> TestClient:
        app = FastAPI()
        app.include_router(router)
        return TestClient(app, raise_server_exceptions=False)

    def _patched_settings(self):
        mock_cfg = MagicMock()
        mock_cfg.requires_redis = True
        mock_cfg.TOKEN_MODE = "stateful"
        mock_cfg.effective_failure_mode.side_effect = lambda c: "fail_closed"
        mock_cfg.PRIVATE_API_SECRET.get_secret_value.return_value = _INTERNAL_SECRET
        return mock_cfg

    def _mock_db_ok(self):
        mock_conn = MagicMock()
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=mock_conn)
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_engine = MagicMock()
        mock_engine.connect.return_value = mock_ctx
        return mock_engine

    def _enter_patches(self, stack: ExitStack):
        stack.enter_context(
            patch(
                "auth_user_service.routes.health.settings",
                self._patched_settings(),
            )
        )
        stack.enter_context(
            patch(
                "auth_user_service.routes.health.get_redis_client",
                return_value=MagicMock(),
            )
        )
        stack.enter_context(
            patch(
                "auth_user_service.routes.health.get_redis_degraded_since",
                return_value=None,
            )
        )
        stack.enter_context(
            patch("auth_user_service.routes.health.engine", self._mock_db_ok())
        )

    def test_anonymous_caller_gets_shallow_status_only(self):
        with ExitStack() as stack:
            self._enter_patches(stack)
            resp = self._client().get("/health/")

        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
        for key in _DETAIL_ONLY_KEYS:
            assert key not in resp.json()

    def test_internal_token_reveals_full_detail(self):
        with ExitStack() as stack:
            self._enter_patches(stack)
            resp = self._client().get(
                "/health/", headers={"X-Internal-Token": _INTERNAL_SECRET}
            )

        body = resp.json()
        assert resp.status_code == 200
        assert body["status"] == "ok"
        for key in _DETAIL_ONLY_KEYS:
            assert key in body
        assert body["token_mode"] == "stateful"

    def test_wrong_token_is_denied_detail(self):
        with ExitStack() as stack:
            self._enter_patches(stack)
            resp = self._client().get(
                "/health/", headers={"X-Internal-Token": "wrong-secret"}
            )

        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
