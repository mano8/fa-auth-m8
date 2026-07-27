"""Tests for routes/security.py — the non-disclosing superuser-probe canary (3.9),
the read-only privileged-action audit-log route, and the superadmin
retention-purge maintenance action (Phase 7)."""

import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.db_models.api_keys import ApiKey
from auth_user_service.db_models.privileged_action_audit import AuditAction
from auth_user_service.routes.security import (
    ApiKeyPurgeRequest,
    AuditPurgeRequest,
    _enforce_api_key_purge_rate_limit,
    _enforce_audit_log_rate_limit,
    _enforce_audit_purge_rate_limit,
    _enforce_probe_rate_limit,
    purge_api_keys,
    purge_audit_log,
    read_audit_log,
    superuser_probe,
)
from auth_user_service.services.audit import RetentionWindow, record_privileged_action


def _user() -> MagicMock:
    m = MagicMock()
    m.id = uuid.uuid4()
    return m


def _principal(role: RoleType, *, is_superuser: bool) -> MagicMock:
    m = MagicMock()
    m.id = uuid.uuid4()
    m.role = role
    m.is_superuser = is_superuser
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

    def test_audit_log_route_prefix_and_path(self) -> None:
        from auth_user_service.routes.security import router

        route = next(r for r in router.routes if r.path == "/security/audit-log")
        assert route.include_in_schema is False
        assert "GET" in route.methods

    def test_audit_log_route_uses_admin_guard_not_superuser(self) -> None:
        from auth_user_service.core.deps import get_current_active_admin
        from auth_user_service.routes.security import router

        route = next(r for r in router.routes if r.path == "/security/audit-log")
        dependants = [
            d.call for d in route.dependant.dependencies if d.call is not None
        ]
        assert get_current_active_admin in dependants


class TestEnforceAuditLogRateLimit:
    def test_allows_within_limit(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 1
        _enforce_audit_log_rate_limit(redis, "user-1")
        redis.expire.assert_called_once()

    def test_rejects_over_limit_with_429(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 31
        with pytest.raises(HTTPException) as exc_info:
            _enforce_audit_log_rate_limit(redis, "user-1")
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
                _enforce_audit_log_rate_limit(None, "user-1")
        assert exc_info.value.status_code == 503

    def test_keys_by_user_id_not_shared_across_users(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 1
        _enforce_audit_log_rate_limit(redis, "user-a")
        _enforce_audit_log_rate_limit(redis, "user-b")
        called_keys = {call.args[0] for call in redis.incr.call_args_list}
        assert called_keys == {
            "security:audit_log:user-a",
            "security:audit_log:user-b",
        }

    def test_redis_unavailable_fail_open_does_not_raise(self) -> None:
        with patch("auth_user_service.routes.security.settings") as mock_settings:
            mock_settings.effective_failure_mode.return_value = "fail_open"
            _enforce_audit_log_rate_limit(None, "user-1")

    def test_redis_unavailable_emits_degraded_decision_metric(self) -> None:
        mock_metrics = MagicMock()
        with (
            patch("auth_user_service.routes.security.settings") as mock_settings,
            patch(
                "auth_user_service.routes.security._get_metrics",
                return_value=mock_metrics,
            ),
        ):
            mock_settings.effective_failure_mode.return_value = "fail_open"
            _enforce_audit_log_rate_limit(None, "user-1")
        mock_metrics.degraded_decision_total.labels.assert_called_once_with(
            control="rate_limit", mode="fail_open", reason="redis_unavailable"
        )


class TestReadAuditLog:
    def test_superadmin_sees_every_row(self, db_session) -> None:
        author_a = _principal(RoleType.SUPERADMIN, is_superuser=True)
        author_b_id = uuid.uuid4()
        record_privileged_action(
            db_session,
            actor_user_id=author_a.id,
            actor_role=RoleType.SUPERADMIN,
            action=AuditAction.EDIT,
            table_name="auth_user",
            row_pk=uuid.uuid4(),
        )
        record_privileged_action(
            db_session,
            actor_user_id=author_b_id,
            actor_role=RoleType.SUPERADMIN,
            action=AuditAction.DELETE,
            table_name="auth_user",
            row_pk=uuid.uuid4(),
        )
        db_session.commit()

        redis = MagicMock()
        redis.incr.return_value = 1
        viewer = _principal(RoleType.SUPERADMIN, is_superuser=True)
        result = read_audit_log(session=db_session, redis=redis, current_user=viewer)

        seen_actors = {row.actor_user_id for row in result.data}
        assert author_a.id in seen_actors
        assert author_b_id in seen_actors
        assert result.count == len(result.data)

    def test_admin_sees_only_own_authored_rows_empty_result(self, db_session) -> None:
        # In-scope, only a superadmin generates issuer audit rows (Phase 7
        # routes/users.py and routes/sessions.py are superadmin-gated), so the
        # admin-own filter is proven with an empty result: an ADMIN viewer who
        # authored nothing sees zero rows even though superadmin rows exist.
        other_actor = uuid.uuid4()
        record_privileged_action(
            db_session,
            actor_user_id=other_actor,
            actor_role=RoleType.SUPERADMIN,
            action=AuditAction.ADD,
            table_name="auth_user",
            row_pk=uuid.uuid4(),
        )
        db_session.commit()

        redis = MagicMock()
        redis.incr.return_value = 1
        admin_viewer = _principal(RoleType.ADMIN, is_superuser=False)
        result = read_audit_log(
            session=db_session, redis=redis, current_user=admin_viewer
        )

        assert result.data == []
        assert result.count == 0

    def test_admin_sees_rows_it_authored_and_not_others(self, db_session) -> None:
        admin_viewer = _principal(RoleType.ADMIN, is_superuser=False)
        other_actor = uuid.uuid4()
        record_privileged_action(
            db_session,
            actor_user_id=admin_viewer.id,
            actor_role=RoleType.ADMIN,
            action=AuditAction.EDIT,
            table_name="auth_user",
            row_pk=uuid.uuid4(),
        )
        record_privileged_action(
            db_session,
            actor_user_id=other_actor,
            actor_role=RoleType.SUPERADMIN,
            action=AuditAction.DELETE,
            table_name="auth_user",
            row_pk=uuid.uuid4(),
        )
        db_session.commit()

        redis = MagicMock()
        redis.incr.return_value = 1
        result = read_audit_log(
            session=db_session, redis=redis, current_user=admin_viewer
        )

        assert result.count == 1
        assert result.data[0].actor_user_id == admin_viewer.id

    def test_enforces_rate_limit(self, db_session) -> None:
        redis = MagicMock()
        redis.incr.return_value = 31
        viewer = _principal(RoleType.SUPERADMIN, is_superuser=True)
        with pytest.raises(HTTPException) as exc_info:
            read_audit_log(session=db_session, redis=redis, current_user=viewer)
        assert exc_info.value.status_code == 429


class TestPurgeAuditLogRoute:
    def test_route_registration_and_guard(self) -> None:
        from auth_user_service.core.deps import get_current_active_superuser
        from auth_user_service.routes.security import router

        route = next(r for r in router.routes if r.path == "/security/audit-log/purge")
        assert route.include_in_schema is False
        assert "POST" in route.methods
        dependants = [
            d.call for d in route.dependant.dependencies if d.call is not None
        ]
        assert get_current_active_superuser in dependants

    def test_superadmin_purge_removes_only_expired_rows(self, db_session) -> None:
        actor = _principal(RoleType.SUPERADMIN, is_superuser=True)
        redis = MagicMock()
        redis.incr.return_value = 1

        result = purge_audit_log(
            session=db_session,
            redis=redis,
            payload=AuditPurgeRequest(window=RetentionWindow.THREE_MONTHS),
            current_user=actor,
        )

        assert result.window == RetentionWindow.THREE_MONTHS
        assert result.removed == 0

    def test_window_below_floor_returns_400(self, db_session) -> None:
        actor = _principal(RoleType.SUPERADMIN, is_superuser=True)
        redis = MagicMock()
        redis.incr.return_value = 1

        with pytest.raises(HTTPException) as exc_info:
            purge_audit_log(
                session=db_session,
                redis=redis,
                payload=AuditPurgeRequest(window=RetentionWindow.ONE_WEEK),
                current_user=actor,
            )
        assert exc_info.value.status_code == 400

    def test_enforces_rate_limit(self, db_session) -> None:
        actor = _principal(RoleType.SUPERADMIN, is_superuser=True)
        redis = MagicMock()
        redis.incr.return_value = 11

        with pytest.raises(HTTPException) as exc_info:
            purge_audit_log(
                session=db_session,
                redis=redis,
                payload=AuditPurgeRequest(window=RetentionWindow.ONE_YEAR),
                current_user=actor,
            )
        assert exc_info.value.status_code == 429


class TestEnforceAuditPurgeRateLimit:
    def test_allows_within_limit(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 1
        _enforce_audit_purge_rate_limit(redis, "user-1")
        redis.expire.assert_called_once()

    def test_rejects_over_limit_with_429(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 11
        with pytest.raises(HTTPException) as exc_info:
            _enforce_audit_purge_rate_limit(redis, "user-1")
        assert exc_info.value.status_code == 429

    def test_keys_by_user_id_not_shared_across_users(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 1
        _enforce_audit_purge_rate_limit(redis, "user-a")
        _enforce_audit_purge_rate_limit(redis, "user-b")
        called_keys = {call.args[0] for call in redis.incr.call_args_list}
        assert called_keys == {
            "security:audit_purge:user-a",
            "security:audit_purge:user-b",
        }

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
                _enforce_audit_purge_rate_limit(None, "user-1")
        assert exc_info.value.status_code == 503

    def test_redis_unavailable_fail_open_does_not_raise(self) -> None:
        with patch("auth_user_service.routes.security.settings") as mock_settings:
            mock_settings.effective_failure_mode.return_value = "fail_open"
            _enforce_audit_purge_rate_limit(None, "user-1")

    def test_redis_unavailable_emits_degraded_decision_metric(self) -> None:
        mock_metrics = MagicMock()
        with (
            patch("auth_user_service.routes.security.settings") as mock_settings,
            patch(
                "auth_user_service.routes.security._get_metrics",
                return_value=mock_metrics,
            ),
        ):
            mock_settings.effective_failure_mode.return_value = "fail_open"
            _enforce_audit_purge_rate_limit(None, "user-1")
        mock_metrics.degraded_decision_total.labels.assert_called_once_with(
            control="rate_limit", mode="fail_open", reason="redis_unavailable"
        )


class TestPurgeApiKeysRoute:
    """`POST /security/api-keys/purge` (APIKEY-LIFECYCLE-01, Phase 7 addendum)."""

    def test_route_registration_and_guard(self) -> None:
        from auth_user_service.core.deps import get_current_active_superuser
        from auth_user_service.routes.security import router

        route = next(r for r in router.routes if r.path == "/security/api-keys/purge")
        assert route.include_in_schema is False
        assert "POST" in route.methods
        dependants = [
            d.call for d in route.dependant.dependencies if d.call is not None
        ]
        assert get_current_active_superuser in dependants

    def test_superadmin_purge_removes_dead_key(self, db_session, sample_user) -> None:
        import uuid as _uuid
        from datetime import datetime, timedelta, timezone

        dead = ApiKey(
            key_hash=(_uuid.uuid4().hex + _uuid.uuid4().hex),
            user_id=sample_user.id,
            name="dead",
            revoked=True,
            expires_at=None,
            updated_at=datetime.now(timezone.utc) - timedelta(days=400),
        )
        db_session.add(dead)
        db_session.commit()

        actor = _principal(RoleType.SUPERADMIN, is_superuser=True)
        redis = MagicMock()
        redis.incr.return_value = 1

        result = purge_api_keys(
            session=db_session,
            redis=redis,
            payload=ApiKeyPurgeRequest(window=RetentionWindow.ONE_YEAR),
            current_user=actor,
        )

        assert result.window == RetentionWindow.ONE_YEAR
        assert result.removed == 1

    def test_window_below_floor_returns_400(self, db_session) -> None:
        actor = _principal(RoleType.SUPERADMIN, is_superuser=True)
        redis = MagicMock()
        redis.incr.return_value = 1

        with pytest.raises(HTTPException) as exc_info:
            purge_api_keys(
                session=db_session,
                redis=redis,
                payload=ApiKeyPurgeRequest(window=RetentionWindow.ONE_WEEK),
                current_user=actor,
            )
        assert exc_info.value.status_code == 400

    def test_enforces_rate_limit(self, db_session) -> None:
        actor = _principal(RoleType.SUPERADMIN, is_superuser=True)
        redis = MagicMock()
        redis.incr.return_value = 11

        with pytest.raises(HTTPException) as exc_info:
            purge_api_keys(
                session=db_session,
                redis=redis,
                payload=ApiKeyPurgeRequest(window=RetentionWindow.ONE_YEAR),
                current_user=actor,
            )
        assert exc_info.value.status_code == 429


class TestEnforceApiKeyPurgeRateLimit:
    def test_allows_within_limit(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 1
        _enforce_api_key_purge_rate_limit(redis, "user-1")
        redis.expire.assert_called_once()

    def test_rejects_over_limit_with_429(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 11
        with pytest.raises(HTTPException) as exc_info:
            _enforce_api_key_purge_rate_limit(redis, "user-1")
        assert exc_info.value.status_code == 429

    def test_keys_by_user_id_not_shared_across_users(self) -> None:
        redis = MagicMock()
        redis.incr.return_value = 1
        _enforce_api_key_purge_rate_limit(redis, "user-a")
        _enforce_api_key_purge_rate_limit(redis, "user-b")
        called_keys = {call.args[0] for call in redis.incr.call_args_list}
        assert called_keys == {
            "security:api_key_purge:user-a",
            "security:api_key_purge:user-b",
        }

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
                _enforce_api_key_purge_rate_limit(None, "user-1")
        assert exc_info.value.status_code == 503

    def test_redis_unavailable_fail_open_does_not_raise(self) -> None:
        with patch("auth_user_service.routes.security.settings") as mock_settings:
            mock_settings.effective_failure_mode.return_value = "fail_open"
            _enforce_api_key_purge_rate_limit(None, "user-1")

    def test_redis_unavailable_emits_degraded_decision_metric(self) -> None:
        mock_metrics = MagicMock()
        with (
            patch("auth_user_service.routes.security.settings") as mock_settings,
            patch(
                "auth_user_service.routes.security._get_metrics",
                return_value=mock_metrics,
            ),
        ):
            mock_settings.effective_failure_mode.return_value = "fail_open"
            _enforce_api_key_purge_rate_limit(None, "user-1")
        mock_metrics.degraded_decision_total.labels.assert_called_once_with(
            control="rate_limit", mode="fail_open", reason="redis_unavailable"
        )
