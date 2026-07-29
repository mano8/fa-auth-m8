"""Unit tests for services.api_keys (ApiKeyService, RateLimitEnforcer)."""

import inspect
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlmodel import col, select

from auth_sdk_m8.schemas.base import Period, RoleType
from auth_user_service.core.config import settings
from auth_user_service.db_models.api_keys import ApiKey, ApiKeyAudience, RateLimit
from auth_user_service.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)
from auth_user_service.services.api_keys import (
    ApiKeyAudienceError,
    ApiKeyPurgeRetentionFloorError,
    ApiKeyPurgeStalledError,
    ApiKeyService,
    RateLimitEnforcer,
    purge_dead_api_keys,
)
from auth_user_service.services.audit import RetentionWindow


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class TestRevokeAllUserKeysInTx:
    def test_revokes_all_non_revoked_keys_without_commit(self, db_session, sample_user):
        for _ in range(2):
            db_session.add(
                ApiKey(
                    name="k",
                    key_hash=uuid.uuid4().hex + uuid.uuid4().hex,
                    user_id=sample_user.id,
                    revoked=False,
                )
            )
        already = ApiKey(
            name="revoked",
            key_hash=uuid.uuid4().hex + uuid.uuid4().hex,
            user_id=sample_user.id,
            revoked=True,
        )
        db_session.add(already)
        db_session.commit()

        count = ApiKeyService.revoke_all_user_keys_in_tx(db_session, sample_user.id)

        assert count == 2  # only the two non-revoked keys are flipped
        remaining_active = db_session.exec(
            select(ApiKey).where(
                ApiKey.user_id == sample_user.id,
                ApiKey.revoked == False,  # noqa: E712
            )
        ).all()
        assert remaining_active == []

    def test_no_keys_returns_zero(self, db_session):
        assert ApiKeyService.revoke_all_user_keys_in_tx(db_session, uuid.uuid4()) == 0


@pytest.fixture
def active_api_key(db_session, sample_user):
    plaintext, key_hash = ApiKeyService.generate_key()
    api_key = ApiKey(
        name="test-key",
        key_hash=key_hash,
        user_id=sample_user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        revoked=False,
    )
    db_session.add(api_key)
    db_session.commit()
    db_session.refresh(api_key)
    return plaintext, api_key


@pytest.fixture
def mock_settings():
    s = MagicMock()
    s.API_KEY_DEFAULT_LIMIT_MINUTE = 60
    s.API_KEY_DEFAULT_LIMIT_HOUR = 1000
    s.API_KEY_DEFAULT_LIMIT_DAY = 10000
    s.API_KEY_DEFAULT_LIMIT_MONTH = 200000
    return s


# ---------------------------------------------------------------------------
# ApiKeyService.generate_key
# ---------------------------------------------------------------------------


class TestGenerateKey:
    def test_returns_tuple(self):
        result = ApiKeyService.generate_key()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_plaintext_has_prefix(self):
        plaintext, _ = ApiKeyService.generate_key()
        assert plaintext.startswith(ApiKeyService.KEY_PREFIX)

    def test_hash_is_64_chars(self):
        _, key_hash = ApiKeyService.generate_key()
        assert len(key_hash) == 64  # SHA-256 hex

    def test_each_call_generates_unique_key(self):
        plaintext1, _ = ApiKeyService.generate_key()
        plaintext2, _ = ApiKeyService.generate_key()
        assert plaintext1 != plaintext2


# ---------------------------------------------------------------------------
# ApiKeyService.verify_key
# ---------------------------------------------------------------------------


class TestVerifyKey:
    def test_correct_plaintext_verifies(self):
        plaintext, key_hash = ApiKeyService.generate_key()
        assert ApiKeyService.verify_key(plaintext, key_hash) is True

    def test_wrong_plaintext_fails(self):
        _, key_hash = ApiKeyService.generate_key()
        assert ApiKeyService.verify_key("ak_wrong", key_hash) is False

    def test_empty_string_fails(self):
        _, key_hash = ApiKeyService.generate_key()
        assert ApiKeyService.verify_key("", key_hash) is False


# ---------------------------------------------------------------------------
# ApiKeyService.get_active_key
# ---------------------------------------------------------------------------


class TestGetActiveKey:
    def test_returns_key_for_valid_plaintext(self, db_session, active_api_key):
        plaintext, api_key = active_api_key
        found = ApiKeyService.get_active_key(db_session, plaintext)
        assert found is not None
        assert found.id == api_key.id

    def test_returns_none_for_unknown_key(self, db_session):
        assert ApiKeyService.get_active_key(db_session, "ak_unknown") is None

    def test_returns_none_for_revoked_key(self, db_session, active_api_key):
        plaintext, api_key = active_api_key
        api_key.revoked = True
        db_session.add(api_key)
        db_session.commit()
        assert ApiKeyService.get_active_key(db_session, plaintext) is None

    def test_returns_none_for_expired_key(self, db_session, sample_user):
        plaintext, key_hash = ApiKeyService.generate_key()
        api_key = ApiKey(
            name="expired",
            key_hash=key_hash,
            user_id=sample_user.id,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
            revoked=False,
        )
        db_session.add(api_key)
        db_session.commit()
        assert ApiKeyService.get_active_key(db_session, plaintext) is None

    def test_invalid_key_emits_metric(self, db_session):
        mock_m = MagicMock()
        mock_m.api_key_validations_total = MagicMock()
        with patch(
            "auth_user_service.services.api_keys._metrics.get", return_value=mock_m
        ):
            result = ApiKeyService.get_active_key(db_session, "ak_nonexistent")
        assert result is None
        mock_m.api_key_validations_total.labels.assert_called_once_with(
            result="invalid"
        )

    def test_revoked_key_emits_metric(self, db_session, sample_user):
        plaintext, key_hash = ApiKeyService.generate_key()
        api_key = ApiKey(
            name="revoked-m", key_hash=key_hash, user_id=sample_user.id, revoked=True
        )
        db_session.add(api_key)
        db_session.commit()

        mock_m = MagicMock()
        mock_m.api_key_validations_total = MagicMock()
        with patch(
            "auth_user_service.services.api_keys._metrics.get", return_value=mock_m
        ):
            result = ApiKeyService.get_active_key(db_session, plaintext)
        assert result is None
        mock_m.api_key_validations_total.labels.assert_called_once_with(
            result="revoked"
        )

    def test_expired_key_emits_metric(self, db_session, sample_user):
        plaintext, key_hash = ApiKeyService.generate_key()
        api_key = ApiKey(
            name="expired-m",
            key_hash=key_hash,
            user_id=sample_user.id,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
            revoked=False,
        )
        db_session.add(api_key)
        db_session.commit()

        mock_m = MagicMock()
        mock_m.api_key_validations_total = MagicMock()
        with patch(
            "auth_user_service.services.api_keys._metrics.get", return_value=mock_m
        ):
            result = ApiKeyService.get_active_key(db_session, plaintext)
        assert result is None
        mock_m.api_key_validations_total.labels.assert_called_once_with(
            result="expired"
        )

    def test_valid_key_emits_success_metric(self, db_session, active_api_key):
        plaintext, _ = active_api_key
        mock_m = MagicMock()
        mock_m.api_key_validations_total = MagicMock()
        with patch(
            "auth_user_service.services.api_keys._metrics.get", return_value=mock_m
        ):
            result = ApiKeyService.get_active_key(db_session, plaintext)
        assert result is not None
        mock_m.api_key_validations_total.labels.assert_called_once_with(
            result="success"
        )

    def test_returns_key_when_no_expiry(self, db_session, sample_user):
        plaintext, key_hash = ApiKeyService.generate_key()
        api_key = ApiKey(
            name="no-expiry",
            key_hash=key_hash,
            user_id=sample_user.id,
            expires_at=None,
            revoked=False,
        )
        db_session.add(api_key)
        db_session.commit()
        found = ApiKeyService.get_active_key(db_session, plaintext)
        assert found is not None


# ---------------------------------------------------------------------------
# ApiKeyService.get_limits
# ---------------------------------------------------------------------------


class TestGetLimits:
    def test_returns_empty_when_no_rows(self, db_session, active_api_key):
        _, api_key = active_api_key
        limits = ApiKeyService.get_limits(db_session, api_key.id, api_key.user_id)
        assert limits == []

    def test_key_specific_limit_returned(self, db_session, active_api_key):
        _, api_key = active_api_key
        row = RateLimit(api_key_id=api_key.id, period=Period.MINUTE, limit=30)
        db_session.add(row)
        db_session.commit()

        limits = ApiKeyService.get_limits(db_session, api_key.id, api_key.user_id)
        assert (Period.MINUTE, 30) in limits

    def test_user_default_limit_returned_when_no_key_limit(
        self, db_session, active_api_key, sample_user
    ):
        _, api_key = active_api_key
        row = RateLimit(user_id=sample_user.id, period=Period.HOUR, limit=500)
        db_session.add(row)
        db_session.commit()

        limits = ApiKeyService.get_limits(db_session, api_key.id, api_key.user_id)
        assert (Period.HOUR, 500) in limits

    def test_key_limit_overrides_user_limit_for_same_period(
        self, db_session, active_api_key, sample_user
    ):
        _, api_key = active_api_key
        user_row = RateLimit(user_id=sample_user.id, period=Period.DAY, limit=5000)
        key_row = RateLimit(api_key_id=api_key.id, period=Period.DAY, limit=100)
        db_session.add(user_row)
        db_session.add(key_row)
        db_session.commit()

        limits = ApiKeyService.get_limits(db_session, api_key.id, api_key.user_id)
        day_limits = [lim for p, lim in limits if p == Period.DAY]
        assert day_limits == [100]  # key-specific wins

    def test_results_ordered_by_period(self, db_session, active_api_key):
        _, api_key = active_api_key
        db_session.add(RateLimit(api_key_id=api_key.id, period=Period.DAY, limit=1000))
        db_session.add(RateLimit(api_key_id=api_key.id, period=Period.MINUTE, limit=10))
        db_session.commit()

        limits = ApiKeyService.get_limits(db_session, api_key.id, api_key.user_id)
        periods = [p for p, _ in limits]
        assert periods.index(Period.MINUTE) < periods.index(Period.DAY)


# ---------------------------------------------------------------------------
# RateLimitEnforcer
# ---------------------------------------------------------------------------


class TestRateLimitEnforcer:
    def _make_enforcer(self, mock_redis, mock_settings):
        return RateLimitEnforcer(mock_redis, mock_settings)

    def _make_api_key(self):
        api_key = MagicMock(spec=ApiKey)
        api_key.id = uuid.uuid4()
        return api_key

    def _make_pipe(self, mock_redis, count):
        pipe = MagicMock()
        mock_redis.pipeline.return_value.__enter__ = MagicMock(return_value=pipe)
        mock_redis.pipeline.return_value.__exit__ = MagicMock(return_value=False)
        pipe.execute.return_value = (count, True)
        return pipe

    def test_allowed_result_when_under_limit(self, mock_settings):
        redis = MagicMock()
        self._make_pipe(redis, 1)
        api_key = self._make_api_key()
        enforcer = self._make_enforcer(redis, mock_settings)

        result = enforcer.enforce(api_key, [(Period.MINUTE, 10)])

        assert result.allowed is True

    def test_blocked_result_when_over_limit(self, mock_settings):
        redis = MagicMock()
        self._make_pipe(redis, 11)
        api_key = self._make_api_key()
        enforcer = self._make_enforcer(redis, mock_settings)

        result = enforcer.enforce(api_key, [(Period.MINUTE, 10)])

        assert result.allowed is False
        assert result.exceeded_period == Period.MINUTE

    def test_falls_back_to_settings_when_no_limits(self, mock_settings):
        mock_settings.API_KEY_DEFAULT_LIMIT_MINUTE = 60
        mock_settings.API_KEY_DEFAULT_LIMIT_HOUR = 0
        mock_settings.API_KEY_DEFAULT_LIMIT_DAY = 0
        mock_settings.API_KEY_DEFAULT_LIMIT_MONTH = 0

        redis = MagicMock()
        self._make_pipe(redis, 1)
        api_key = self._make_api_key()
        enforcer = self._make_enforcer(redis, mock_settings)

        result = enforcer.enforce(api_key, [])  # empty limits → use defaults

        assert result.allowed is True

    def test_default_limits_includes_day_when_positive(self, mock_settings):
        mock_settings.API_KEY_DEFAULT_LIMIT_MINUTE = 0
        mock_settings.API_KEY_DEFAULT_LIMIT_HOUR = 0
        mock_settings.API_KEY_DEFAULT_LIMIT_DAY = 5000
        mock_settings.API_KEY_DEFAULT_LIMIT_MONTH = 0

        enforcer = RateLimitEnforcer(MagicMock(), mock_settings)
        defaults = enforcer._default_limits()

        assert (Period.DAY, 5000) in defaults

    def test_default_limits_includes_month_when_positive(self, mock_settings):
        mock_settings.API_KEY_DEFAULT_LIMIT_MINUTE = 0
        mock_settings.API_KEY_DEFAULT_LIMIT_HOUR = 0
        mock_settings.API_KEY_DEFAULT_LIMIT_DAY = 0
        mock_settings.API_KEY_DEFAULT_LIMIT_MONTH = 100000

        enforcer = RateLimitEnforcer(MagicMock(), mock_settings)
        defaults = enforcer._default_limits()

        assert (Period.MONTH, 100000) in defaults

    def test_default_limits_excludes_zero_values(self, mock_settings):
        mock_settings.API_KEY_DEFAULT_LIMIT_MINUTE = 0
        mock_settings.API_KEY_DEFAULT_LIMIT_HOUR = 1000
        mock_settings.API_KEY_DEFAULT_LIMIT_DAY = 0
        mock_settings.API_KEY_DEFAULT_LIMIT_MONTH = 0

        enforcer = RateLimitEnforcer(MagicMock(), mock_settings)
        defaults = enforcer._default_limits()

        assert (Period.MINUTE, 0) not in defaults
        assert any(p == Period.HOUR for p, _ in defaults)

    def test_metrics_allowed_incremented(self, mock_settings):
        from unittest.mock import patch, MagicMock as MM

        redis = MagicMock()
        self._make_pipe(redis, 1)
        api_key = self._make_api_key()
        enforcer = self._make_enforcer(redis, mock_settings)

        mock_metrics = MM()
        mock_counter = MM()
        mock_metrics.api_key_rate_limit_checks_total = mock_counter
        mock_metrics.api_key_rate_limit_hits_total = None

        with patch(
            "auth_user_service.services.api_keys._metrics.get",
            return_value=mock_metrics,
        ):
            result = enforcer.enforce(api_key, [(Period.MINUTE, 10)])

        assert result.allowed is True
        assert mock_counter.labels.call_count >= 2  # "checked" + "allowed"

    def test_metrics_blocked_incremented(self, mock_settings):
        from unittest.mock import patch, MagicMock as MM

        redis = MagicMock()
        self._make_pipe(redis, 100)
        api_key = self._make_api_key()
        enforcer = self._make_enforcer(redis, mock_settings)

        mock_metrics = MM()
        mock_counter = MM()
        mock_hits = MM()
        mock_metrics.api_key_rate_limit_checks_total = mock_counter
        mock_metrics.api_key_rate_limit_hits_total = mock_hits

        with patch(
            "auth_user_service.services.api_keys._metrics.get",
            return_value=mock_metrics,
        ):
            result = enforcer.enforce(api_key, [(Period.MINUTE, 10)])

        assert result.allowed is False
        mock_hits.labels.assert_called_once_with(period=Period.MINUTE.value)


# ---------------------------------------------------------------------------
# Audience binding (APIKEY-AUD-01, §3.12)
# ---------------------------------------------------------------------------

_PERMITTED = frozenset({"prompt-engine-m8", "media-worker-m8"})


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


class TestNormalizeAudiences:
    def test_strips_and_dedupes_preserving_order(self):
        assert ApiKeyService.normalize_audiences([" b-m8 ", "a-m8", "b-m8"]) == [
            "b-m8",
            "a-m8",
        ]

    def test_empty_audience_rejected(self):
        with pytest.raises(ApiKeyAudienceError):
            ApiKeyService.normalize_audiences(["  "])

    def test_wildcard_rejected(self):
        with pytest.raises(ApiKeyAudienceError):
            ApiKeyService.normalize_audiences(["*"])


class TestValidateAudiences:
    def _patch_registry(self, permitted=_PERMITTED):
        return patch(
            "auth_user_service.core.consumer_registry.get_introspection_audiences",
            return_value=permitted,
        )

    def test_valid_audiences_pass(self):
        with self._patch_registry():
            assert ApiKeyService.validate_audiences(["prompt-engine-m8"]) == [
                "prompt-engine-m8"
            ]

    def test_unknown_audience_rejected(self):
        with self._patch_registry():
            with pytest.raises(ApiKeyAudienceError, match="ineligible"):
                ApiKeyService.validate_audiences(["not-a-consumer"])

    def test_over_max_rejected(self):
        with self._patch_registry(), patch.object(settings, "API_KEY_MAX_AUDIENCES", 1):
            with pytest.raises(ApiKeyAudienceError, match="at most"):
                ApiKeyService.validate_audiences(
                    ["prompt-engine-m8", "media-worker-m8"]
                )


class TestSetKeyAudiencesInTx:
    def test_sets_rows_without_commit(self, db_session, sample_user):
        api_key = _make_key(db_session, sample_user)
        ApiKeyService.set_key_audiences_in_tx(db_session, api_key, ["prompt-engine-m8"])
        db_session.commit()
        db_session.refresh(api_key)
        assert [a.audience_id for a in api_key.audiences] == ["prompt-engine-m8"]

    def test_replaces_existing_rows(self, db_session, sample_user):
        api_key = _make_key(db_session, sample_user)
        db_session.add(
            ApiKeyAudience(api_key_id=api_key.id, audience_id="media-worker-m8")
        )
        db_session.commit()
        db_session.refresh(api_key)
        ApiKeyService.set_key_audiences_in_tx(db_session, api_key, ["prompt-engine-m8"])
        db_session.commit()
        db_session.refresh(api_key)
        assert [a.audience_id for a in api_key.audiences] == ["prompt-engine-m8"]

    def test_binds_a_key_that_is_not_yet_persisted(self, db_session, sample_user):
        """The issuance path: the key row has no id until it is flushed.

        Every other caller passes a key that is already in the database. The
        creation route does not, so the bindings would otherwise be written with
        a null ``api_key_id`` and the insert would fail on the NOT NULL column.
        """
        api_key = ApiKey(
            key_hash=(uuid.uuid4().hex + uuid.uuid4().hex),
            user_id=sample_user.id,
            name="new-key",
        )
        db_session.add(api_key)
        ApiKeyService.set_key_audiences_in_tx(db_session, api_key, ["prompt-engine-m8"])
        db_session.commit()
        db_session.refresh(api_key)
        assert api_key.id is not None
        assert [a.audience_id for a in api_key.audiences] == ["prompt-engine-m8"]


class TestBindExistingKeyAudiences:
    def _patch_registry(self):
        return patch(
            "auth_user_service.core.consumer_registry.get_introspection_audiences",
            return_value=_PERMITTED,
        )

    def test_binds_when_key_has_none(self, db_session, sample_user):
        api_key = _make_key(db_session, sample_user)
        with self._patch_registry():
            bound = ApiKeyService.bind_existing_key_audiences(
                db_session, api_key, ["prompt-engine-m8"]
            )
        db_session.commit()
        db_session.refresh(api_key)
        assert bound == ["prompt-engine-m8"]
        assert [a.audience_id for a in api_key.audiences] == ["prompt-engine-m8"]

    def test_identical_set_is_idempotent_noop(self, db_session, sample_user):
        api_key = _make_key(db_session, sample_user)
        db_session.add(
            ApiKeyAudience(api_key_id=api_key.id, audience_id="prompt-engine-m8")
        )
        db_session.commit()
        db_session.refresh(api_key)
        with self._patch_registry():
            bound = ApiKeyService.bind_existing_key_audiences(
                db_session, api_key, ["prompt-engine-m8"]
            )
        assert bound == ["prompt-engine-m8"]

    def test_changing_a_different_set_is_refused(self, db_session, sample_user):
        api_key = _make_key(db_session, sample_user)
        db_session.add(
            ApiKeyAudience(api_key_id=api_key.id, audience_id="media-worker-m8")
        )
        db_session.commit()
        db_session.refresh(api_key)
        with self._patch_registry():
            with pytest.raises(ApiKeyAudienceError, match="immutable"):
                ApiKeyService.bind_existing_key_audiences(
                    db_session, api_key, ["prompt-engine-m8"]
                )


# ---------------------------------------------------------------------------
# purge_dead_api_keys (APIKEY-LIFECYCLE-01)
# ---------------------------------------------------------------------------


def _keys_for_owner(db_session, owner_id) -> list[ApiKey]:
    return list(db_session.exec(select(ApiKey).where(ApiKey.user_id == owner_id)).all())


def _revoked_key(owner, *, updated_at: datetime) -> ApiKey:
    return ApiKey(
        key_hash=(uuid.uuid4().hex + uuid.uuid4().hex),
        user_id=owner.id,
        name="dead-revoked",
        revoked=True,
        expires_at=None,
        updated_at=updated_at,
    )


def _expired_key(owner, *, expires_at: datetime) -> ApiKey:
    return ApiKey(
        key_hash=(uuid.uuid4().hex + uuid.uuid4().hex),
        user_id=owner.id,
        name="dead-expired",
        revoked=False,
        expires_at=expires_at,
    )


def _live_key(owner) -> ApiKey:
    return ApiKey(
        key_hash=(uuid.uuid4().hex + uuid.uuid4().hex),
        user_id=owner.id,
        name="live",
        revoked=False,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )


class TestPurgeDeadApiKeys:
    def test_rejects_window_below_the_default_floor(self, db_session, sample_user):
        with pytest.raises(ApiKeyPurgeRetentionFloorError):
            purge_dead_api_keys(
                db_session,
                window=RetentionWindow.ONE_WEEK,
                actor_user_id=sample_user.id,
                actor_role=RoleType.SUPERADMIN,
            )

    def test_shorter_window_allowed_under_explicit_config_opt_in(
        self, db_session, sample_user
    ):
        with patch(
            "auth_user_service.core.config.settings.API_KEY_PURGE_MIN_RETENTION_SECONDS",
            0,
        ):
            result = purge_dead_api_keys(
                db_session,
                window=RetentionWindow.ONE_WEEK,
                actor_user_id=sample_user.id,
                actor_role=RoleType.SUPERADMIN,
            )
        assert result.window == RetentionWindow.ONE_WEEK

    def test_purges_revoked_key_dated_by_updated_at(self, db_session, sample_user):
        now = datetime.now(timezone.utc)
        dead = _revoked_key(sample_user, updated_at=now - timedelta(days=400))
        db_session.add(dead)
        db_session.commit()

        result = purge_dead_api_keys(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=sample_user.id,
            actor_role=RoleType.SUPERADMIN,
            now=now,
        )

        assert result.removed == 1
        remaining_ids = {k.id for k in _keys_for_owner(db_session, sample_user.id)}
        assert dead.id not in remaining_ids

    def test_purges_expired_key_dated_by_expires_at(self, db_session, sample_user):
        now = datetime.now(timezone.utc)
        dead = _expired_key(sample_user, expires_at=now - timedelta(days=400))
        db_session.add(dead)
        db_session.commit()

        result = purge_dead_api_keys(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=sample_user.id,
            actor_role=RoleType.SUPERADMIN,
            now=now,
        )

        assert result.removed == 1
        remaining_ids = {k.id for k in _keys_for_owner(db_session, sample_user.id)}
        assert dead.id not in remaining_ids

    def test_never_purges_a_live_key(self, db_session, sample_user):
        now = datetime.now(timezone.utc)
        live = _live_key(sample_user)
        db_session.add(live)
        db_session.commit()

        result = purge_dead_api_keys(
            db_session,
            window=RetentionWindow.THREE_MONTHS,
            actor_user_id=sample_user.id,
            actor_role=RoleType.SUPERADMIN,
            now=now,
        )

        assert result.removed == 0
        remaining_ids = {k.id for k in _keys_for_owner(db_session, sample_user.id)}
        assert live.id in remaining_ids

    def test_null_expires_at_never_eligible_on_expiry_basis(
        self, db_session, sample_user
    ):
        # Non-revoked, no expiry — never dead, regardless of age.
        now = datetime.now(timezone.utc)
        never_expiring = ApiKey(
            key_hash=(uuid.uuid4().hex + uuid.uuid4().hex),
            user_id=sample_user.id,
            name="never-expires",
            revoked=False,
            expires_at=None,
            updated_at=now - timedelta(days=400),
        )
        db_session.add(never_expiring)
        db_session.commit()

        result = purge_dead_api_keys(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=sample_user.id,
            actor_role=RoleType.SUPERADMIN,
            now=now,
        )

        assert result.removed == 0
        remaining_ids = {k.id for k in _keys_for_owner(db_session, sample_user.id)}
        assert never_expiring.id in remaining_ids

    def test_recently_dead_key_survives_a_short_window(self, db_session, sample_user):
        now = datetime.now(timezone.utc)
        recent = _revoked_key(sample_user, updated_at=now - timedelta(days=10))
        db_session.add(recent)
        db_session.commit()

        result = purge_dead_api_keys(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=sample_user.id,
            actor_role=RoleType.SUPERADMIN,
            now=now,
        )

        assert result.removed == 0
        remaining_ids = {k.id for k in _keys_for_owner(db_session, sample_user.id)}
        assert recent.id in remaining_ids

    def test_deleting_the_key_cascades_audience_and_rate_limit_children(
        self, db_session, sample_user
    ):
        now = datetime.now(timezone.utc)
        dead = _revoked_key(sample_user, updated_at=now - timedelta(days=400))
        db_session.add(dead)
        db_session.commit()
        db_session.refresh(dead)

        db_session.add(
            ApiKeyAudience(api_key_id=dead.id, audience_id="media-worker-m8")
        )
        db_session.add(RateLimit(api_key_id=dead.id, period=Period.MINUTE, limit=10))
        db_session.commit()

        purge_dead_api_keys(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=sample_user.id,
            actor_role=RoleType.SUPERADMIN,
            now=now,
        )

        assert (
            db_session.exec(
                select(ApiKeyAudience).where(ApiKeyAudience.api_key_id == dead.id)
            ).first()
            is None
        )
        assert (
            db_session.exec(
                select(RateLimit).where(RateLimit.api_key_id == dead.id)
            ).first()
            is None
        )

    def test_batches_deletes_across_multiple_batch_iterations(
        self, db_session, sample_user
    ):
        now = datetime.now(timezone.utc)
        dead_keys = [
            _revoked_key(sample_user, updated_at=now - timedelta(days=400))
            for _ in range(5)
        ]
        for key in dead_keys:
            db_session.add(key)
        db_session.commit()

        result = purge_dead_api_keys(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=sample_user.id,
            actor_role=RoleType.SUPERADMIN,
            batch_size=2,
            now=now,
        )

        assert result.removed == 5

    def test_raises_when_a_delete_is_silently_suppressed(
        self, db_session, sample_user
    ) -> None:
        """G8-10, modelled on the audit-purge sibling test: with exactly one
        eligible row and ``batch_size=1`` the fetched batch never falls short
        of the batch size, so the loop only stops via the progress guard if
        the delete never actually removes the row."""
        now = datetime.now(timezone.utc)
        dead = _revoked_key(sample_user, updated_at=now - timedelta(days=400))
        db_session.add(dead)
        db_session.commit()

        with patch.object(db_session, "delete", lambda obj: None):
            with pytest.raises(ApiKeyPurgeStalledError):
                purge_dead_api_keys(
                    db_session,
                    window=RetentionWindow.ONE_YEAR,
                    actor_user_id=sample_user.id,
                    actor_role=RoleType.SUPERADMIN,
                    now=now,
                    batch_size=1,
                )

        db_session.delete(dead)
        db_session.commit()

    def test_writes_its_own_audit_row_that_survives_the_purge(
        self, db_session, sample_user
    ):
        now = datetime.now(timezone.utc)
        dead = _revoked_key(sample_user, updated_at=now - timedelta(days=400))
        db_session.add(dead)
        db_session.commit()

        result = purge_dead_api_keys(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=sample_user.id,
            actor_role=RoleType.SUPERADMIN,
            now=now,
        )

        rows = db_session.exec(
            select(PrivilegedActionAudit).where(
                col(PrivilegedActionAudit.actor_user_id) == sample_user.id,
                col(PrivilegedActionAudit.table_name) == ApiKey.__tablename__,
            )
        ).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.action == AuditAction.DELETE
        assert "1y" in row.row_pk
        assert f"removed={result.removed}" in row.row_pk
        assert row.actor_role == RoleType.SUPERADMIN

    def test_signature_has_no_row_scoping_parameter(self) -> None:
        # The horizon is the only selector — locking the signature shape
        # prevents a future change from adding a key-id/owner-id parameter
        # that would turn this into a targeted single-row delete.
        params = set(inspect.signature(purge_dead_api_keys).parameters)
        assert params == {
            "session",
            "window",
            "actor_user_id",
            "actor_role",
            "batch_size",
            "now",
        }


class TestCreationCapExcludesExpiredKeys:
    """The live-key cap query in ``routes.api_keys.create_api_key`` (§3.11
    ``APIKEY-LIFECYCLE-01``) counts only usable keys — an expired-but-unrevoked
    row must not consume it. ``routes/api_keys.py`` is a recorded live-tested
    coverage omission (.coveragerc), so this proves the corrected predicate at
    the query level rather than duplicating a route-level HTTP test."""

    def test_expired_unrevoked_key_is_excluded_from_the_cap_predicate(
        self, db_session, sample_user
    ):
        import sqlalchemy as sa
        from sqlalchemy import func as sa_func

        now = datetime.now(timezone.utc)
        expired = _expired_key(sample_user, expires_at=now - timedelta(hours=1))
        db_session.add(expired)
        db_session.commit()

        count_stmt = select(sa_func.count()).where(
            ApiKey.user_id == sample_user.id,
            col(ApiKey.revoked).is_(False),
            sa.or_(
                col(ApiKey.expires_at).is_(None),
                col(ApiKey.expires_at) >= now,
            ),
        )
        assert db_session.exec(count_stmt).one() == 0

    def test_live_key_is_still_counted(self, db_session, sample_user):
        import sqlalchemy as sa
        from sqlalchemy import func as sa_func

        now = datetime.now(timezone.utc)
        live = _live_key(sample_user)
        db_session.add(live)
        db_session.commit()

        count_stmt = select(sa_func.count()).where(
            ApiKey.user_id == sample_user.id,
            col(ApiKey.revoked).is_(False),
            sa.or_(
                col(ApiKey.expires_at).is_(None),
                col(ApiKey.expires_at) >= now,
            ),
        )
        assert db_session.exec(count_stmt).one() == 1
