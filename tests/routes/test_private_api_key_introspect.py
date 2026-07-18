"""Tests for POST /private/v1/api-keys/introspect — the remote half of §3.12.

The route function is exercised directly with the consumer authentication, key
lookup, owner resolution, and rate-limit chain stubbed, so every branch of the
normative processing order — schema-version gate, anti-abuse allowance, key
resolution, live owner resolution, audience admission, functional-quota parity,
and the single generic inactive result — is covered in isolation. The shared
canonical principal resolution itself is unit tested in
``tests/core/test_api_key_principal.py``; the audience helper and the anti-abuse
helper are covered directly below.
"""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException, Response
from sqlalchemy.exc import SQLAlchemyError

from auth_sdk_m8.schemas.api_key import (
    ApiKeyIntrospectionActiveResponse,
    ApiKeyIntrospectionInactiveResponse,
    ApiKeyIntrospectionRequest,
    ApiKeyPrincipal,
)
from auth_sdk_m8.schemas.base import ApiKeyAccessMode, RoleType

from auth_user_service.routes.private import (
    _consume_introspection_antiabuse,
    _key_carries_audience,
    introspect_api_key,
)

_CONSUMER = "prompt-engine-m8"


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _request(**overrides) -> ApiKeyIntrospectionRequest:
    data = {"api_key": "ak_" + "s" * 20}
    data.update(overrides)
    return ApiKeyIntrospectionRequest(**data)


def _redis(count: int = 1) -> MagicMock:
    """A Redis mock whose anti-abuse pipeline reports *count* for the window."""
    redis = MagicMock()
    pipe = MagicMock()
    pipe.execute.return_value = [count, True]
    redis.pipeline.return_value.__enter__.return_value = pipe
    return redis


def _api_key(audiences=None, expires_at=None) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        expires_at=expires_at,
        audiences=audiences if audiences is not None else [],
    )


def _principal() -> ApiKeyPrincipal:
    return ApiKeyPrincipal(
        user_id=str(uuid.uuid4()),
        role=RoleType.WRITER,
        is_superuser=False,
        access_mode=ApiKeyAccessMode.READ_WRITE,
        auth_generation=4,
    )


_UNSET = object()


async def _call(body=None, redis=_UNSET):
    """Invoke the route with the consumer authenticated as ``_CONSUMER``.

    ``redis`` defaults to a within-limit mock; pass ``None`` explicitly to
    exercise the Redis-unavailable posture.
    """
    with patch(
        "auth_user_service.routes.private.authenticate_private_consumer",
        return_value=_CONSUMER,
    ):
        return await introspect_api_key(
            body=body or _request(),
            request=MagicMock(),
            response=Response(),
            session=MagicMock(),
            redis=_redis() if redis is _UNSET else redis,
        )


# ── consumer authentication / scope ───────────────────────────────────────────


@pytest.mark.anyio
async def test_consumer_auth_failure_propagates() -> None:
    """A 403 from the scope gate is the endpoint's response (never leaked as 200)."""
    with patch(
        "auth_user_service.routes.private.authenticate_private_consumer",
        side_effect=HTTPException(status_code=403, detail="Forbidden"),
    ):
        with pytest.raises(HTTPException) as exc:
            await introspect_api_key(
                body=_request(),
                request=MagicMock(),
                response=Response(),
                session=MagicMock(),
                redis=_redis(),
            )
    assert exc.value.status_code == 403


# ── schema-version gate ───────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_unsupported_schema_version_is_503() -> None:
    """A requested contract version the issuer does not implement fails closed."""
    with pytest.raises(HTTPException) as exc:
        await _call(body=_request(schema_version="99"))
    assert exc.value.status_code == 503


# ── key resolution (steps 4-5) ────────────────────────────────────────────────


@pytest.mark.anyio
async def test_unknown_key_is_generic_inactive() -> None:
    """An unknown/revoked/expired key returns the single generic inactive shape."""
    with patch(
        "auth_user_service.routes.private.ApiKeyService.get_active_key",
        return_value=None,
    ):
        result = await _call()
    assert isinstance(result, ApiKeyIntrospectionInactiveResponse)
    assert result.active is False


@pytest.mark.anyio
async def test_key_lookup_db_error_is_503() -> None:
    """An unreachable authoritative database is a 503, never a guessed answer."""
    with patch(
        "auth_user_service.routes.private.ApiKeyService.get_active_key",
        side_effect=SQLAlchemyError("db down"),
    ):
        with pytest.raises(HTTPException) as exc:
            await _call()
    assert exc.value.status_code == 503


@pytest.mark.anyio
async def test_raw_secret_reaches_lookup_and_is_masked_in_repr() -> None:
    """The issuer receives the real secret; the request model masks it."""
    body = _request(api_key="ak_super_secret_value")
    assert "super_secret_value" not in repr(body)
    with patch(
        "auth_user_service.routes.private.ApiKeyService.get_active_key",
        return_value=None,
    ) as lookup:
        await _call(body=body)
    assert lookup.call_args.args[1] == "ak_super_secret_value"


# ── owner resolution (steps 6-7) ──────────────────────────────────────────────


@pytest.mark.anyio
async def test_owner_cannot_vouch_is_generic_inactive() -> None:
    """Missing/inactive/claim-inconsistent owner returns the generic inactive shape."""
    with (
        patch(
            "auth_user_service.routes.private.ApiKeyService.get_active_key",
            return_value=_api_key(),
        ),
        patch(
            "auth_user_service.routes.private.resolve_api_key_owner_principal",
            return_value=None,
        ),
    ):
        result = await _call()
    assert isinstance(result, ApiKeyIntrospectionInactiveResponse)


@pytest.mark.anyio
async def test_owner_resolution_db_error_is_503() -> None:
    with (
        patch(
            "auth_user_service.routes.private.ApiKeyService.get_active_key",
            return_value=_api_key(),
        ),
        patch(
            "auth_user_service.routes.private.resolve_api_key_owner_principal",
            side_effect=SQLAlchemyError("db down"),
        ),
    ):
        with pytest.raises(HTTPException) as exc:
            await _call()
    assert exc.value.status_code == 503


# ── audience admission (steps 8-9) ────────────────────────────────────────────


@pytest.mark.anyio
async def test_key_without_the_audience_is_generic_inactive() -> None:
    """No matching audience ⇒ generic inactive (fail-closed cutover) — and the
    key's functional quota is **not** consumed."""
    apply = MagicMock()
    with (
        patch(
            "auth_user_service.routes.private.ApiKeyService.get_active_key",
            return_value=_api_key(audiences=[]),
        ),
        patch(
            "auth_user_service.routes.private.resolve_api_key_owner_principal",
            return_value=_principal(),
        ),
        patch("auth_user_service.routes.private._apply_rate_limit", apply),
    ):
        result = await _call()
    assert isinstance(result, ApiKeyIntrospectionInactiveResponse)
    apply.assert_not_called()


# ── active path (steps 10-13) ─────────────────────────────────────────────────


@pytest.mark.anyio
async def test_active_returns_minimized_principal_and_consumes_quota() -> None:
    """A fully admitted key returns the canonical principal and consumes quota."""
    expires = datetime(2030, 1, 1, tzinfo=timezone.utc)
    key = _api_key(
        audiences=[SimpleNamespace(audience_id=_CONSUMER)], expires_at=expires
    )
    principal = _principal()
    apply = MagicMock()
    with (
        patch(
            "auth_user_service.routes.private.ApiKeyService.get_active_key",
            return_value=key,
        ),
        patch(
            "auth_user_service.routes.private.resolve_api_key_owner_principal",
            return_value=principal,
        ),
        patch("auth_user_service.routes.private._apply_rate_limit", apply),
    ):
        result = await _call(redis=_redis())
    assert isinstance(result, ApiKeyIntrospectionActiveResponse)
    assert result.active is True
    assert result.audience_id == _CONSUMER
    assert result.principal is principal
    assert result.key_expires_at == expires
    apply.assert_called_once()


@pytest.mark.anyio
async def test_active_quota_exhausted_relays_429() -> None:
    """An exhausted functional quota surfaces as 429 with the local semantics."""
    key = _api_key(audiences=[SimpleNamespace(audience_id=_CONSUMER)])
    with (
        patch(
            "auth_user_service.routes.private.ApiKeyService.get_active_key",
            return_value=key,
        ),
        patch(
            "auth_user_service.routes.private.resolve_api_key_owner_principal",
            return_value=_principal(),
        ),
        patch(
            "auth_user_service.routes.private._apply_rate_limit",
            side_effect=HTTPException(
                status_code=429, detail="rate", headers={"Retry-After": "5"}
            ),
        ),
    ):
        with pytest.raises(HTTPException) as exc:
            await _call(redis=_redis())
    assert exc.value.status_code == 429
    assert exc.value.headers["Retry-After"] == "5"


@pytest.mark.anyio
async def test_active_redis_none_uses_degraded_decision() -> None:
    """On the active path with Redis down (dev fail-open) the degraded decision
    handles admission — the same chain local auth uses."""
    key = _api_key(audiences=[SimpleNamespace(audience_id=_CONSUMER)])
    degraded = MagicMock()
    with (
        patch("auth_user_service.routes.private.settings") as cfg,
        patch(
            "auth_user_service.routes.private.ApiKeyService.get_active_key",
            return_value=key,
        ),
        patch(
            "auth_user_service.routes.private.resolve_api_key_owner_principal",
            return_value=_principal(),
        ),
        patch(
            "auth_user_service.routes.private._handle_api_key_redis_degraded", degraded
        ),
    ):
        cfg.effective_api_key_strict_rate_limit = False
        result = await _call(redis=None)
    assert isinstance(result, ApiKeyIntrospectionActiveResponse)
    degraded.assert_called_once()


# ── audience helper ───────────────────────────────────────────────────────────


def test_key_carries_audience_matches() -> None:
    key = _api_key(audiences=[SimpleNamespace(audience_id=_CONSUMER)])
    assert _key_carries_audience(key, _CONSUMER) is True


def test_key_carries_audience_no_match() -> None:
    key = _api_key(audiences=[SimpleNamespace(audience_id="other")])
    assert _key_carries_audience(key, _CONSUMER) is False


def test_key_carries_audience_none_relation_is_false() -> None:
    """A key with no audience attribute at all (pre-Expand) carries none."""
    assert _key_carries_audience(SimpleNamespace(), _CONSUMER) is False


# ── anti-abuse helper ─────────────────────────────────────────────────────────


def test_antiabuse_within_limit_allows() -> None:
    """A consumer under the per-minute ceiling is not blocked."""
    with patch("auth_user_service.routes.private.settings") as cfg:
        cfg.API_KEY_INTROSPECTION_ANTIABUSE_PER_MINUTE = 5
        _consume_introspection_antiabuse(_redis(count=3), _CONSUMER)  # no raise


def test_antiabuse_over_limit_is_429() -> None:
    with patch("auth_user_service.routes.private.settings") as cfg:
        cfg.API_KEY_INTROSPECTION_ANTIABUSE_PER_MINUTE = 5
        with pytest.raises(HTTPException) as exc:
            _consume_introspection_antiabuse(_redis(count=6), _CONSUMER)
    assert exc.value.status_code == 429
    assert exc.value.headers["Retry-After"] == "60"


def test_antiabuse_redis_down_strict_is_503() -> None:
    with patch("auth_user_service.routes.private.settings") as cfg:
        cfg.effective_api_key_strict_rate_limit = True
        with pytest.raises(HTTPException) as exc:
            _consume_introspection_antiabuse(None, _CONSUMER)
    assert exc.value.status_code == 503


def test_antiabuse_redis_down_non_strict_allows() -> None:
    with patch("auth_user_service.routes.private.settings") as cfg:
        cfg.effective_api_key_strict_rate_limit = False
        _consume_introspection_antiabuse(None, _CONSUMER)  # fail-open, logged
