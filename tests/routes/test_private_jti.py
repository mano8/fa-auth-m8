"""Tests for the /private/v1/jti-status endpoint — 100% branch coverage.

Covers the v1 legacy (Redis-blacklist-only) path and the v2 subject-bound route
branches (3.5.2). The database-authoritative ordered decision itself is unit
tested against a real session in ``tests/services/test_generation.py``
(``TestDecideJtiStatus``); here the decision is stubbed so every route branch —
version gate, mode gate, 503-on-DB-unavailable, and the Redis accelerator around
an active decision — is exercised in isolation.
"""

import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError

from auth_sdk_m8.schemas.jti_status import (
    JtiStatusActiveResponse,
    JtiStatusInactiveResponse,
)

from auth_user_service.routes.private import (
    JtiStatusRequest,
    JtiStatusResponse,
    PrivateUserCreate,
    check_jti_status,
    create_user,
)
from auth_user_service.services.generation import JtiStatusDecision


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _v2_request(**overrides) -> JtiStatusRequest:
    """A well-formed subject-bound v2 request, minus any overridden fields."""
    data = {
        "jti": "j" * 16,
        "expected_user_id": uuid.uuid4(),
        "schema_version": "2",
    }
    data.update(overrides)
    return JtiStatusRequest(**data)


# ── v1 legacy path (no subject binding) ───────────────────────────────────────


@pytest.mark.anyio
async def test_v1_non_stateful_returns_active() -> None:
    """Non-stateful mode skips Redis and returns the bare v1 active shape."""
    with patch("auth_user_service.routes.private.settings") as mock_cfg:
        mock_cfg.is_stateful = False
        result = await check_jti_status(
            body=JtiStatusRequest(jti="some-jti"),
            session=None,
            redis=None,
        )
    assert result == JtiStatusResponse(active=True)


@pytest.mark.anyio
async def test_v1_redis_unavailable_fail_open_returns_active() -> None:
    """Redis unavailable (None) in stateful + fail_open mode → active=True."""
    with patch("auth_user_service.routes.private.settings") as mock_cfg:
        mock_cfg.is_stateful = True
        mock_cfg.effective_failure_mode.return_value = "fail_open"
        result = await check_jti_status(
            body=JtiStatusRequest(jti="some-jti"),
            session=None,
            redis=None,
        )
    assert result == JtiStatusResponse(active=True)


@pytest.mark.anyio
async def test_v1_redis_unavailable_fail_closed_returns_inactive() -> None:
    """Redis unavailable (None) in stateful + fail_closed mode → active=False."""
    with patch("auth_user_service.routes.private.settings") as mock_cfg:
        mock_cfg.is_stateful = True
        mock_cfg.effective_failure_mode.return_value = "fail_closed"
        result = await check_jti_status(
            body=JtiStatusRequest(jti="some-jti"),
            session=None,
            redis=None,
        )
    assert result == JtiStatusResponse(active=False)


@pytest.mark.anyio
async def test_v1_not_revoked_returns_active() -> None:
    """Stateful mode, Redis available, JTI not in blacklist → active=True."""
    mock_redis = MagicMock()
    mock_blacklist = MagicMock()
    mock_blacklist.is_revoked.return_value = False

    with (
        patch("auth_user_service.routes.private.settings") as mock_cfg,
        patch("auth_sdk_m8.security.AccessTokenBlacklist", return_value=mock_blacklist),
    ):
        mock_cfg.is_stateful = True
        result = await check_jti_status(
            body=JtiStatusRequest(jti="active-jti"),
            session=None,
            redis=mock_redis,
        )

    assert result == JtiStatusResponse(active=True)
    mock_blacklist.is_revoked.assert_called_once_with("active-jti")


@pytest.mark.anyio
async def test_v1_revoked_returns_inactive() -> None:
    """Stateful mode, Redis available, JTI in blacklist → active=False."""
    mock_redis = MagicMock()
    mock_blacklist = MagicMock()
    mock_blacklist.is_revoked.return_value = True

    with (
        patch("auth_user_service.routes.private.settings") as mock_cfg,
        patch("auth_sdk_m8.security.AccessTokenBlacklist", return_value=mock_blacklist),
    ):
        mock_cfg.is_stateful = True
        result = await check_jti_status(
            body=JtiStatusRequest(jti="revoked-jti"),
            session=None,
            redis=mock_redis,
        )

    assert result == JtiStatusResponse(active=False)
    mock_blacklist.is_revoked.assert_called_once_with("revoked-jti")


# ── v2 subject-bound path ─────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_v2_unsupported_schema_version_is_generic_inactive() -> None:
    """A v2 request declaring an unsupported version fails closed, no disclosure."""
    result = await check_jti_status(
        body=_v2_request(schema_version="1"),
        session=None,
        redis=None,
    )
    assert isinstance(result, JtiStatusInactiveResponse)
    assert result.active is False


@pytest.mark.anyio
async def test_v2_missing_schema_version_is_generic_inactive() -> None:
    """A subject-bound request without a version is also refused (fail closed)."""
    result = await check_jti_status(
        body=_v2_request(schema_version=None),
        session=None,
        redis=None,
    )
    assert isinstance(result, JtiStatusInactiveResponse)


@pytest.mark.anyio
async def test_v2_non_stateful_active_echoes_generation() -> None:
    """Hybrid/stateless: token is expiry-bounded active, echoing the owner gen."""
    subject = uuid.uuid4()
    owner = MagicMock()
    owner.id = subject
    owner.auth_generation = 7
    session = MagicMock()
    session.get.return_value = owner

    with patch("auth_user_service.routes.private.settings") as mock_cfg:
        mock_cfg.is_stateful = False
        result = await check_jti_status(
            body=_v2_request(expected_user_id=subject),
            session=session,
            redis=None,
        )

    assert isinstance(result, JtiStatusActiveResponse)
    assert result.user_id == str(subject)
    assert result.auth_generation == 7


@pytest.mark.anyio
async def test_v2_non_stateful_unknown_subject_is_inactive() -> None:
    """Hybrid/stateless: a subject with no account cannot be vouched for."""
    session = MagicMock()
    session.get.return_value = None

    with patch("auth_user_service.routes.private.settings") as mock_cfg:
        mock_cfg.is_stateful = False
        result = await check_jti_status(
            body=_v2_request(),
            session=session,
            redis=None,
        )

    assert isinstance(result, JtiStatusInactiveResponse)


@pytest.mark.anyio
async def test_v2_non_stateful_db_unavailable_is_503() -> None:
    """Hybrid/stateless: an unreachable database is a 503, never a guess."""
    session = MagicMock()
    session.get.side_effect = SQLAlchemyError("db down")

    with patch("auth_user_service.routes.private.settings") as mock_cfg:
        mock_cfg.is_stateful = False
        with pytest.raises(HTTPException) as exc:
            await check_jti_status(
                body=_v2_request(),
                session=session,
                redis=None,
            )
    assert exc.value.status_code == 503


@pytest.mark.anyio
async def test_v2_stateful_decision_inactive_is_generic_inactive() -> None:
    """A stateful DB-inactive decision returns the generic inactive shape."""
    with (
        patch("auth_user_service.routes.private.settings") as mock_cfg,
        patch("auth_user_service.routes.private.GenerationController") as mock_ctrl,
    ):
        mock_cfg.is_stateful = True
        mock_ctrl.decide_jti_status.return_value = JtiStatusDecision(active=False)
        result = await check_jti_status(
            body=_v2_request(),
            session=MagicMock(),
            redis=None,
        )
    assert isinstance(result, JtiStatusInactiveResponse)


@pytest.mark.anyio
async def test_v2_stateful_active_redis_down_falls_back_to_db() -> None:
    """Redis unavailable falls back to the authoritative active DB decision."""
    subject = uuid.uuid4()
    with (
        patch("auth_user_service.routes.private.settings") as mock_cfg,
        patch("auth_user_service.routes.private.GenerationController") as mock_ctrl,
    ):
        mock_cfg.is_stateful = True
        mock_ctrl.decide_jti_status.return_value = JtiStatusDecision(
            active=True, user_id=subject, auth_generation=9
        )
        result = await check_jti_status(
            body=_v2_request(expected_user_id=subject),
            session=MagicMock(),
            redis=None,
        )
    assert isinstance(result, JtiStatusActiveResponse)
    assert result.user_id == str(subject)
    assert result.auth_generation == 9


@pytest.mark.anyio
async def test_v2_stateful_active_not_blacklisted_is_active() -> None:
    """An active DB decision with a clean blacklist stays active."""
    subject = uuid.uuid4()
    mock_blacklist = MagicMock()
    mock_blacklist.is_revoked.return_value = False
    with (
        patch("auth_user_service.routes.private.settings") as mock_cfg,
        patch("auth_user_service.routes.private.GenerationController") as mock_ctrl,
        patch("auth_sdk_m8.security.AccessTokenBlacklist", return_value=mock_blacklist),
    ):
        mock_cfg.is_stateful = True
        mock_ctrl.decide_jti_status.return_value = JtiStatusDecision(
            active=True, user_id=subject, auth_generation=3
        )
        result = await check_jti_status(
            body=_v2_request(jti="blk" + "j" * 13, expected_user_id=subject),
            session=MagicMock(),
            redis=MagicMock(),
        )
    assert isinstance(result, JtiStatusActiveResponse)
    assert result.auth_generation == 3


@pytest.mark.anyio
async def test_v2_stateful_active_but_blacklisted_is_inactive() -> None:
    """The Redis blacklist accelerator flips an otherwise-active decision."""
    subject = uuid.uuid4()
    mock_blacklist = MagicMock()
    mock_blacklist.is_revoked.return_value = True
    with (
        patch("auth_user_service.routes.private.settings") as mock_cfg,
        patch("auth_user_service.routes.private.GenerationController") as mock_ctrl,
        patch("auth_sdk_m8.security.AccessTokenBlacklist", return_value=mock_blacklist),
    ):
        mock_cfg.is_stateful = True
        mock_ctrl.decide_jti_status.return_value = JtiStatusDecision(
            active=True, user_id=subject, auth_generation=3
        )
        result = await check_jti_status(
            body=_v2_request(expected_user_id=subject),
            session=MagicMock(),
            redis=MagicMock(),
        )
    assert isinstance(result, JtiStatusInactiveResponse)


@pytest.mark.anyio
async def test_v2_stateful_db_unavailable_is_503() -> None:
    """A stateful decision over an unreachable database is a 503, never fail-open."""
    with (
        patch("auth_user_service.routes.private.settings") as mock_cfg,
        patch("auth_user_service.routes.private.GenerationController") as mock_ctrl,
    ):
        mock_cfg.is_stateful = True
        mock_ctrl.decide_jti_status.side_effect = SQLAlchemyError("db down")
        with pytest.raises(HTTPException) as exc:
            await check_jti_status(
                body=_v2_request(),
                session=MagicMock(),
                redis=None,
            )
    assert exc.value.status_code == 503


# ── model validation ─────────────────────────────────────────────────────────


def test_jti_status_request_rejects_empty_jti() -> None:
    """JtiStatusRequest must reject empty jti (min_length=1)."""
    with pytest.raises(Exception):
        JtiStatusRequest(jti="")


# ── private create_user validation (F8.2) ─────────────────────────────────────


def test_private_user_create_enforces_password_policy() -> None:
    """A sub-policy (<8 char) password is rejected at the schema boundary."""
    with pytest.raises(Exception):
        PrivateUserCreate(email="a@b.com", password="short", full_name="A")


def test_private_user_create_normalises_email() -> None:
    """Email is lowercased/stripped so the dup-check and stored value match."""
    model = PrivateUserCreate(
        email="  MixedCase@Example.COM ", password="goodpassword", full_name="A"
    )
    assert model.email == "mixedcase@example.com"


def test_create_user_rejects_duplicate_email() -> None:
    """An existing email yields 409 instead of a silent duplicate insert."""
    session = MagicMock()
    body = PrivateUserCreate(
        email="dup@example.com", password="goodpassword", full_name="Dup"
    )
    with patch("auth_user_service.routes.private.UserController") as mock_ctrl:
        mock_ctrl.get_user_by_email.return_value = object()  # already exists
        with pytest.raises(HTTPException) as exc:
            create_user(user_in=body, session=session)
    assert exc.value.status_code == 409
    session.add.assert_not_called()
    session.commit.assert_not_called()


def test_create_user_honours_is_verified_flag() -> None:
    """The accepted is_verified flag maps to email_verified (was dropped)."""
    session = MagicMock()
    body = PrivateUserCreate(
        email="new@example.com",
        password="goodpassword",
        full_name="New",
        is_verified=True,
    )
    with patch("auth_user_service.routes.private.UserController") as mock_ctrl:
        mock_ctrl.get_user_by_email.return_value = None
        create_user(user_in=body, session=session)

    created = session.add.call_args.args[0]
    assert created.email == "new@example.com"
    assert created.email_verified is True
    assert created.hashed_password is not None
    session.commit.assert_called_once()
