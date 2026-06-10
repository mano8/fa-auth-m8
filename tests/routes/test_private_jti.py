"""Tests for the /private/v1/jti-status endpoint — 100% branch coverage."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from auth_user_service.routes.private import (
    JtiStatusRequest,
    JtiStatusResponse,
    PrivateUserCreate,
    check_jti_status,
    create_user,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ── check_jti_status branches ─────────────────────────────────────────────────


@pytest.mark.anyio
async def test_jti_status_non_stateful_returns_active() -> None:
    """Non-stateful mode skips Redis and returns active=True immediately."""
    with patch("auth_user_service.routes.private.settings") as mock_cfg:
        mock_cfg.is_stateful = False
        result = await check_jti_status(
            body=JtiStatusRequest(jti="some-jti"),
            redis=None,
        )
    assert result == JtiStatusResponse(active=True)


@pytest.mark.anyio
async def test_jti_status_redis_unavailable_fail_open_returns_active() -> None:
    """Redis unavailable (None) in stateful + fail_open mode → active=True."""
    with patch("auth_user_service.routes.private.settings") as mock_cfg:
        mock_cfg.is_stateful = True
        mock_cfg.effective_failure_mode.return_value = "fail_open"
        result = await check_jti_status(
            body=JtiStatusRequest(jti="some-jti"),
            redis=None,
        )
    assert result == JtiStatusResponse(active=True)


@pytest.mark.anyio
async def test_jti_status_redis_unavailable_fail_closed_returns_inactive() -> None:
    """Redis unavailable (None) in stateful + fail_closed mode → active=False."""
    with patch("auth_user_service.routes.private.settings") as mock_cfg:
        mock_cfg.is_stateful = True
        mock_cfg.effective_failure_mode.return_value = "fail_closed"
        result = await check_jti_status(
            body=JtiStatusRequest(jti="some-jti"),
            redis=None,
        )
    assert result == JtiStatusResponse(active=False)


@pytest.mark.anyio
async def test_jti_status_not_revoked_returns_active() -> None:
    """Stateful mode, Redis available, JTI not in blacklist → active=True."""
    mock_redis = MagicMock()
    mock_blacklist = MagicMock()
    mock_blacklist.is_revoked.return_value = False

    with (
        patch("auth_user_service.routes.private.settings") as mock_cfg,
        # Patch where imported at runtime (deferred import inside function body)
        patch("auth_sdk_m8.security.AccessTokenBlacklist", return_value=mock_blacklist),
    ):
        mock_cfg.is_stateful = True
        result = await check_jti_status(
            body=JtiStatusRequest(jti="active-jti"),
            redis=mock_redis,
        )

    assert result == JtiStatusResponse(active=True)
    mock_blacklist.is_revoked.assert_called_once_with("active-jti")


@pytest.mark.anyio
async def test_jti_status_revoked_returns_inactive() -> None:
    """Stateful mode, Redis available, JTI in blacklist → active=False."""
    mock_redis = MagicMock()
    mock_blacklist = MagicMock()
    mock_blacklist.is_revoked.return_value = True

    with (
        patch("auth_user_service.routes.private.settings") as mock_cfg,
        # Patch where imported at runtime (deferred import inside function body)
        patch("auth_sdk_m8.security.AccessTokenBlacklist", return_value=mock_blacklist),
    ):
        mock_cfg.is_stateful = True
        result = await check_jti_status(
            body=JtiStatusRequest(jti="revoked-jti"),
            redis=mock_redis,
        )

    assert result == JtiStatusResponse(active=False)
    mock_blacklist.is_revoked.assert_called_once_with("revoked-jti")


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
    with patch(
        "auth_user_service.routes.private.UserController"
    ) as mock_ctrl:
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
