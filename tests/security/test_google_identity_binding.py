"""S1 — Google login binds to the provider identity and the account state.

Security invariant: *Google identity binds by ``sub``, never by email alone.*
Before S1 a Google login entered **any** account whose email matched the one
Google asserted (``N1``) and never checked ``is_active`` (``N2``). These tests
run the real resolution and exchange path against a database session; only the
Google token endpoint and Redis are stubbed.

Proofs (plan ``S1`` acceptance):

- PASSWORD account + Google login with the same email → refused;
- superuser target → refused;
- Google ``email_verified`` false or absent → refused;
- inactive or tombstoned account → refused;
- a different ``sub`` asserting a bound Google account's email → refused;
- existing Google users keep logging in, by ``sub``;
- every refusal is the same generic ``400``, audited and counted, and mints
  no token or session.
"""

from __future__ import annotations

import uuid
from typing import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from auth_sdk_m8.schemas.base import AuthProviderType

from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.tombstones import AuthTombstone
from auth_user_service.db_models.users import User
from auth_user_service.routes import google_auth
from auth_user_service.routes.google_auth import (
    _REFUSAL_DETAIL,
    _perform_oauth_exchange,
    _resolve_google_user,
)
from auth_user_service.schemas.google import OAuthGoogleToken

pytestmark = pytest.mark.security

_ROUTE = "auth_user_service.routes.google_auth"


def _token(
    *,
    email: str,
    sub: str,
    email_verified: bool | None = True,
) -> OAuthGoogleToken:
    return OAuthGoogleToken(
        access_token="goog-access",
        expires_in=3600,
        refresh_token="goog-refresh",
        user_id=sub,
        email=email,
        email_verified=email_verified,
        name="  Google Person  ",
        picture="https://example.com/p.png",
    )


def _new_email() -> str:
    return f"g_{uuid.uuid4().hex[:10]}@example.com"


@pytest.fixture
def metrics() -> Iterator[MagicMock]:
    m = MagicMock()
    with patch(f"{_ROUTE}._get_metrics", return_value=m):
        yield m


def _refused(session: Session, token: OAuthGoogleToken) -> HTTPException:
    with pytest.raises(HTTPException) as exc:
        _resolve_google_user(session, token)
    return exc.value


def _assert_generic_refusal(exc: HTTPException) -> None:
    assert exc.status_code == 400
    assert exc.detail == _REFUSAL_DETAIL


def _refusal_label(metrics: MagicMock) -> str:
    return metrics.oauth_attempts_total.labels.call_args.kwargs["result"]


# ── email collisions: no implicit linking (D-g) ──────────────────────────────


def test_password_account_email_is_refused(db_session, sample_user, metrics) -> None:
    exc = _refused(db_session, _token(email=sample_user.email, sub="sub-attacker"))

    _assert_generic_refusal(exc)
    assert _refusal_label(metrics) == "refused_email_in_use"
    db_session.refresh(sample_user)
    assert sample_user.provider == AuthProviderType.PASSWORD
    assert sample_user.oauth_user_id is None


def test_email_collision_is_case_insensitive(db_session, sample_user, metrics) -> None:
    """The asserted email is normalized before the collision lookup."""
    exc = _refused(
        db_session, _token(email=sample_user.email.upper(), sub="sub-attacker")
    )
    _assert_generic_refusal(exc)
    assert _refusal_label(metrics) == "refused_email_in_use"


def test_superuser_email_is_refused(db_session, superuser, metrics) -> None:
    exc = _refused(db_session, _token(email=superuser.email, sub="sub-attacker"))

    _assert_generic_refusal(exc)
    assert _refusal_label(metrics) == "refused_email_in_use"


def test_changed_sub_is_refused(db_session, google_user, metrics) -> None:
    """Another Google identity asserting a bound account's email never enters it."""
    original_sub = google_user.oauth_user_id
    exc = _refused(db_session, _token(email=google_user.email, sub="sub-other"))

    _assert_generic_refusal(exc)
    assert _refusal_label(metrics) == "refused_subject_mismatch"
    db_session.refresh(google_user)
    assert google_user.oauth_user_id == original_sub


# ── Google's own assertion ───────────────────────────────────────────────────


@pytest.mark.parametrize("verified", [False, None])
def test_unverified_google_email_creates_nothing(db_session, metrics, verified) -> None:
    email = _new_email()
    exc = _refused(
        db_session, _token(email=email, sub=f"sub-{email}", email_verified=verified)
    )

    _assert_generic_refusal(exc)
    assert _refusal_label(metrics) == "refused_email_unverified"
    assert db_session.exec(select(User).where(User.email == email)).first() is None


def test_unverified_google_email_cannot_enter_bound_account(
    db_session, google_user, metrics
) -> None:
    exc = _refused(
        db_session,
        _token(
            email=google_user.email,
            sub=google_user.oauth_user_id,
            email_verified=False,
        ),
    )
    _assert_generic_refusal(exc)
    assert _refusal_label(metrics) == "refused_email_unverified"


def test_missing_subject_is_refused(db_session, metrics) -> None:
    exc = _refused(db_session, _token(email=_new_email(), sub=""))
    _assert_generic_refusal(exc)
    assert _refusal_label(metrics) == "refused_subject_missing"


# ── account state ────────────────────────────────────────────────────────────


def test_inactive_google_account_is_refused(db_session, google_user, metrics) -> None:
    google_user.is_active = False
    db_session.add(google_user)
    db_session.commit()

    exc = _refused(
        db_session, _token(email=google_user.email, sub=google_user.oauth_user_id)
    )
    _assert_generic_refusal(exc)
    assert _refusal_label(metrics) == "refused_inactive"


def test_tombstoned_account_is_refused(db_session, google_user, metrics) -> None:
    db_session.add(AuthTombstone(user_id=google_user.id, terminal_generation=9))
    db_session.commit()

    exc = _refused(
        db_session, _token(email=google_user.email, sub=google_user.oauth_user_id)
    )
    _assert_generic_refusal(exc)
    assert _refusal_label(metrics) == "refused_tombstoned"


# ── legitimate Google users ──────────────────────────────────────────────────


def test_existing_google_user_keeps_logging_in(db_session, google_user) -> None:
    user = _resolve_google_user(
        db_session, _token(email=google_user.email, sub=google_user.oauth_user_id)
    )
    assert user.id == google_user.id


def test_bound_account_is_found_by_sub_not_email(db_session, google_user) -> None:
    """A Google user whose Google address changed still reaches their account."""
    user = _resolve_google_user(
        db_session, _token(email=_new_email(), sub=google_user.oauth_user_id)
    )
    assert user.id == google_user.id


def test_new_identity_provisions_a_bound_google_account(db_session) -> None:
    email = _new_email()
    sub = f"sub-{uuid.uuid4().hex}"

    user = _resolve_google_user(db_session, _token(email=email.upper(), sub=sub))

    assert user.email == email
    assert user.provider == AuthProviderType.GOOGLE
    assert user.oauth_user_id == sub
    assert user.email_verified is True
    assert user.full_name == "Google Person"
    assert user.hashed_password is None


# ── audit trail ──────────────────────────────────────────────────────────────


def test_refusal_is_logged_without_email_or_subject(
    db_session, sample_user, metrics, caplog
) -> None:
    with caplog.at_level("WARNING", logger=google_auth.logger.name):
        _refused(db_session, _token(email=sample_user.email, sub="sub-secret-123"))

    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "event=google_login.refused reason=email_in_use" in logged
    assert str(sample_user.id) in logged
    assert sample_user.email not in logged
    assert "sub-secret-123" not in logged


def test_every_refusal_is_indistinguishable(
    db_session, sample_user, google_user, metrics
) -> None:
    refusals = [
        _refused(db_session, _token(email=sample_user.email, sub="sub-a")),
        _refused(db_session, _token(email=google_user.email, sub="sub-b")),
        _refused(
            db_session,
            _token(email=_new_email(), sub="sub-c", email_verified=False),
        ),
    ]
    assert {(e.status_code, e.detail) for e in refusals} == {(400, _REFUSAL_DETAIL)}


# ── nothing is minted for a refused login ────────────────────────────────────


async def _exchange(session: Session, token: OAuthGoogleToken):
    with (
        patch(
            f"{_ROUTE}.OAuthController.get_google_access_token",
            new_callable=AsyncMock,
            return_value=token,
        ),
        patch(f"{_ROUTE}.AuthCodeStore"),
        patch(f"{_ROUTE}.OAuthSessionStore") as session_store,
        patch(f"{_ROUTE}.RedisRefreshStore") as refresh_store,
    ):
        response = await _perform_oauth_exchange(
            session,
            MagicMock(),
            "google-code",
            "verifier",
            "https://auth.example.com/user/google-auth/oauth-callback/",
            "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/cb.html",
            "challenge",
            "state-1",
        )
    return response, session_store, refresh_store


def _sessions_of(session: Session, user_id: uuid.UUID) -> list[ClientSession]:
    return list(
        session.exec(select(ClientSession).where(ClientSession.user_id == user_id))
    )


@pytest.mark.anyio
async def test_refused_exchange_mints_no_token_or_session(
    db_session, sample_user, metrics
) -> None:
    with patch(f"{_ROUTE}.AuthController.create_auth_tokens") as mint:
        with pytest.raises(HTTPException) as exc:
            await _exchange(
                db_session, _token(email=sample_user.email, sub="sub-attacker")
            )
    _assert_generic_refusal(exc.value)
    mint.assert_not_called()
    assert _sessions_of(db_session, sample_user.id) == []


@pytest.mark.anyio
async def test_inactive_exchange_mints_no_token_or_session(
    db_session, google_user, metrics
) -> None:
    google_user.is_active = False
    db_session.add(google_user)
    db_session.commit()

    with patch(f"{_ROUTE}.AuthController.create_auth_tokens") as mint:
        with pytest.raises(HTTPException):
            await _exchange(
                db_session,
                _token(email=google_user.email, sub=google_user.oauth_user_id),
            )
    mint.assert_not_called()
    assert _sessions_of(db_session, google_user.id) == []


@pytest.mark.anyio
async def test_bound_google_exchange_issues_a_google_session(
    db_session, google_user
) -> None:
    response, session_store, _ = await _exchange(
        db_session, _token(email=google_user.email, sub=google_user.oauth_user_id)
    )

    assert response.status_code == 307
    assert "#auth_code=" in response.headers["location"]
    session_store.return_value.delete.assert_called_once_with("state-1")
    [client_session] = _sessions_of(db_session, google_user.id)
    assert client_session.provider == AuthProviderType.GOOGLE


# ── HTTP surface: the refusal is a real 400, not a 500 ───────────────────────


@pytest.fixture
def app_client(db_session) -> Iterator[TestClient]:
    from auth_user_service.core.engine_sync import get_db
    from auth_user_service.main import app

    app.dependency_overrides[get_db] = lambda: db_session
    try:
        yield TestClient(app, raise_server_exceptions=False)
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_refused_callback_returns_generic_json_400(
    app_client, sample_user, metrics
) -> None:
    """The app's error handler must not turn the refusal into a 500 or redirect."""
    from auth_user_service.core.config import settings

    with (
        patch(f"{_ROUTE}.get_redis_client", return_value=MagicMock()),
        patch(
            f"{_ROUTE}._get_oauth_session",
            return_value={
                "pkce_verifier": "v",
                "redirect_target": "chrome-extension://x/cb.html",
                "code_challenge": "c",
            },
        ),
        patch(
            f"{_ROUTE}.OAuthController.get_google_access_token",
            new_callable=AsyncMock,
            return_value=_token(email=sample_user.email, sub="sub-attacker"),
        ),
    ):
        response = app_client.get(
            f"{settings.API_PREFIX}/google-auth/oauth-callback/",
            params={"code": "google-code", "state": "state-1"},
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert response.json() == {"detail": _REFUSAL_DETAIL}
    assert "set-cookie" not in response.headers
