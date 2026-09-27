"""C2 — a disabled login method answers ``404 feature_unavailable`` and does no work.

``PASSWORD_LOGIN_ENABLED=false`` closes ``POST /login/access-token``, and
``GOOGLE_OAUTH_ENABLED=false`` closes every Google sign-in step, whatever the
client sends (contract §6, "Disabled feature ⇒ no route"). With the flags at
their defaults the routes behave as before.
"""

from collections.abc import Iterator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from auth_user_service.core.config import settings
from auth_user_service.schemas.account_lifecycle import AccountErrorCode

_UNAVAILABLE = {"detail": AccountErrorCode.FEATURE_UNAVAILABLE.value}


@pytest.fixture
def client(db_session) -> Iterator[TestClient]:
    from auth_user_service.core.deps import get_redis_client
    from auth_user_service.core.engine_sync import get_db
    from auth_user_service.main import app

    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_redis_client] = lambda: None
    try:
        yield TestClient(app, raise_server_exceptions=False)
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_redis_client, None)


def _login(client: TestClient):
    return client.post(
        f"{settings.API_PREFIX}/login/access-token",
        data={"username": "someone@example.com", "password": "Irrelevant1!"},
    )


def test_password_login_disabled_is_unavailable_before_any_work(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "PASSWORD_LOGIN_ENABLED", False)
    with (
        patch("auth_user_service.routes.login.AuthController.authenticate") as auth,
        patch("auth_user_service.routes.login._enforce_login_rate_limit") as limit,
    ):
        response = _login(client)
    assert response.status_code == 404
    assert response.json() == _UNAVAILABLE
    auth.assert_not_called()
    limit.assert_not_called()


def test_password_login_disabled_wins_over_a_malformed_body(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "PASSWORD_LOGIN_ENABLED", False)
    response = client.post(f"{settings.API_PREFIX}/login/access-token")
    assert response.status_code == 404
    assert response.json() == _UNAVAILABLE


def test_password_login_enabled_reaches_authentication(client: TestClient) -> None:
    assert settings.PASSWORD_LOGIN_ENABLED is True
    with (
        patch(
            "auth_user_service.routes.login.AuthController.authenticate",
            return_value=None,
        ) as auth,
        patch("auth_user_service.routes.login._enforce_login_rate_limit"),
    ):
        response = _login(client)
    assert response.status_code == 400
    auth.assert_called_once()


_GOOGLE_ROUTES = [
    ("get", "/google-api/login-url/"),
    ("post", "/google-api/exchange/"),
    ("get", "/google-auth/oauth-callback/?code=c&state=s"),
]


@pytest.mark.parametrize(("method", "path"), _GOOGLE_ROUTES)
def test_google_disabled_closes_every_google_step(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, method: str, path: str
) -> None:
    monkeypatch.setattr(settings, "GOOGLE_OAUTH_ENABLED", False)
    assert settings.GOOGLE_CLIENT_ID is not None  # credentials alone do not enable it
    with (
        patch("auth_user_service.routes.oauth_login.get_redis_client") as redis_a,
        patch("auth_user_service.routes.google_auth.get_redis_client") as redis_b,
    ):
        response = getattr(client, method)(f"{settings.API_PREFIX}{path}")
    assert response.status_code == 404
    assert response.json() == _UNAVAILABLE
    redis_a.assert_not_called()
    redis_b.assert_not_called()


def test_google_unset_with_credentials_stays_enabled(client: TestClient) -> None:
    assert settings.GOOGLE_OAUTH_ENABLED is None
    assert settings.google_login_enabled is True
    response = client.get(f"{settings.API_PREFIX}/google-api/login-url/")
    # Past the guard: the route's own validation answers, not feature_unavailable.
    assert response.json() != _UNAVAILABLE
