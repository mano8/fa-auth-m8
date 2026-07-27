"""Issuer user-directory transport tests.

The directory is the only thing standing between "a superadmin typed a uuid"
and "a row is owned by that uuid", so every outcome that is not a definitive
yes or no has to fail closed, and the caller's token must never leak into an
error.
"""

from __future__ import annotations

import uuid
from typing import Optional

import httpx
import pytest
from fastapi_full.core.user_directory import (
    IssuerUserDirectory,
    UserDirectoryUnavailable,
    derive_user_directory_url,
)

BASE_URL = "http://auth_user_service:8000/user/users/get"
INTROSPECTION_URL = "http://auth_user_service:8000/user/private/v1/jti-status"
TOKEN = "header.payload.signature"  # a shape, not a credential
USER_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")


class _Settings:
    """Minimal stand-in for the consumer settings the directory reads."""

    def __init__(self, introspection_url: Optional[str]) -> None:
        self.INTROSPECTION_URL = introspection_url


def _directory(handler: httpx.MockTransport) -> IssuerUserDirectory:
    return IssuerUserDirectory(BASE_URL, transport=handler)


class TestDeriveUserDirectoryUrl:
    """The lookup URL is derived from the already-configured issuer URL."""

    def test_derives_from_the_jti_status_url(self) -> None:
        assert derive_user_directory_url(INTROSPECTION_URL) == BASE_URL

    def test_tolerates_a_trailing_slash(self) -> None:
        assert derive_user_directory_url(INTROSPECTION_URL + "/") == BASE_URL

    def test_appends_to_a_bare_issuer_base(self) -> None:
        assert (
            derive_user_directory_url("http://auth_user_service:8000/user") == BASE_URL
        )


class TestFromSettings:
    """A stateless deployment has no issuer URL and must fail closed."""

    def test_builds_the_derived_url(self) -> None:
        directory = IssuerUserDirectory.from_settings(
            _Settings(INTROSPECTION_URL)  # type: ignore[arg-type]
        )
        assert directory._base_url == BASE_URL

    def test_unconfigured_directory_refuses_every_lookup(self) -> None:
        directory = IssuerUserDirectory.from_settings(
            _Settings(None)  # type: ignore[arg-type]
        )
        with pytest.raises(UserDirectoryUnavailable) as exc_info:
            directory.user_exists(USER_ID, bearer_token=TOKEN)
        assert exc_info.value.reason == "user_directory_not_configured"


class TestUserExists:
    """Definitive answers only; everything else raises."""

    def test_existing_user_resolves(self) -> None:
        seen: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["authorization"] = request.headers["Authorization"]
            return httpx.Response(200, json={"id": str(USER_ID)})

        assert (
            _directory(httpx.MockTransport(handler)).user_exists(
                USER_ID, bearer_token=TOKEN
            )
            is True
        )
        assert seen["url"] == f"{BASE_URL}/{USER_ID}/"
        assert seen["authorization"] == f"Bearer {TOKEN}"

    def test_unknown_user_resolves_to_false(self) -> None:
        transport = httpx.MockTransport(lambda request: httpx.Response(404))
        assert _directory(transport).user_exists(USER_ID, bearer_token=TOKEN) is False

    @pytest.mark.parametrize("status_code", [401, 403, 429, 500, 503])
    def test_any_other_status_fails_closed(self, status_code: int) -> None:
        transport = httpx.MockTransport(lambda request: httpx.Response(status_code))
        with pytest.raises(UserDirectoryUnavailable) as exc_info:
            _directory(transport).user_exists(USER_ID, bearer_token=TOKEN)
        assert exc_info.value.reason == "user_directory_status"

    def test_a_redirect_is_not_followed(self) -> None:
        transport = httpx.MockTransport(
            lambda request: httpx.Response(302, headers={"Location": "http://evil"})
        )
        with pytest.raises(UserDirectoryUnavailable) as exc_info:
            _directory(transport).user_exists(USER_ID, bearer_token=TOKEN)
        assert exc_info.value.reason == "user_directory_status"

    def test_transport_failure_fails_closed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("boom", request=request)

        with pytest.raises(UserDirectoryUnavailable) as exc_info:
            _directory(httpx.MockTransport(handler)).user_exists(
                USER_ID, bearer_token=TOKEN
            )
        assert exc_info.value.reason == "user_directory_transport"

    def test_missing_bearer_token_fails_closed(self) -> None:
        transport = httpx.MockTransport(lambda request: httpx.Response(200))
        with pytest.raises(UserDirectoryUnavailable) as exc_info:
            _directory(transport).user_exists(USER_ID, bearer_token="")
        assert exc_info.value.reason == "bearer_token_missing"

    def test_errors_carry_no_secret(self) -> None:
        transport = httpx.MockTransport(lambda request: httpx.Response(500, text=TOKEN))
        with pytest.raises(UserDirectoryUnavailable) as exc_info:
            _directory(transport).user_exists(USER_ID, bearer_token=TOKEN)
        assert TOKEN not in str(exc_info.value)
        assert str(exc_info.value) == "user_directory_status"
