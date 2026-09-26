"""S1A (N20) — a failed Google token exchange never echoes its exception text.

``OAuthController.get_google_access_token`` used to answer with
``f"Token exchange failed: {ex}"`` / ``f"Authentication error: {ex}"``. The
client now gets fixed details; only the exception type and the upstream status
reach the server log. An ``HTTPException`` raised inside the exchange (a
missing ``id_token``) keeps its own status instead of being rewrapped as 500.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import HTTPException

from auth_user_service.services import oauth
from auth_user_service.services.oauth import OAuthController

pytestmark = pytest.mark.security

_LEAK = "secret-upstream-detail"


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _client_posting(post: AsyncMock) -> MagicMock:
    client = MagicMock()
    client.post = post
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=client)
    context.__aexit__ = AsyncMock(return_value=False)
    return MagicMock(return_value=context)


async def _exchange(post: AsyncMock) -> HTTPException:
    with patch.object(oauth.httpx, "AsyncClient", _client_posting(post)):
        with pytest.raises(HTTPException) as exc:
            await OAuthController.get_google_access_token(
                code="code", code_verifier="verifier", redirect_uri="https://a/cb"
            )
    return exc.value


def _response(*, status: int = 200, body: object = None) -> MagicMock:
    request = httpx.Request("POST", "https://oauth2.googleapis.com/token")
    response = MagicMock()
    response.status_code = status
    if status >= 400:
        response.raise_for_status.side_effect = httpx.HTTPStatusError(
            _LEAK, request=request, response=httpx.Response(status, request=request)
        )
    response.json.return_value = body
    return response


@pytest.mark.anyio
async def test_upstream_error_status_is_logged_not_returned(caplog) -> None:
    with caplog.at_level("WARNING", logger=oauth.logger.name):
        exc = await _exchange(AsyncMock(return_value=_response(status=401)))

    assert exc.status_code == 400
    assert exc.detail == "Token exchange with Google failed."
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "error=HTTPStatusError upstream_status=401" in logged
    assert _LEAK not in logged


@pytest.mark.anyio
async def test_transport_error_detail_is_fixed() -> None:
    exc = await _exchange(AsyncMock(side_effect=httpx.ConnectError(_LEAK)))

    assert exc.status_code == 400
    assert _LEAK not in str(exc.detail)


@pytest.mark.anyio
async def test_unexpected_error_detail_is_fixed(caplog) -> None:
    response = _response()
    response.json.side_effect = ValueError(_LEAK)

    with caplog.at_level("ERROR", logger=oauth.logger.name):
        exc = await _exchange(AsyncMock(return_value=response))

    assert exc.status_code == 500
    assert exc.detail == "Authentication error."
    assert _LEAK not in "\n".join(r.getMessage() for r in caplog.records)


@pytest.mark.anyio
async def test_missing_id_token_keeps_its_own_400() -> None:
    exc = await _exchange(AsyncMock(return_value=_response(body={"access_token": "a"})))

    assert exc.status_code == 400
    assert exc.detail == "Missing id_token in token response."
