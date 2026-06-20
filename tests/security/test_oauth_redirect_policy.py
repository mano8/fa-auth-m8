"""Tests for 8.2 — OAuth redirect-prefix pinning enforcement.

Production/strict mode must reject chrome-extension:// redirects when
OAUTH_ALLOWED_REDIRECT_PREFIXES is empty (open public-client model).
In local/dev the setting is advisory — any extension ID is accepted.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from auth_user_service.routes.oauth_login import get_google_login_url

_VALID_CHALLENGE = "A" * 43
_EXT_ID = "abcdefghijklmnopqrstuvwxyzabcdef"
_VALID_EXT_REDIRECT = f"chrome-extension://{_EXT_ID}/callback.html"
_OTHER_EXT_REDIRECT = "chrome-extension://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/cb"


def _settings(**overrides):
    m = MagicMock()
    m.OAUTH_ALLOWED_REDIRECT_SCHEMES = ["chrome-extension://"]
    m.OAUTH_ALLOWED_REDIRECT_PREFIXES = []
    m.GOOGLE_OAUTH_REDIRECT_URI = ""
    m.ENVIRONMENT = "local"
    m.STRICT_PRODUCTION_MODE = False
    for k, v in overrides.items():
        setattr(m, k, v)
    return m


@pytest.fixture
def anyio_backend():
    return "asyncio"


class TestExtensionRedirectProductionPolicy:
    """In production/strict: empty OAUTH_ALLOWED_REDIRECT_PREFIXES → 400."""

    @pytest.mark.anyio
    async def test_unpinned_extension_redirect_rejected_in_production(self):
        s = _settings(ENVIRONMENT="production")
        with patch("auth_user_service.routes.oauth_login.settings", s):
            with pytest.raises(HTTPException) as exc:
                await get_google_login_url(
                    redirect_target=_VALID_EXT_REDIRECT,
                    code_challenge=_VALID_CHALLENGE,
                )
        assert exc.value.status_code == 400
        assert "OAUTH_ALLOWED_REDIRECT_PREFIXES" in exc.value.detail

    @pytest.mark.anyio
    async def test_unpinned_extension_redirect_rejected_in_strict_mode(self):
        s = _settings(ENVIRONMENT="local", STRICT_PRODUCTION_MODE=True)
        with patch("auth_user_service.routes.oauth_login.settings", s):
            with pytest.raises(HTTPException) as exc:
                await get_google_login_url(
                    redirect_target=_VALID_EXT_REDIRECT,
                    code_challenge=_VALID_CHALLENGE,
                )
        assert exc.value.status_code == 400
        assert "OAUTH_ALLOWED_REDIRECT_PREFIXES" in exc.value.detail

    @pytest.mark.anyio
    async def test_unpinned_extension_redirect_rejected_in_staging(self):
        s = _settings(ENVIRONMENT="staging")
        with patch("auth_user_service.routes.oauth_login.settings", s):
            with pytest.raises(HTTPException) as exc:
                await get_google_login_url(
                    redirect_target=_VALID_EXT_REDIRECT,
                    code_challenge=_VALID_CHALLENGE,
                )
        assert exc.value.status_code == 400
        assert "OAUTH_ALLOWED_REDIRECT_PREFIXES" in exc.value.detail

    @pytest.mark.anyio
    async def test_pinned_extension_redirect_passes_prefix_check_in_production(self):
        """Matching prefix in production passes the prefix gate (may fail later on deps)."""
        prefix = f"chrome-extension://{_EXT_ID}/"
        s = _settings(
            ENVIRONMENT="production",
            OAUTH_ALLOWED_REDIRECT_PREFIXES=[prefix],
        )
        with patch("auth_user_service.routes.oauth_login.settings", s):
            # _validate_redirect_target must NOT raise the pinning error.
            # The route may still raise from missing Redis/Google deps — that is fine.
            try:
                await get_google_login_url(
                    redirect_target=_VALID_EXT_REDIRECT,
                    code_challenge=_VALID_CHALLENGE,
                )
            except HTTPException as exc:
                assert "OAUTH_ALLOWED_REDIRECT_PREFIXES" not in exc.detail
            except Exception:
                pass  # non-HTTP errors from missing deps are expected

    @pytest.mark.anyio
    async def test_non_matching_prefix_rejected_in_production(self):
        prefix = f"chrome-extension://{_EXT_ID}/"
        s = _settings(
            ENVIRONMENT="production",
            OAUTH_ALLOWED_REDIRECT_PREFIXES=[prefix],
        )
        with patch("auth_user_service.routes.oauth_login.settings", s):
            with pytest.raises(HTTPException) as exc:
                await get_google_login_url(
                    redirect_target=_OTHER_EXT_REDIRECT,
                    code_challenge=_VALID_CHALLENGE,
                )
        assert exc.value.status_code == 400
        assert "allowed prefixes" in exc.value.detail


class TestExtensionRedirectLocalPolicy:
    """In local/dev: empty OAUTH_ALLOWED_REDIRECT_PREFIXES is allowed (open model)."""

    @pytest.mark.anyio
    async def test_unpinned_extension_redirect_allowed_in_local(self):
        """Local mode with no prefix list passes redirect validation."""
        s = _settings(ENVIRONMENT="local")
        with patch("auth_user_service.routes.oauth_login.settings", s):
            # Should not raise 400 from the pinning check;
            # may raise later from missing Google/Redis deps.
            try:
                await get_google_login_url(
                    redirect_target=_VALID_EXT_REDIRECT,
                    code_challenge=_VALID_CHALLENGE,
                )
            except HTTPException as exc:
                assert "OAUTH_ALLOWED_REDIRECT_PREFIXES" not in exc.detail

    @pytest.mark.anyio
    async def test_unpinned_extension_redirect_allowed_in_development(self):
        s = _settings(ENVIRONMENT="development")
        with patch("auth_user_service.routes.oauth_login.settings", s):
            try:
                await get_google_login_url(
                    redirect_target=_VALID_EXT_REDIRECT,
                    code_challenge=_VALID_CHALLENGE,
                )
            except HTTPException as exc:
                assert "OAUTH_ALLOWED_REDIRECT_PREFIXES" not in exc.detail
