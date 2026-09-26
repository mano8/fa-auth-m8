"""Manage add on auth."""

import logging
from google.oauth2 import id_token
from google.auth.transport import requests as googleRequests
import httpx
from fastapi import HTTPException

from auth_user_service.schemas.google import OAuthGoogleToken
from auth_user_service.core.config import settings

logger = logging.getLogger(__name__)

# Fixed client-facing details (S1A, N20): the exception text of a failed
# exchange never reaches the client.
_TOKEN_EXCHANGE_FAILED = "Token exchange with Google failed."
_AUTHENTICATION_ERROR = "Authentication error."


class OAuthController:
    """Manage add on auth."""

    @staticmethod
    async def get_google_access_token(
        code: str, code_verifier: str, redirect_uri: str
    ) -> OAuthGoogleToken:
        """
        get and verrify google access token from OAuth callback
        """
        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
            raise HTTPException(
                status_code=503, detail="Google OAuth is not configured."
            )
        token_request_uri = "https://oauth2.googleapis.com/token"  # nosec B105 - OAuth endpoint URL, not a credential
        data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID.get_secret_value(),
            "client_secret": settings.GOOGLE_CLIENT_SECRET.get_secret_value(),
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        }
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(token_request_uri, data=data)
                response.raise_for_status()
                token_data = response.json()

            if "id_token" not in token_data:
                raise HTTPException(
                    status_code=400, detail="Missing id_token in token response."
                )
            try:
                id_info = id_token.verify_oauth2_token(
                    token_data["id_token"],
                    googleRequests.Request(),
                    settings.GOOGLE_CLIENT_ID.get_secret_value(),
                    clock_skew_in_seconds=10,
                )
            except Exception as e:
                logger.warning("id_token verification error", exc_info=True)
                raise HTTPException(status_code=400, detail="Invalid id_token") from e

            return OAuthGoogleToken(
                access_token=token_data.get("access_token"),
                expires_in=token_data.get("expires_in"),
                refresh_token=token_data.get("refresh_token"),
                user_id=id_info.get("sub"),
                email=id_info.get("email"),
                email_verified=id_info.get("email_verified"),
                name=id_info.get("name"),
                picture=id_info.get("picture"),
            )
        except HTTPException:
            raise
        except httpx.HTTPStatusError as ex:
            # Only the type and upstream status are logged; the exception text
            # can carry the request, and nothing upstream reaches the client.
            logger.warning(
                "event=google_token_exchange.failed error=%s upstream_status=%d",
                type(ex).__name__,
                ex.response.status_code,
            )
            raise HTTPException(status_code=400, detail=_TOKEN_EXCHANGE_FAILED) from ex
        except httpx.HTTPError as ex:
            logger.warning(
                "event=google_token_exchange.failed error=%s upstream_status=-",
                type(ex).__name__,
            )
            raise HTTPException(status_code=400, detail=_TOKEN_EXCHANGE_FAILED) from ex
        except Exception as ex:
            logger.error(
                "event=google_token_exchange.error error=%s", type(ex).__name__
            )
            raise HTTPException(status_code=500, detail=_AUTHENTICATION_ERROR) from ex
