"""Google OAuth token schemas"""

from typing import Optional

from pydantic import BaseModel


class OAuthGoogleToken(BaseModel):
    """
    Schema for Google OAuth token response data.
    """

    access_token: str
    expires_in: int
    refresh_token: str
    user_id: str
    email: str
    # Absent when Google did not assert the claim. Login refuses anything but an
    # explicit ``True`` (S1), so a missing claim must reach that refusal as
    # ``None`` rather than fail schema validation as a 500.
    email_verified: Optional[bool] = None
    name: str
    picture: str
