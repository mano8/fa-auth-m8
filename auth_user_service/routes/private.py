"""
Private API routes for inter-service user management.

These endpoints are NOT exposed to the public internet. They must be
protected at the network level (Docker internal network) AND require
the X-Internal-Token header to match PRIVATE_API_SECRET.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field, field_validator

from auth_sdk_m8.utils.email import normalize_email

from auth_user_service.core.config import settings
from auth_user_service.core.deps import (
    SessionDep,
    get_redis_client,
    verify_private_api_secret,
)
from auth_user_service.core.security import SecurityHelper
from auth_user_service.db_models.users import User, UserPublic
from auth_user_service.services.users import UserController

router = APIRouter(
    tags=["private"],
    prefix="/private",
    dependencies=[Depends(verify_private_api_secret)],
)


class JtiStatusRequest(BaseModel):
    """Request body for the inter-service JTI status check."""

    jti: str = Field(min_length=1)


class JtiStatusResponse(BaseModel):
    """Response for the inter-service JTI status check."""

    active: bool


class PrivateUserCreate(BaseModel):
    """Private Create user"""

    email: EmailStr
    # Mirror the public registration password policy (UserRegister): an
    # internal caller must not be able to seat a user with a sub-policy
    # password just because it holds PRIVATE_API_SECRET.
    password: str = Field(min_length=8, max_length=128)
    full_name: str
    is_verified: bool = False

    @field_validator("email", mode="before")
    @classmethod
    def _normalise_email(cls, v: str) -> str:
        """Lowercase/strip so the duplicate check and stored value match the
        public path's normalisation."""
        return normalize_email(v)


@router.post("/users/", response_model=UserPublic)
def create_user(user_in: PrivateUserCreate, session: SessionDep) -> Any:
    """
    Create a new user (internal service call only).

    Network isolation + PRIVATE_API_SECRET gate *who* may call this, but they
    do not validate the payload. We still enforce the same invariants as the
    public registration path — defence in depth so a compromised or buggy
    internal caller cannot create duplicate-email or weak-password accounts —
    and we honour the accepted ``is_verified`` flag (mapped to
    ``email_verified``) instead of silently dropping it.
    """
    existing = UserController.get_user_by_email(session=session, email=user_in.email)
    if existing:
        raise HTTPException(
            status_code=409,
            detail="The user with this email already exists in the system.",
        )
    user = User(
        email=user_in.email,
        full_name=user_in.full_name,
        email_verified=user_in.is_verified,
        hashed_password=SecurityHelper.get_password_hash(user_in.password),
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@router.post(
    "/v1/jti-status",
    response_model=JtiStatusResponse,
    include_in_schema=False,
)
async def check_jti_status(
    body: JtiStatusRequest,
    redis=Depends(get_redis_client),
) -> JtiStatusResponse:
    """Check whether a JTI has been blacklisted (inter-service use only).

    Only meaningful when TOKEN_MODE=stateful. In hybrid/stateless modes no
    access token blacklist exists — returns active=True immediately.
    When Redis is unavailable the response honours ACCESS_REVOCATION_FAILURE_MODE:
    fail_closed → active=False (token treated as revoked, consumer returns 503);
    fail_open → active=True (token passes, legacy behaviour).
    Consumer services call this instead of accessing auth Redis directly.
    """
    if not settings.is_stateful:
        return JtiStatusResponse(active=True)
    if redis is None:
        mode = settings.effective_failure_mode("access_revocation")
        return JtiStatusResponse(active=(mode != "fail_closed"))
    from auth_sdk_m8.security import AccessTokenBlacklist  # noqa: PLC0415

    return JtiStatusResponse(
        active=not AccessTokenBlacklist(redis).is_revoked(body.jti)
    )
