"""
Private API routes for inter-service user management.

These endpoints are NOT exposed to the public internet. They must be
protected at the network level (Docker internal network) AND require
the X-Internal-Token header to match PRIVATE_API_SECRET.
"""

from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, EmailStr, Field, field_validator

from auth_sdk_m8.security.consumer_auth import (
    INTERNAL_CLIENT_HEADER,
    ConsumerAuthenticationError,
    ConsumerScope,
)
from auth_sdk_m8.security.guards import INTERNAL_TOKEN_HEADER
from auth_sdk_m8.utils.email import normalize_email

from auth_user_service.core.config import settings
from auth_user_service.core.consumer_registry import get_consumer_registry
from auth_user_service.core.deps import (
    SessionDep,
    get_redis_client,
    require_private_scope,
)
from auth_user_service.core.security import SecurityHelper
from auth_user_service.db_models.users import User, UserPublic
from auth_user_service.events import get_hub
from auth_user_service.services.service_token import issue_service_token
from auth_user_service.services.users import UserController

# Each private route names the scope it needs (9.1, deny-by-default). When no
# per-consumer registry is configured these dependencies transparently fall back
# to the legacy single-PRIVATE_API_SECRET gate (see require_private_scope). The
# router no longer carries a blanket gate so the service-token exchange route can
# authenticate the bootstrap credential itself.
router = APIRouter(tags=["private"], prefix="/private")


class ServiceTokenRequest(BaseModel):
    """Optional body for the service-token exchange.

    ``scopes`` lets a consumer narrow the minted token to a subset of what its
    bootstrap credential was granted (least privilege per call); omitted/empty
    mints a token carrying every granted scope.
    """

    scopes: Optional[list[str]] = None


class ServiceTokenResponse(BaseModel):
    """OAuth-client-credentials-style response for a minted service token."""

    access_token: str
    token_type: str = "bearer"  # noqa: S105 — OAuth token_type label, not a secret
    expires_in: int
    scope: str


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


@router.post(
    "/users/",
    response_model=UserPublic,
    dependencies=[Depends(require_private_scope(ConsumerScope.USER_CREATE))],
)
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
    dependencies=[Depends(require_private_scope(ConsumerScope.INTROSPECTION))],
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


@router.get(
    "/v1/events/stream",
    include_in_schema=False,
    dependencies=[Depends(require_private_scope(ConsumerScope.EVENT_STREAM))],
)
async def event_stream(
    last_event_id: Optional[str] = Header(default=None, alias="Last-Event-ID"),
) -> StreamingResponse:
    """Authenticated SSE stream of auth-state events (inter-service use only).

    Emits ``session-revoked`` / ``user-deleted`` frames so consumers can evict
    locally cached token-validation state ahead of natural expiry. Push is a
    best-effort accelerator — the JTI blacklist (``/private/v1/jti-status``)
    stays authoritative — so a consumer that never connects is still correct.

    Auth: requires the ``event-stream`` scope (per-consumer credential or a
    scoped service token; legacy single ``X-Internal-Token`` when no consumer
    registry is configured). Resume: pass ``Last-Event-ID`` to replay a buffered
    gap; an unresumable gap is signalled with an ``event: gap`` frame after
    which the consumer must flush its caches.
    """
    hub = get_hub()
    if hub is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Event stream disabled",
        )
    return StreamingResponse(
        hub.stream(last_event_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Disable proxy/buffering so frames flush immediately (nginx etc.).
            "X-Accel-Buffering": "no",
        },
    )


@router.post(
    "/v1/service-token",
    response_model=ServiceTokenResponse,
    include_in_schema=False,
)
def issue_service_token_route(
    request: Request,
    body: Optional[ServiceTokenRequest] = None,
) -> ServiceTokenResponse:
    """Exchange a per-consumer bootstrap credential for a short-TTL service token.

    The consumer authenticates with its ``X-Internal-Client`` +
    ``X-Internal-Token`` bootstrap credential and receives a short-lived JWT
    carrying the (optionally narrowed) subset of its granted scopes, to be
    presented as ``Authorization: Bearer <token>`` on subsequent private calls.
    Rotation comes from the short TTL; the bootstrap secret rotates rarely.

    Only available under the per-consumer model — when no ``PRIVATE_API_CONSUMERS``
    registry is configured the exchange is disabled (``404``): the legacy single
    ``PRIVATE_API_SECRET`` posture has no per-consumer identity to mint against.
    """
    registry = get_consumer_registry()
    if registry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service-token exchange not enabled",
        )
    try:
        credential = registry.authorize(
            request.headers.get(INTERNAL_CLIENT_HEADER),
            request.headers.get(INTERNAL_TOKEN_HEADER),
            None,
        )
    except ConsumerAuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        ) from exc

    granted = credential.scopes
    requested = frozenset(body.scopes) if body and body.scopes else granted
    # Deny-by-default: a token may only narrow, never widen, the granted scopes;
    # a consumer with no scopes has nothing to mint.
    if not requested or not requested <= granted:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    token, expires_in = issue_service_token(
        credential.client_id,
        requested,
        signing_secret=settings.PRIVATE_API_SECRET.get_secret_value(),
        ttl_seconds=settings.SERVICE_TOKEN_TTL_SECONDS,
    )
    return ServiceTokenResponse(
        access_token=token,
        expires_in=expires_in,
        scope=" ".join(sorted(requested)),
    )
