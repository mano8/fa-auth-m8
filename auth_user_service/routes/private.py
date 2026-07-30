"""
Private API routes for inter-service user management.

These endpoints are NOT exposed to the public internet. They must be
protected at the network level (Docker internal network) AND require a
per-consumer credential (``X-Internal-Client`` + ``X-Internal-Token``) or a
short-TTL service token, authorized against ``PRIVATE_API_CONSUMERS``. The legacy
single shared ``PRIVATE_API_SECRET`` gate has been retired.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Final, Optional, Union

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session

from auth_sdk_m8.core.exceptions import UnsupportedApiKeySchemaVersionError
from auth_sdk_m8.schemas.api_key import (
    ApiKeyIntrospectionActiveResponse,
    ApiKeyIntrospectionInactiveResponse,
    ApiKeyIntrospectionRequest,
    validate_api_key_introspection_schema_version,
)
from auth_sdk_m8.schemas.jti_status import (
    JTI_STATUS_SCHEMA_VERSION,
    JtiStatusActiveResponse,
    JtiStatusInactiveResponse,
)
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
    _apply_rate_limit,
    _handle_api_key_redis_degraded,
    authenticate_private_consumer,
    get_redis_client,
    require_private_scope,
    resolve_api_key_owner_principal,
)
from auth_user_service.core.security import SecurityHelper
from auth_user_service.db_models.api_keys import ApiKey
from auth_user_service.db_models.users import User, UserPublic
from auth_user_service.events import get_hub
from auth_user_service.services.api_keys import ApiKeyService
from auth_user_service.services.generation import GenerationController
from auth_user_service.services.service_token import issue_service_token
from auth_user_service.services.users import UserController

_logger = logging.getLogger(__name__)

# Each private route names the scope it needs (9.1, deny-by-default). The
# per-consumer registry is required — the legacy single-PRIVATE_API_SECRET gate is
# retired, so when no registry is configured these dependencies fail closed (see
# require_private_scope). The router carries no blanket gate so the service-token
# exchange route can authenticate the bootstrap credential itself.
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
    """Request body for the inter-service JTI status check.

    Two shapes are accepted during the contract-2.0 rollout, distinguished by
    whether the caller asserts the token subject:

    * **v1** — ``{jti}`` only, from a not-yet-upgraded consumer.
    * **v2** — additionally ``expected_user_id`` (the ``sub`` the caller already
      holds, making the request subject-bound) and the ``schema_version`` it
      speaks (3.5.2).
    """

    jti: str = Field(min_length=1)
    expected_user_id: Optional[uuid.UUID] = Field(
        default=None,
        description="v2 only: the token subject the caller asserts it holds.",
    )
    schema_version: Optional[str] = Field(
        default=None,
        description="v2 only: the JTI-status contract version the caller speaks.",
    )


class JtiStatusResponse(BaseModel):
    """Legacy v1 response for the inter-service JTI status check.

    The bare ``{active}`` shape returned to a v1 (non-subject-bound) request; it
    carries no ``auth_generation`` and never discloses a ``user_id``.
    """

    active: bool


class PrivateUserCreate(BaseModel):
    """Private Create user"""

    email: EmailStr
    # Mirror the public registration password policy (UserRegister): an
    # internal caller must not be able to seat a user with a sub-policy
    # password just because it holds the user-create scope.
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

    Network isolation + the per-consumer ``user-create`` scope gate *who* may
    call this, but they do not validate the payload. We still enforce the same
    invariants as the public registration path — defence in depth so a
    compromised or buggy internal caller cannot create duplicate-email or
    weak-password accounts — and we honour the accepted ``is_verified`` flag
    (mapped to ``email_verified``) instead of silently dropping it.
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


#: Bounded, secret-free detail for the fail-closed introspection 503.
_INTROSPECTION_UNAVAILABLE = "Introspection temporarily unavailable"

#: Bucket stamp for the fixed per-minute anti-abuse window, mirroring
#: ``RedisRateLimiter._BUCKET_FORMAT[Period.MINUTE]``. This is a Redis key
#: component, not a rendered date: it is deliberately fixed and locale-independent
#: so the same minute always maps to the same key on every host.
_ANTIABUSE_BUCKET_FORMAT: Final[str] = "%Y%m%d%H%M"


def _blacklist_hit(redis: Any, jti: str) -> bool:
    """Whether the Redis access-token blacklist contains *jti* (accelerator)."""
    from auth_sdk_m8.security import AccessTokenBlacklist  # noqa: PLC0415

    return AccessTokenBlacklist(redis).is_revoked(jti)


def _legacy_jti_status(jti: str, redis: Any) -> JtiStatusResponse:
    """The pre-2.0 v1 decision: Redis blacklist only, honouring the failure mode.

    Only meaningful when TOKEN_MODE=stateful. In hybrid/stateless modes no
    access-token blacklist exists, so the token is active. When Redis is
    unavailable the answer honours ``ACCESS_REVOCATION_FAILURE_MODE``:
    ``fail_closed`` → ``active=False`` (consumer returns 503), ``fail_open`` →
    ``active=True`` (legacy behaviour).
    """
    if not settings.is_stateful:
        return JtiStatusResponse(active=True)
    if redis is None:
        mode = settings.effective_failure_mode("access_revocation")
        return JtiStatusResponse(active=(mode != "fail_closed"))
    return JtiStatusResponse(active=not _blacklist_hit(redis, jti))


def _expiry_bounded_status(
    session: Session, subject: uuid.UUID
) -> Union[JtiStatusActiveResponse, JtiStatusInactiveResponse]:
    """Hybrid/stateless v2 answer: active until natural token expiry (3.6).

    Access-token revocation is not tracked in these modes, so a legitimately
    issued token stays active. The owner's current generation is echoed for
    cache tagging; a subject with no account cannot be vouched for and returns
    the generic inactive shape. An unreachable database is a ``503``.
    """
    try:
        owner = session.get(User, subject)
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_INTROSPECTION_UNAVAILABLE,
        ) from exc
    if owner is None:
        return JtiStatusInactiveResponse()
    return JtiStatusActiveResponse(
        user_id=str(owner.id), auth_generation=owner.auth_generation
    )


@router.post(
    "/v1/jti-status",
    response_model=None,
    include_in_schema=False,
    dependencies=[Depends(require_private_scope(ConsumerScope.INTROSPECTION))],
)
async def check_jti_status(
    body: JtiStatusRequest,
    session: SessionDep,
    redis=Depends(get_redis_client),
) -> Any:
    """Introspect an access-token JTI for consumer services (inter-service only).

    Two request shapes are accepted during the contract-2.0 rollout, distinguished
    by whether the caller asserts the token subject:

    * **v1** — ``{jti}`` only. Returns the legacy bare ``{active}`` body,
      consulting only the Redis access-token blacklist; no generation is
      disclosed.
    * **v2** — ``{jti, expected_user_id, schema_version: "2"}`` (3.5.2). In
      stateful mode the answer is the database-authoritative, subject-bound
      decision: tombstone → missing/revoked session → subject mismatch →
      missing/inactive/claim-inconsistent owner → stale generation → Redis
      blacklist, evaluated in order. Only a current session owned by the asserted
      subject behind a canonical, active, current-generation owner is ``active``
      — that response carries ``user_id`` and ``auth_generation`` for cache
      tagging. **Every** inactive cause returns the same generic ``{active:
      false}`` shape, so the endpoint is never an account-state or JTI-validity
      enumeration oracle. An unreachable authoritative database is a ``503`` — the
      generation decision never falls open (the legacy
      ``ACCESS_REVOCATION_FAILURE_MODE=fail_open`` escape applies only to the
      pre-2.0 blacklist accelerator). In hybrid/stateless modes an already-issued
      access token is expiry-bounded (3.6), so it stays active until expiry.

    Consumer services call this instead of accessing auth Redis directly.
    """
    if body.expected_user_id is None:
        return _legacy_jti_status(body.jti, redis)

    # v2 subject-bound. A request speaking an unsupported contract version is
    # refused with the same generic inactive shape (fail closed, no disclosure).
    if body.schema_version != JTI_STATUS_SCHEMA_VERSION:
        return JtiStatusInactiveResponse()

    if not settings.is_stateful:
        return _expiry_bounded_status(session, body.expected_user_id)

    try:
        decision = GenerationController.decide_jti_status(
            session, body.jti, body.expected_user_id
        )
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_INTROSPECTION_UNAVAILABLE,
        ) from exc

    if not decision.active:
        return JtiStatusInactiveResponse()
    # Redis blacklist is an accelerator: a hit revokes, but Redis being down
    # falls back to the authoritative DB decision that already vouched for the
    # session (3.5.4) — never a fail-open of the generation decision.
    if redis is not None and _blacklist_hit(redis, body.jti):
        return JtiStatusInactiveResponse()
    return JtiStatusActiveResponse(
        user_id=str(decision.user_id),
        auth_generation=decision.auth_generation,
    )


def _consume_introspection_antiabuse(redis: Any, consumer_id: str) -> None:
    """Consume the per-consumer anti-abuse allowance for introspection (§3.12 step 3).

    A fixed per-minute window keyed by the authenticated consumer id, consumed on
    **every** authenticated attempt (inactive keys included) and entirely separate
    from the introspected key's own functional quota (steps 11-12). Exhaustion is
    a ``429`` with ``Retry-After``. When Redis is unavailable this ceiling cannot
    be enforced, so it follows the same posture as key rate limiting: a
    strict/production deployment fails closed (``503``), non-strict development
    proceeds (logged unsafe). Labels stay bounded — only the registry-bounded
    consumer id, never a key hash or user id.
    """
    if redis is None:
        if settings.effective_api_key_strict_rate_limit:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=_INTROSPECTION_UNAVAILABLE,
            )
        _logger.warning(
            "introspect.antiabuse_unavailable decision=allow mode=fail_open consumer=%s",
            consumer_id,
        )
        return

    limit = settings.API_KEY_INTROSPECTION_ANTIABUSE_PER_MINUTE
    bucket = datetime.now(timezone.utc).strftime(_ANTIABUSE_BUCKET_FORMAT)
    key = f"introspect:antiabuse:{consumer_id}:{bucket}"
    with redis.pipeline() as pipe:
        pipe.incr(key)
        pipe.expire(key, 60)
        count, _ = pipe.execute()
    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Introspection rate limit exceeded",
            headers={"Retry-After": "60"},
        )


def _key_carries_audience(api_key: ApiKey, audience_id: str) -> bool:
    """Whether *api_key* is bound to *audience_id* (§3.12 steps 8-9, ``APIKEY-AUD-01``).

    The audience is the authenticated consumer's registry identity, never
    client-supplied. Audiences persist in the normalized ``api_key_audiences``
    relation; a key with **no** audience rows is issuer-local only, so a remote
    consumer's introspection is answered ``active: false`` — the documented
    fail-closed cutover (no existing key silently becomes a cross-service
    credential). Read defensively so a pre-Expand stand-in without the relation
    also carries none.
    """
    audiences = getattr(api_key, "audiences", None) or ()
    return any(getattr(a, "audience_id", None) == audience_id for a in audiences)


@router.post(
    "/v1/api-keys/introspect",
    response_model=None,
    include_in_schema=False,
)
async def introspect_api_key(
    body: ApiKeyIntrospectionRequest,
    request: Request,
    response: Response,
    session: SessionDep,
    redis: Any = Depends(get_redis_client),
) -> Any:
    """Resolve a user API key to its canonical live owner principal (§3.12).

    The distributed half of the API-key authorization rule: a service that is
    **not** ``fa-auth-m8`` holds only the opaque key and cannot share the issuer
    database, so it resolves the owner's **current** role here. Internal-caller
    authentication is kept strictly separate from the state of the key being
    inspected:

    * ``401`` — missing/invalid internal consumer credential.
    * ``403`` — valid credential lacking the dedicated ``API_KEY_INTROSPECTION``
      scope (distinct from ``INTROSPECTION`` so a JTI-status consumer is not
      implicitly granted key introspection).
    * ``200 {"active": false}`` — one generic shape for **every** unusable key:
      unknown/revoked/expired key, missing/inactive/claim-inconsistent owner, or
      an audience the key does not carry. The endpoint never returns ``401`` for
      an inactive key, so it is not an account-state or key-validity oracle.
    * ``200 {"active": true, ...}`` — the minimized canonical principal (owner's
      current role/superuser evidence ∩ the key's immutable access mode), with
      the derived ``audience_id`` and ``key_expires_at``; no ``is_active``, key
      hash, key id, or email is exposed.
    * ``429`` — the key's own functional quota is exhausted (or the per-consumer
      anti-abuse allowance), preserving ``Retry-After``.
    * ``503`` — authoritative DB unavailable, an unsupported requested schema
      version, or strict-Redis quota unavailability (never fail-open here).

    The processing order is normative (§3.12): authenticate consumer → verify
    scope → consume anti-abuse allowance → resolve key → check revocation/expiry
    → resolve owner live → check activity/consistency → derive audience from the
    consumer identity → verify the key carries it → compute the constrained
    principal → consume the key's functional quota → queue the ``last_used_at``
    write-behind → return. Inactive keys and audience mismatches consume the
    anti-abuse allowance but never the key's functional quota. The raw key is a
    :class:`~pydantic.SecretStr` and never appears in the URL, logs, traces, or
    error messages.
    """
    # 1-2. Authenticate the internal consumer for the dedicated scope; its
    # registry identity is the evaluated audience (never the request body).
    consumer_id = authenticate_private_consumer(
        request, ConsumerScope.API_KEY_INTROSPECTION
    )

    # A requested contract version this issuer does not implement is a 503 — it
    # never guesses at a contract (shared SDK fail-closed chokepoint).
    try:
        validate_api_key_introspection_schema_version(body.schema_version)
    except UnsupportedApiKeySchemaVersionError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_INTROSPECTION_UNAVAILABLE,
        ) from exc

    # 3. Consume the per-consumer anti-abuse allowance (before touching keys).
    _consume_introspection_antiabuse(redis, consumer_id)

    # 4-5. Resolve the presented key (hash lookup, revocation, expiry).
    try:
        api_key = ApiKeyService.get_active_key(session, body.api_key.get_secret_value())
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_INTROSPECTION_UNAVAILABLE,
        ) from exc
    if api_key is None:
        return ApiKeyIntrospectionInactiveResponse()

    # 6-7. Resolve the owner live and check activity/canonical consistency.
    try:
        principal = resolve_api_key_owner_principal(session, api_key)
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_INTROSPECTION_UNAVAILABLE,
        ) from exc
    if principal is None:
        return ApiKeyIntrospectionInactiveResponse()

    # 8-9. Derive the audience from the consumer identity and require the key to
    # carry it. No audience ⇒ issuer-local only ⇒ generic inactive remotely.
    if not _key_carries_audience(api_key, consumer_id):
        return ApiKeyIntrospectionInactiveResponse()

    # 10 is the principal above. 11-12. Consume the key's authoritative functional
    # quota and queue the last_used_at write-behind through the exact same chain
    # local auth uses (429/Retry-After + strict-Redis 503 parity with local auth).
    if redis is not None:
        _apply_rate_limit(redis, session, api_key, response)
    else:
        _handle_api_key_redis_degraded(api_key)

    # 13. Return the minimized canonical principal.
    return ApiKeyIntrospectionActiveResponse(
        audience_id=consumer_id,
        principal=principal,
        key_expires_at=api_key.expires_at,
    )


@router.get(
    "/v1/events/stream",
    include_in_schema=False,
    dependencies=[Depends(require_private_scope(ConsumerScope.EVENT_STREAM))],
)
async def event_stream(  # pragma: no cover
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

    Pre-existing SSE route, exercised only by tests/live (a unit-level ASGI
    client cannot drive a real streaming response) — not part of the new
    authorization-bearing contract surface this coverage gate now measures
    (3A-2).
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

    Requires the per-consumer model — when no ``PRIVATE_API_CONSUMERS`` registry
    is configured there is no per-consumer identity to mint against, so the
    exchange is disabled (``404``). The legacy single ``PRIVATE_API_SECRET`` gate
    has been retired, so a registry is the only supported private-API posture.
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
