"""
FastAPI authentication dependencies.

Provides token validation, current-user extraction, Redis connectivity,
and role/privilege guards for auth_user_service routes.
"""

import logging
from datetime import datetime, timezone
from typing import Annotated, Optional

from typing import Callable

from fastapi import Depends, Header, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer
from redis import ConnectionPool, Redis
from sqlmodel import Session, col, select

from auth_sdk_m8.authorization import (
    has_minimum_role,
    has_superuser_privileges,
    privilege_claims_are_consistent,
    validate_api_key_required_role,
)
from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.api_key import ApiKeyPrincipal
from auth_sdk_m8.schemas.base import ApiKeyAccessMode, RoleType
from auth_sdk_m8.schemas.user import UserModel
from auth_sdk_m8.security import (
    ValidationHooks,
    build_access_validator,
)
from auth_sdk_m8.security.consumer_auth import (
    INTERNAL_CLIENT_HEADER,
    ConsumerAuthenticationError,
    ConsumerScope,
    ConsumerScopeError,
)
from auth_sdk_m8.security.guards import INTERNAL_TOKEN_HEADER, extract_bearer_token

from auth_user_service.core.client import RedisSessionManager
from auth_user_service.core.config import settings
from auth_user_service.core.consumer_registry import get_consumer_registry
from auth_user_service.services.service_token import (
    ServiceTokenError,
    decode_service_token,
)
from auth_sdk_m8.observability.metrics import get as _get_metrics
from auth_user_service.core.engine_sync import SessionDep  # noqa: F401 (re-exported)
from auth_user_service.db_models.api_keys import ApiKey
from auth_user_service.db_models.users import User
from auth_user_service.services.api_keys import ApiKeyService, RateLimitEnforcer

# Redis hash key for write-behind last_used_at updates: field=key_id, value=ISO timestamp
LAST_USED_AT_HASH = "api_key:luat"

_logger = logging.getLogger(__name__)

reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_PREFIX}/login/access-token"
)
google_oauth2 = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_PREFIX}/google-auth/oauth-callback/"
)
TokenDep = Annotated[str, Depends(reusable_oauth2)]
GoogleTokenDep = Annotated[str, Depends(google_oauth2)]


class _LoggingHooks:
    """Emit structured log lines for every token validation outcome."""

    def on_success(self, *, jti: str, sub: str, token_type: str) -> None:
        _logger.info(  # nosec B106
            "event=token.valid type=%s sub=%s jti=%s ts=%s",
            token_type,
            sub,
            jti,
            datetime.now(timezone.utc).isoformat(),
        )

    def on_failure(self, *, reason: str, token_type: str) -> None:
        _logger.warning(  # nosec B106
            "event=token.invalid type=%s reason=%s ts=%s",
            token_type,
            reason,
            datetime.now(timezone.utc).isoformat(),
        )


_hooks: ValidationHooks = _LoggingHooks()

_redis_degraded_since: Optional[datetime] = None
_REDIS_CIRCUIT_BREAKER_SECS = 30
_REDIS_CONNECT_TIMEOUT_SECS = 2

_ssl_kwargs: dict[str, object] = (
    {
        "ssl": True,
        **({"ssl_ca_certs": settings.REDIS_SSL_CA} if settings.REDIS_SSL_CA else {}),
        **(
            {"ssl_certfile": settings.REDIS_SSL_CERT} if settings.REDIS_SSL_CERT else {}
        ),
        **({"ssl_keyfile": settings.REDIS_SSL_KEY} if settings.REDIS_SSL_KEY else {}),
    }
    if settings.REDIS_SSL
    else {}
)
_redis_pool: Optional[ConnectionPool] = ConnectionPool(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    username=settings.REDIS_USER,
    password=settings.REDIS_PASSWORD.get_secret_value() or None,
    decode_responses=True,
    socket_connect_timeout=_REDIS_CONNECT_TIMEOUT_SECS,
    socket_timeout=_REDIS_CONNECT_TIMEOUT_SECS,
    **_ssl_kwargs,  # type: ignore[arg-type]
)


# Module-level validator — created once at startup from validated settings.
# Secure-by-default (auth-sdk-m8 >= 1.0.0): TOKEN_STRICT_VALIDATION is on by
# default, so build_access_validator consumes the strict profile — it enforces
# iss/aud binding and pins the configured algorithm. CommonSettings' boot
# validators require TOKEN_ISSUER / TOKEN_AUDIENCE when strict, so there is no
# permissive "unset" path here; operators opt out of strictness for legacy
# deployments via TOKEN_STRICT_VALIDATION=false.
_access_validator = build_access_validator(settings, _hooks)


def get_redis_client() -> Optional[Redis]:
    """Return a Redis client from the shared pool, or None when unavailable.

    Circuit breaker: after the first failure, skips the ping for
    ``_REDIS_CIRCUIT_BREAKER_SECS`` seconds so that an unreachable Redis
    server does not add per-request latency. Resets on first successful ping.
    """
    global _redis_degraded_since
    if _redis_pool is None:
        return None
    if _redis_degraded_since is not None:
        elapsed = (datetime.now(timezone.utc) - _redis_degraded_since).total_seconds()
        if elapsed < _REDIS_CIRCUIT_BREAKER_SECS:
            return None
    try:
        client = Redis(connection_pool=_redis_pool)
        client.ping()
        _redis_degraded_since = None
        _m = _get_metrics()
        if _m and _m.redis_circuit_breaker_open:
            _m.redis_circuit_breaker_open.set(0)
        return client
    except Exception as exc:
        if _redis_degraded_since is None:
            _redis_degraded_since = datetime.now(timezone.utc)
        _logger.warning("redis.unavailable degraded_mode=true error=%s", exc)
        _m = _get_metrics()
        if _m and _m.redis_circuit_breaker_open:
            _m.redis_circuit_breaker_open.set(1)
        return None


def get_redis_degraded_since() -> Optional[datetime]:
    """Return the UTC timestamp when Redis first became unreachable, or None."""
    return _redis_degraded_since


RedisDep = Annotated[Optional[Redis], Depends(get_redis_client)]


def _check_jti_revocation(jti: str) -> None:
    """Raise HTTPException if the JTI is blacklisted or Redis is unavailable in fail-closed mode.

    Only called in stateful mode.
    """
    redis = get_redis_client()
    _m = _get_metrics()
    if redis is None:
        _mode = settings.effective_failure_mode("access_revocation")
        if _m and _m.degraded_decision_total:
            _m.degraded_decision_total.labels(
                control="access_revocation", mode=_mode, reason="redis_unavailable"
            ).inc()
        if _mode == "fail_closed":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service temporarily unavailable",
            )
        return
    if RedisSessionManager(redis).is_blacklisted(jti):
        if _m and _m.token_validation_failures_total:
            _m.token_validation_failures_total.labels(reason="revoked").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session revoked",
        )


def get_current_user(token: TokenDep) -> UserModel:
    """Validate the access token and return the authenticated user.

    Args:
        token: JWT string extracted from the Authorization header.

    Returns:
        Authenticated ``UserModel``.

    Raises:
        HTTPException 401: Token revoked (stateful mode only).
        HTTPException 403: Token invalid, expired, or user inactive.
    """
    try:
        payload = _access_validator.validate_access_token(token)
    except InvalidToken as ex:
        _m = _get_metrics()
        if _m and _m.token_validation_failures_total:
            _m.token_validation_failures_total.labels(reason="invalid").inc()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials.",
        ) from ex

    # JTI blacklist check only applies in stateful mode.
    # In hybrid mode, access tokens are stateless; only refresh JTIs are tracked.
    if settings.is_stateful:
        _check_jti_revocation(payload.jti)

    if not payload.is_active:
        _m = _get_metrics()
        if _m and _m.token_validation_failures_total:
            _m.token_validation_failures_total.labels(reason="inactive").inc()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )

    payload_dict = payload.model_dump(exclude={"exp", "jti", "type", "sub"})
    payload_dict["id"] = payload.sub
    return UserModel(**payload_dict)


CurrentUser = Annotated[UserModel, Depends(get_current_user)]


def get_current_active_admin(current_user: CurrentUser) -> UserModel:
    """Verify that the current user holds at least ADMIN role (§3.3.1).

    Authorized solely through the SDK's ``has_minimum_role`` role-hierarchy
    predicate on the JWT-authenticated user; ``is_superuser`` is never
    consulted for a role threshold, so the flag alone can never satisfy this
    guard. The issuer builds its own dependency surface and does not call
    fastapi-m8's ``build_auth_deps``, so this mirrors that framework's
    ``require_role(RoleType.ADMIN)`` guard directly against
    ``auth_user_service.core.deps.get_current_user`` — the issuer's existing
    per-request validation already re-checks the token and, in stateful mode,
    the JTI revocation state on every call, so there is no separate
    positive-cache path to bypass here.

    Raises:
        HTTPException 403: Role below ADMIN.
    """
    if not has_minimum_role(current_user.role, RoleType.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges",
        )
    return current_user


def get_current_active_superuser(current_user: CurrentUser) -> UserModel:
    """Verify that the current user holds superuser privileges.

    Authorization uses the canonical SDK dual-evidence predicate
    (``role == SUPERADMIN`` **and** ``is_superuser is True``); the
    ``is_superuser`` flag alone never grants access.

    Raises:
        HTTPException 403: Insufficient privileges.
    """
    if not has_superuser_privileges(current_user.role, current_user.is_superuser):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges",
        )
    return current_user


def authenticate_private_consumer(request: Request, scope: ConsumerScope | str) -> str:
    """Authenticate a private-route caller for *scope* and return its consumer id.

    Authorizes a private call by one of two paths and, on success, returns the
    **authenticated consumer's registry identity** (its ``client_id``) — the
    single source of truth for the caller's identity, used by the API-key
    introspection endpoint to derive the evaluated audience (never from the
    request body, §3.12):

    1. **Short-TTL service token** — an ``Authorization: Bearer <token>`` minted
       at ``/private/v1/service-token``. Verified and required to carry *scope*
       (``401`` invalid/expired, ``403`` missing scope). The identity is the
       token subject.
    2. **Per-consumer bootstrap credential** — ``X-Internal-Client`` +
       ``X-Internal-Token`` authorized against the registry for *scope*
       (``401`` unknown client / wrong secret — indistinguishable, no
       enumeration oracle; ``403`` authenticated but unscoped).

    The per-consumer registry (``PRIVATE_API_CONSUMERS``) is **required**: the
    legacy single shared ``PRIVATE_API_SECRET`` gate has been **retired**. When no
    registry is configured no caller can be authenticated, so every private call
    is denied (``401``, fail-closed) and startup logs the misconfiguration loudly.
    ``PRIVATE_API_SECRET`` itself stays — it signs the short-TTL service tokens and
    backs ``/health`` detail-gating + ``/metrics`` (1.4).

    The verification primitives are reused from ``auth-sdk-m8``; this is the
    issuer-side wiring plus the service-token branch.
    """
    registry = get_consumer_registry()
    if registry is None:
        # Legacy single-secret gate retired: with no per-consumer registry
        # there is no identity to authenticate against — deny by default.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )

    bearer = extract_bearer_token(request)
    if bearer is not None:
        try:
            claims = decode_service_token(
                bearer,
                signing_secret=settings.PRIVATE_API_SECRET.get_secret_value(),
            )
        except ServiceTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
            ) from exc
        if str(scope) not in claims.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden"
            )
        return claims.client_id

    try:
        credential = registry.authorize(
            request.headers.get(INTERNAL_CLIENT_HEADER),
            request.headers.get(INTERNAL_TOKEN_HEADER),
            scope,
        )
    except ConsumerScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden"
        ) from exc
    except ConsumerAuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        ) from exc
    return credential.client_id


def require_private_scope(
    scope: ConsumerScope | str,
) -> Callable[[Request], None]:
    """Build the private-route auth dependency for a required *scope* (9.1).

    A thin wrapper over :func:`authenticate_private_consumer` for routes that
    only need the gate, not the caller identity: it authenticates the consumer
    and discards the returned id. See that function for the full authorization
    contract and the retired-legacy-gate rationale.
    """

    def _dependency(request: Request) -> None:
        authenticate_private_consumer(request, scope)

    return _dependency


def _apply_rate_limit(
    redis: Redis,
    session: Session,
    api_key: ApiKey,
    response: Response,
) -> None:
    """Enforce rate limits and write X-RateLimit-* headers. Raises 429 if exceeded."""
    limits = ApiKeyService.get_limits(session, api_key.id, api_key.user_id)
    result = RateLimitEnforcer(redis, settings).enforce(api_key, limits)

    if not result.allowed:
        retry_after = 60
        if result.reset_at is not None:
            retry_after = max(
                1,
                int((result.reset_at - datetime.now(timezone.utc)).total_seconds()) + 1,
            )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for period: {result.exceeded_period}",
            headers={"Retry-After": str(retry_after)},
        )

    if result.limit is not None:
        response.headers["X-RateLimit-Limit"] = str(result.limit)
    if result.remaining is not None:
        response.headers["X-RateLimit-Remaining"] = str(result.remaining)
    if result.reset_at is not None:
        response.headers["X-RateLimit-Reset"] = str(int(result.reset_at.timestamp()))

    try:
        redis.hset(
            LAST_USED_AT_HASH,
            str(api_key.id),
            datetime.now(timezone.utc).isoformat(),
        )
    except Exception:
        ref = str(api_key.id)
        _logger.warning("luat.write_failed ref=%s", ref)


def _handle_api_key_redis_degraded(api_key: ApiKey) -> None:
    """Decide API-key admission when Redis rate limiting is unavailable.

    Strict posture (production, ``AUTH_STRICT_MODE``, ``STRICT_PRODUCTION_MODE``,
    or explicit ``API_KEY_STRICT_RATE_LIMIT``) fails closed with 503 so a valid
    key cannot be used without a rate-limit ceiling. Non-production, non-strict
    development fails open but the admission is logged as unsafe. Either way a
    ``degraded_decision_total`` metric sample is emitted. Never logs the raw key —
    only the opaque key id reference (plan 11.3).
    """
    strict = settings.effective_api_key_strict_rate_limit
    mode = "fail_closed" if strict else "fail_open"
    _m = _get_metrics()
    if _m and _m.degraded_decision_total:
        _m.degraded_decision_total.labels(
            control="api_key_rate_limit", mode=mode, reason="redis_unavailable"
        ).inc()
    ref = str(api_key.id)
    if strict:
        # nosec B106 — logfmt event line; ref is the opaque key id, not a secret.
        # Codacy/Opengrep also reads the template itself as a hardcoded secret
        # because it contains "api_key" (false positive, must be dismissed in the
        # Codacy UI — inline `nosemgrep` is not honored). It is a format string
        # and `ref` is the key's id.
        _logger.warning(
            "api_key.rate_limit_unavailable "  # nosec B106
            "decision=deny mode=fail_closed "  # nosec B106
            "ref=%s",  # nosec B106
            ref,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service unavailable",
        )
    # ref is the opaque key id, not a secret (same false positive as above)
    _logger.warning(
        "api_key.rate_limit_unavailable "  # nosec B106
        "decision=allow mode=fail_open "  # nosec B106
        "unsafe=true ref=%s",  # nosec B106
        ref,
    )  # nosec B106


def get_current_api_key(
    session: SessionDep,
    redis: RedisDep,
    response: Response,
    x_api_key: Annotated[str, Header(alias="X-API-Key")],
) -> ApiKey:
    """Validate an API key and enforce rate limits.

    Reads the ``X-API-Key`` header, validates the key, runs rate limit checks
    when Redis is available, and queues a write-behind ``last_used_at`` update.
    Sets ``X-RateLimit-*`` response headers when limits are enforced. When Redis
    is unavailable admission is decided by ``_handle_api_key_redis_degraded``:
    fail-closed (503) in production/strict, fail-open (logged) in development.

    Raises:
        HTTPException 401: Key missing, invalid, expired, or revoked.
        HTTPException 429: Rate limit exceeded (includes ``Retry-After`` header).
        HTTPException 503: Redis unavailable under strict/production posture.
    """
    api_key = ApiKeyService.get_active_key(session, x_api_key)
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
        )

    if redis is not None:
        _apply_rate_limit(redis, session, api_key, response)
    else:
        _handle_api_key_redis_degraded(api_key)

    return api_key


CurrentApiKey = Annotated[ApiKey, Depends(get_current_api_key)]


def resolve_api_key_owner_principal(
    session: Session, api_key: ApiKey
) -> Optional[ApiKeyPrincipal]:
    """Resolve an authenticated *api_key* to its canonical live owner principal,
    or ``None`` when the owner cannot vouch for the key.

    An API key stores no role — it is an opaque pointer to its owner — so a
    request is authorized as the owner, at the owner's **current** persisted
    role, and can never exceed it (3.11). The owner is loaded with a **fresh
    query** (``populate_existing`` — never a stale identity-map object); a
    missing, inactive, or claim-inconsistent owner yields ``None`` so the caller
    can render the **generic** rejection for its transport (the issuer-local
    dependency raises ``401``; the remote introspection endpoint answers
    ``active: false``) without ever disclosing another account's state.

    The returned :class:`ApiKeyPrincipal` is the SDK-owned canonical type shared
    by the local and remote paths, so both evaluate one identical object and
    cannot drift; it carries the owner's current ``auth_generation`` as evidence
    for this decision only.

    The key's immutable ``access_mode`` caps the principal (``APIKEY-MODE-01``).
    It is read live from the key; a stand-in without the attribute falls back to
    the most restrictive ``READ_ONLY``, so the surface always stays fail-closed.
    """
    owner = session.exec(
        select(User)
        .where(col(User.id) == api_key.user_id)
        .execution_options(populate_existing=True)
    ).first()
    if (
        owner is None
        or not owner.is_active
        or not privilege_claims_are_consistent(owner.role, owner.is_superuser)
    ):
        return None
    access_mode = getattr(api_key, "access_mode", ApiKeyAccessMode.READ_ONLY)
    return ApiKeyPrincipal(
        user_id=str(owner.id),
        role=owner.role,
        is_superuser=owner.is_superuser,
        access_mode=access_mode,
        auth_generation=owner.auth_generation,
    )


def _resolve_api_key_principal(session: Session, api_key: ApiKey) -> ApiKeyPrincipal:
    """Issuer-local variant of :func:`resolve_api_key_owner_principal`.

    Maps the ``None`` (owner cannot vouch) outcome onto the **generic**
    ``401 Invalid or expired API key`` response the local dependency surface
    uses, so an unknown/revoked/expired key and a missing/inactive/inconsistent
    owner are externally indistinguishable.
    """
    principal = resolve_api_key_owner_principal(session, api_key)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
        )
    return principal


def get_current_api_key_principal(
    api_key: CurrentApiKey,
    session: SessionDep,
) -> ApiKeyPrincipal:
    """Resolve the presented API key to the canonical live owner principal (3.11).

    Composes the existing :func:`get_current_api_key` authentication (hash /
    revoked / expiry validation + rate limiting) with a fresh owner load. This is
    the **base** active-principal dependency; a capability-bearing route MUST
    depend on a role dependency (:func:`require_api_key_role` and its
    ``reader``/``writer`` specializations), never on this bare principal —
    depending on it never implies any write capability.
    """
    return _resolve_api_key_principal(session, api_key)


CurrentApiKeyPrincipal = Annotated[
    ApiKeyPrincipal, Depends(get_current_api_key_principal)
]


def require_api_key_role(
    required_role: RoleType,
) -> Callable[[ApiKeyPrincipal], ApiKeyPrincipal]:
    """Build an API-key capability dependency for *required_role* (3.11).

    Authorizes through the **shared SDK capability check**
    (:meth:`ApiKeyPrincipal.has_capability`) evaluated on the owner's current
    claims and the key's immutable access mode — the *same* predicate the JWT
    guards and the remote introspection path use — so a key can never exceed its
    owner's current role and an owner downgrade takes effect on the key's next
    request. ``required_role`` is capped at ``WRITER``: an API key never carries
    administrative or superuser authority, so a higher requirement is a
    programming error the surface rejects at wiring time
    (:class:`ApiKeyCapabilityCeilingError`), not a routine denial. An owner whose
    role (or a read-only key on a write capability) is insufficient returns the
    standard 403.
    """
    validate_api_key_required_role(required_role)

    def _require_api_key_role(principal: CurrentApiKeyPrincipal) -> ApiKeyPrincipal:
        if not principal.has_capability(required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="The API key owner doesn't have enough privileges",
            )
        return principal

    return _require_api_key_role


# The only reusable specializations — reader and writer. There is deliberately
# no ``_admin``/``_superuser`` member: administrative and superuser operations
# are JWT-only (APIKEY-CAP-01 capability ceiling).
get_current_api_key_reader = require_api_key_role(RoleType.READER)
get_current_api_key_writer = require_api_key_role(RoleType.WRITER)
