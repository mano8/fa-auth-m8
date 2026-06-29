"""Short-TTL scoped service tokens (Phase 9.1, medium-term — issuer side).

The per-consumer bootstrap secret (see
:mod:`auth_user_service.core.consumer_registry`) is a long-lived credential that
rotates rarely. Rather than send it on every private call, a consumer exchanges
it once at ``{API_PREFIX}/private/v1/service-token`` for a **short-TTL scoped
service token** (OAuth client-credentials style) and presents that as
``Authorization: Bearer <token>`` on subsequent private calls. Rotation then
comes for free from the short TTL, while the blast radius stays bounded because
the bootstrap secret is per-consumer and scoped.

The token is a compact JWT that ``fa-auth-m8`` both issues and verifies — it
never leaves the issuer's trust domain — so it is signed symmetrically (HS256)
with the service-owned ``PRIVATE_API_SECRET``. A dedicated audience and a
``type=service`` claim keep it disjoint from user access/refresh tokens: a
service token can never be replayed on a user-facing route, nor vice versa.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt

#: ``aud`` claim isolating service tokens from user-facing access/refresh tokens.
SERVICE_TOKEN_AUDIENCE = "fa-auth-m8/internal-service"  # nosec B105 — audience claim value, not a secret
#: ``type`` claim; mirrors the "access"/"refresh" tagging on user tokens.
SERVICE_TOKEN_TYPE = "service"  # nosec B105 — claim name, not a secret
_ALGORITHM = "HS256"


class ServiceTokenError(Exception):
    """A service token is missing, malformed, mis-scoped at decode, or invalid."""


class ServiceTokenExpired(ServiceTokenError):
    """The presented service token has passed its ``exp``."""


@dataclass(frozen=True)
class ServiceTokenClaims:
    """The trusted claims carried by a verified service token."""

    client_id: str
    scopes: frozenset[str]


def issue_service_token(
    client_id: str,
    scopes: Iterable[str],
    *,
    signing_secret: str,
    ttl_seconds: int,
) -> tuple[str, int]:
    """Mint a short-TTL scoped service token for *client_id*.

    Args:
        client_id: The authenticated consumer id (becomes ``sub``).
        scopes: The scopes to grant the token (a subset of what the consumer's
            bootstrap credential holds — enforced by the caller).
        signing_secret: The HS256 signing key (the service ``PRIVATE_API_SECRET``).
        ttl_seconds: Token lifetime; also returned as ``expires_in``.

    Returns:
        ``(encoded_jwt, expires_in_seconds)``.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": client_id,
        "scope": " ".join(sorted(scopes)),
        "type": SERVICE_TOKEN_TYPE,
        "aud": SERVICE_TOKEN_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=ttl_seconds),
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, signing_secret, algorithm=_ALGORITHM)
    return token, ttl_seconds


def decode_service_token(token: str, *, signing_secret: str) -> ServiceTokenClaims:
    """Verify a service token and return its trusted claims.

    Raises:
        ServiceTokenExpired: The token is past ``exp``.
        ServiceTokenError: The token is malformed, has the wrong signature /
            audience, is not a ``service`` token, or omits a subject.
    """
    try:
        payload = jwt.decode(
            token,
            signing_secret,
            algorithms=[_ALGORITHM],
            audience=SERVICE_TOKEN_AUDIENCE,
            options={"require": ["exp", "sub", "aud"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise ServiceTokenExpired("service token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise ServiceTokenError("invalid service token") from exc

    if payload.get("type") != SERVICE_TOKEN_TYPE:
        raise ServiceTokenError("not a service token")
    subject = payload.get("sub")
    if not subject:
        raise ServiceTokenError("service token missing subject")
    scope_claim = payload.get("scope") or ""
    return ServiceTokenClaims(
        client_id=subject,
        scopes=frozenset(scope_claim.split()),
    )
