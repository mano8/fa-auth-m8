"""JWKS endpoint — exposes the current public key set for RS256/ES256."""

import hashlib
import json
from typing import Any, Optional

from fastapi import APIRouter, Request, Response

from auth_sdk_m8.schemas.auth import ASYMMETRIC_ALGORITHMS
from auth_user_service.core.config import settings
from auth_user_service.core.key_ids import derive_kid
from auth_user_service.services.auth import _resolve_kid

router = APIRouter(prefix="/.well-known", tags=["well-known"])


def _build_jwk(public_key_pem: str, algorithm: str, kid: str) -> dict[str, Any]:
    """Convert a PEM public key to a JWK dict with ``use``, ``alg``, and ``kid``."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from jwt.algorithms import ECAlgorithm, RSAAlgorithm

    key_obj = load_pem_public_key(public_key_pem.encode())
    alg_cls = ECAlgorithm if algorithm.startswith("ES") else RSAAlgorithm
    jwk: dict[str, Any] = json.loads(alg_cls.to_jwk(key_obj))  # type: ignore[arg-type]
    jwk["use"] = "sig"
    jwk["alg"] = algorithm
    jwk["kid"] = kid
    return jwk


def build_key_set() -> dict[str, Any]:
    """Assemble the published JWK Set.

    One JWK normally; two while a rotation overlap window is open
    (``ACCESS_PUBLIC_KEY_OLD_FILE`` set). The **current** key is always first,
    so a consumer that naively takes the first entry gets the signing key. The
    old key is verification-only — it is published so that access tokens issued
    before the rotation keep validating without a consumer restart, and is
    never a signing input.

    Returns an empty key set for symmetric (HS256) configurations — the shared
    secret must never be published.
    """
    algo = settings.ACCESS_TOKEN_ALGORITHM
    if algo not in ASYMMETRIC_ALGORITHMS or not settings.ACCESS_PUBLIC_KEY:
        return {"keys": []}

    keys = [_build_jwk(settings.ACCESS_PUBLIC_KEY, algo, _resolve_kid(algo) or "")]

    old_pem = settings.ACCESS_PUBLIC_KEY_OLD
    if old_pem:
        old_kid = (settings.ACCESS_KEY_ID_OLD or "").strip()
        keys.append(_build_jwk(old_pem, algo, old_kid or derive_kid(old_pem)))

    return {"keys": keys}


def _serialize_key_set(key_set: dict[str, Any]) -> bytes:
    """Serialize the key set deterministically, so the ETag is stable."""
    return json.dumps(
        key_set, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode()


def _matches_if_none_match(header: Optional[str], etag: str) -> bool:
    """Whether an ``If-None-Match`` header matches the current ETag.

    RFC 9110 §13.1.2: ``*`` matches any existing representation, and the
    comparison is *weak* — a validator sent back as ``W/"..."`` still matches
    the strong ETag it was issued from.
    """
    if not header:
        return False
    for candidate in header.split(","):
        candidate = candidate.strip()
        if candidate == "*":
            return True
        if candidate.startswith(("W/", "w/")):
            candidate = candidate[2:].strip()
        if candidate == etag:
            return True
    return False


@router.get(
    "/jwks.json",
    include_in_schema=True,
    responses={
        200: {"description": "The active JWK Set."},
        304: {"description": "The key set is unchanged (`If-None-Match` matched)."},
    },
)
def jwks_endpoint(request: Request) -> Response:
    """Return the active public key set in JWK Set format.

    Only meaningful when ``ACCESS_TOKEN_ALGORITHM`` is RS256 or ES256.

    Carries explicit freshness metadata (audit ``J4``): a ``Cache-Control``
    ``max-age`` matching the SDK's own ``JWKS_CACHE_TTL_SECONDS`` default, and a
    strong ``ETag`` over the serialized key set. The ETag changes exactly when
    the key set does — including when a rotation overlap window opens or closes
    — so a consumer can re-validate more often than its TTL for the cost of a
    ``304``, instead of every intermediary inventing its own freshness policy.

    Consumer services should point ``JWKS_URI`` at this endpoint and let
    ``build_access_validator`` wire up ``JwksKeyResolver`` automatically.
    """
    body = _serialize_key_set(build_key_set())
    etag = f'"{hashlib.sha256(body).hexdigest()}"'
    headers = {
        "Cache-Control": f"public, max-age={max(0, settings.JWKS_CACHE_TTL_SECONDS)}",
        "ETag": etag,
    }

    if _matches_if_none_match(request.headers.get("if-none-match"), etag):
        return Response(status_code=304, headers=headers)

    return Response(content=body, media_type="application/json", headers=headers)
