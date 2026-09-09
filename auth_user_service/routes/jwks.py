"""JWKS endpoint — exposes the current public key set for RS256/ES256."""

import json
from typing import Any

from fastapi import APIRouter

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


@router.get("/jwks.json", include_in_schema=True)
def jwks_endpoint() -> dict[str, Any]:
    """Return the active public key set in JWK Set format.

    Only meaningful when ``ACCESS_TOKEN_ALGORITHM`` is RS256 or ES256.

    Consumer services should point ``JWKS_URI`` at this endpoint and let
    ``build_access_validator`` wire up ``JwksKeyResolver`` automatically.
    """
    return build_key_set()
