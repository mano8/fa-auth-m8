"""C1 — challenge tokens and M8 JWTs are separate families, and neither crosses.

Security invariant: *no JWT ↔ challenge-token cross-acceptance* (contract §4).
A challenge token presented to every M8 JWT validator — the SDK access
validator, the route dependency built on it, the refresh decoder, and the
private service-token decoder — is rejected; an access, refresh, or service
JWT, an API key, or another purpose's challenge presented to the challenge
parser is rejected. Each direction runs the real validator with the test
settings' real keys, and each has a positive control so a rejection cannot come
from a broken fixture.
"""

import uuid
from collections.abc import Callable
from datetime import timedelta

import pytest
from fastapi import HTTPException

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenAccessData, TokenMinimalData, TokenSecret
from auth_sdk_m8.security import build_access_validator

from auth_user_service.core.challenge_tokens import (
    ChallengePurpose,
    ChallengeTokenRejected,
    mint_challenge_token,
    parse_challenge_token,
)
from auth_user_service.core.config import settings
from auth_user_service.core.deps import get_current_user
from auth_user_service.core.security import SecurityHelper
from auth_user_service.services.api_keys import ApiKeyService
from auth_user_service.services.service_token import (
    ServiceTokenError,
    decode_service_token,
    issue_service_token,
)

pytestmark = pytest.mark.security

_ACCESS_SECRETS = TokenSecret(
    secret_key=settings.ACCESS_SECRET_KEY,
    algorithm=settings.ACCESS_TOKEN_ALGORITHM,
)
_REFRESH_SECRETS = TokenSecret(
    secret_key=settings.REFRESH_SECRET_KEY,
    algorithm=settings.REFRESH_TOKEN_ALGORITHM,
)
_SERVICE_SECRET = settings.PRIVATE_API_SECRET.get_secret_value()

_PURPOSES = list(ChallengePurpose)


def _challenge(purpose: ChallengePurpose) -> str:
    return mint_challenge_token(purpose).token.get_secret_value()


def _access_jwt() -> str:
    token, _ = SecurityHelper.create_access_token(
        data=TokenAccessData(
            sub=str(uuid.uuid4()),
            role="user",
            email="family@example.com",
            full_name="Family Test",
            is_superuser=False,
            is_active=True,
        ),
        expires_delta=timedelta(minutes=5),
        secrets=_ACCESS_SECRETS,
    )
    return token


def _refresh_jwt() -> str:
    token, _ = SecurityHelper.create_refresh_token(
        data=TokenMinimalData(sub=str(uuid.uuid4())),
        expires_delta=timedelta(minutes=5),
        secrets=_REFRESH_SECRETS,
    )
    return token


def _service_jwt() -> str:
    token, _ = issue_service_token(
        "family-consumer",
        ["jti-status"],
        signing_secret=_SERVICE_SECRET,
        ttl_seconds=60,
    )
    return token


def _api_key() -> str:
    plaintext, _ = ApiKeyService.generate_key()
    return plaintext


# ── challenge token → JWT validators ─────────────────────────────────────────


@pytest.mark.parametrize("purpose", _PURPOSES)
def test_sdk_access_validator_rejects_challenge(purpose: ChallengePurpose) -> None:
    validator = build_access_validator(settings)
    with pytest.raises(InvalidToken):
        validator.validate_access_token(_challenge(purpose))


@pytest.mark.parametrize("purpose", _PURPOSES)
def test_bearer_dependency_rejects_challenge(purpose: ChallengePurpose) -> None:
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(token=_challenge(purpose))
    assert exc_info.value.status_code == 403


@pytest.mark.parametrize("purpose", _PURPOSES)
def test_refresh_decoder_rejects_challenge(purpose: ChallengePurpose) -> None:
    with pytest.raises(InvalidToken):
        SecurityHelper.decode_refresh_token(_challenge(purpose), _REFRESH_SECRETS)


@pytest.mark.parametrize("purpose", _PURPOSES)
def test_service_token_decoder_rejects_challenge(purpose: ChallengePurpose) -> None:
    with pytest.raises(ServiceTokenError):
        decode_service_token(_challenge(purpose), signing_secret=_SERVICE_SECRET)


def test_jwt_validators_accept_their_own_family() -> None:
    """Positive control: the fixtures above are real, valid JWTs."""
    SecurityHelper.decode_refresh_token(_refresh_jwt(), _REFRESH_SECRETS)
    claims = decode_service_token(_service_jwt(), signing_secret=_SERVICE_SECRET)
    assert claims.client_id == "family-consumer"


# ── JWTs, API keys, other purposes → challenge parser ────────────────────────


@pytest.mark.parametrize("purpose", _PURPOSES)
@pytest.mark.parametrize(
    "foreign",
    [_access_jwt, _refresh_jwt, _service_jwt, _api_key],
    ids=["access-jwt", "refresh-jwt", "service-jwt", "api-key"],
)
def test_challenge_parser_rejects_other_families(
    purpose: ChallengePurpose, foreign: Callable[[], str]
) -> None:
    with pytest.raises(ChallengeTokenRejected):
        parse_challenge_token(foreign(), purpose)


@pytest.mark.parametrize("purpose", _PURPOSES)
def test_challenge_parser_rejects_prefixed_jwt(purpose: ChallengePurpose) -> None:
    """A JWT dressed in the right prefix is still not a challenge token."""
    with pytest.raises(ChallengeTokenRejected):
        parse_challenge_token(f"{purpose.prefix}{_access_jwt()}", purpose)


@pytest.mark.parametrize("issued", _PURPOSES)
@pytest.mark.parametrize("expected", _PURPOSES)
def test_challenge_is_bound_to_its_purpose(
    issued: ChallengePurpose, expected: ChallengePurpose
) -> None:
    token = _challenge(issued)
    if issued is expected:
        assert len(parse_challenge_token(token, expected)) == 64
        return
    with pytest.raises(ChallengeTokenRejected):
        parse_challenge_token(token, expected)
