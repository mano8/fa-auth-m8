"""Tests for core.challenge_tokens — format, digest, and non-disclosure."""

import hashlib
import re

import pytest

from auth_user_service.core.challenge_tokens import (
    CHALLENGE_TOKEN_BODY_LENGTH,
    CHALLENGE_TTLS,
    ChallengePurpose,
    ChallengeTokenRejected,
    challenge_digest,
    mint_challenge_token,
    parse_challenge_token,
)

_PURPOSES = list(ChallengePurpose)


def test_prefixes_are_the_frozen_ones() -> None:
    assert {p: p.prefix for p in ChallengePurpose} == {
        ChallengePurpose.EMAIL_VERIFICATION: "m8vfy_",
        ChallengePurpose.PASSWORD_RESET: "m8rst_",
        ChallengePurpose.EMAIL_CHANGE: "m8eml_",
    }


@pytest.mark.parametrize("purpose", _PURPOSES)
def test_minted_token_shape_and_digest(purpose: ChallengePurpose) -> None:
    issued = mint_challenge_token(purpose)
    raw = issued.token.get_secret_value()
    assert issued.purpose is purpose
    assert re.fullmatch(
        f"{purpose.prefix}[A-Za-z0-9_-]{{{CHALLENGE_TOKEN_BODY_LENGTH}}}", raw
    )
    assert issued.digest == hashlib.sha256(raw.encode()).hexdigest()
    assert parse_challenge_token(raw, purpose) == issued.digest


def test_minted_tokens_are_unique() -> None:
    tokens = {
        mint_challenge_token(ChallengePurpose.PASSWORD_RESET).token.get_secret_value()
        for _ in range(64)
    }
    assert len(tokens) == 64


def test_raw_token_never_in_repr() -> None:
    issued = mint_challenge_token(ChallengePurpose.EMAIL_CHANGE)
    raw = issued.token.get_secret_value()
    assert raw not in repr(issued)
    assert raw not in str(issued)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "m8rst_",
        "m8rst_" + "A" * (CHALLENGE_TOKEN_BODY_LENGTH - 1),
        "m8rst_" + "A" * (CHALLENGE_TOKEN_BODY_LENGTH + 1),
        "m8rst_" + "A" * (CHALLENGE_TOKEN_BODY_LENGTH - 1) + ".",
        "m8rst_" + "A" * (CHALLENGE_TOKEN_BODY_LENGTH - 1) + "=",
        "m8rst_" + "A" * CHALLENGE_TOKEN_BODY_LENGTH + "\n",
        " m8rst_" + "A" * CHALLENGE_TOKEN_BODY_LENGTH,
        "M8RST_" + "A" * CHALLENGE_TOKEN_BODY_LENGTH,
        "m8rst_" + "é" * CHALLENGE_TOKEN_BODY_LENGTH,
    ],
    ids=[
        "empty",
        "prefix-only",
        "short",
        "long",
        "dot",
        "padding",
        "trailing-newline",
        "leading-space",
        "uppercase-prefix",
        "non-ascii",
    ],
)
def test_malformed_values_rejected(value: str) -> None:
    with pytest.raises(ChallengeTokenRejected):
        parse_challenge_token(value, ChallengePurpose.PASSWORD_RESET)


def test_rejection_does_not_echo_the_value() -> None:
    value = "m8rst_" + "A" * (CHALLENGE_TOKEN_BODY_LENGTH - 1)
    with pytest.raises(ChallengeTokenRejected) as exc_info:
        parse_challenge_token(value, ChallengePurpose.PASSWORD_RESET)
    assert value not in str(exc_info.value)


def test_digest_covers_the_prefix() -> None:
    body = "A" * CHALLENGE_TOKEN_BODY_LENGTH
    assert challenge_digest(f"m8vfy_{body}") != challenge_digest(f"m8rst_{body}")


def test_ttls_match_the_contract() -> None:
    hours = {
        purpose: (
            ttl.minimum.total_seconds() / 3600,
            ttl.default.total_seconds() / 3600,
            ttl.maximum.total_seconds() / 3600,
        )
        for purpose, ttl in CHALLENGE_TTLS.items()
    }
    assert hours == {
        ChallengePurpose.EMAIL_VERIFICATION: (0.25, 24, 24),
        ChallengePurpose.PASSWORD_RESET: (5 / 60, 0.5, 0.5),
        ChallengePurpose.EMAIL_CHANGE: (10 / 60, 1, 1),
    }
    for ttl in CHALLENGE_TTLS.values():
        assert ttl.minimum <= ttl.default <= ttl.maximum
