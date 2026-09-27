"""Account challenge tokens — the emailed, single-use token family.

Frozen by ``docs/account-lifecycle-contract.md`` §4. A challenge token is **not**
a JWT and never becomes one: it is 256 bits from ``secrets``, base64url-encoded
without padding, behind a public purpose prefix (``m8vfy_``, ``m8rst_``,
``m8eml_``). The prefix routes the token to its purpose; it is not a security
control. Only the SHA-256 digest of the whole token is ever stored, and the raw
value leaves :func:`mint_challenge_token` wrapped in a ``SecretStr`` so a stray
``repr``/log line cannot print it.

The format has no ``.``, so every JWT decoder rejects a challenge token as
malformed, and :func:`parse_challenge_token` accepts nothing but the exact
format of the expected purpose, so no JWT, API key, or other-purpose challenge
reaches a lookup. Storage, binding, expiry, and consumption belong to the
services that issue each purpose; this module only mints, parses, and digests.
"""

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum

from pydantic import SecretStr

#: Random bytes behind the prefix (256 bits).
CHALLENGE_TOKEN_BYTES = 32
#: Length of the unpadded base64url body for ``CHALLENGE_TOKEN_BYTES``.
CHALLENGE_TOKEN_BODY_LENGTH = 43


class ChallengePurpose(str, Enum):
    """What a challenge proves; each purpose has its own prefix and consumer."""

    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"  # nosec B105
    EMAIL_CHANGE = "email_change"

    @property
    def prefix(self) -> str:
        """Public token prefix for this purpose."""
        return _PREFIXES[self]


_PREFIXES: dict[ChallengePurpose, str] = {
    ChallengePurpose.EMAIL_VERIFICATION: "m8vfy_",
    ChallengePurpose.PASSWORD_RESET: "m8rst_",  # nosec B105
    ChallengePurpose.EMAIL_CHANGE: "m8eml_",
}

_BODY_PATTERN = f"[A-Za-z0-9_-]{{{CHALLENGE_TOKEN_BODY_LENGTH}}}"
_TOKEN_PATTERNS: dict[ChallengePurpose, re.Pattern[str]] = {
    purpose: re.compile(f"{re.escape(prefix)}{_BODY_PATTERN}")
    for purpose, prefix in _PREFIXES.items()
}


@dataclass(frozen=True)
class ChallengeTtl:
    """Default lifetime of one purpose and the bounds configuration may set."""

    default: timedelta
    minimum: timedelta
    maximum: timedelta


#: Contract §4 lifetimes. Configuration may move a TTL only inside its bounds.
CHALLENGE_TTLS: dict[ChallengePurpose, ChallengeTtl] = {
    ChallengePurpose.EMAIL_VERIFICATION: ChallengeTtl(
        default=timedelta(hours=24),
        minimum=timedelta(minutes=15),
        maximum=timedelta(hours=24),
    ),
    ChallengePurpose.PASSWORD_RESET: ChallengeTtl(
        default=timedelta(minutes=30),
        minimum=timedelta(minutes=5),
        maximum=timedelta(minutes=30),
    ),
    ChallengePurpose.EMAIL_CHANGE: ChallengeTtl(
        default=timedelta(hours=1),
        minimum=timedelta(minutes=10),
        maximum=timedelta(hours=1),
    ),
}


class ChallengeTokenRejected(ValueError):
    """The presented value is not a challenge token of the expected purpose.

    Carries no detail about *why*: every rejection maps to the one generic
    ``challenge_invalid`` response, and the value itself is never echoed.
    """


@dataclass(frozen=True)
class IssuedChallenge:
    """A freshly minted challenge: the raw token for the mail, the digest to store."""

    purpose: ChallengePurpose
    token: SecretStr = field(repr=False)
    digest: str


def mint_challenge_token(purpose: ChallengePurpose) -> IssuedChallenge:
    """Mint a new challenge token for *purpose* and its storage digest."""
    raw = f"{purpose.prefix}{secrets.token_urlsafe(CHALLENGE_TOKEN_BYTES)}"
    return IssuedChallenge(
        purpose=purpose, token=SecretStr(raw), digest=challenge_digest(raw)
    )


def parse_challenge_token(value: str, expected: ChallengePurpose) -> str:
    """Return the storage digest of *value* if it is an *expected* challenge token.

    Raises:
        ChallengeTokenRejected: *value* is not exactly a token of the expected
            purpose — a JWT, an API key, another purpose's token, or anything
            malformed.
    """
    if _TOKEN_PATTERNS[expected].fullmatch(value) is None:
        raise ChallengeTokenRejected()
    return challenge_digest(value)


def challenge_digest(raw: str) -> str:
    """SHA-256 hex digest of the whole token, prefix included — the stored form."""
    return hashlib.sha256(raw.encode("ascii")).hexdigest()
