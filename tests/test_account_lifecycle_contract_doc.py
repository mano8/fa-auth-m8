"""The frozen account-lifecycle contract document stays in step with the code.

``docs/account-lifecycle-contract.md`` is the authority for the feature set;
the constants in code are its executable half. These checks fail when one moves
without the other, and keep the document standalone (no parent-checkout or
sibling path in a file this repository ships).
"""

from pathlib import Path

import pytest

from auth_user_service.core.challenge_tokens import CHALLENGE_TTLS, ChallengePurpose
from auth_user_service.core.service_meta import CONTRACT_RANGE, CONTRACT_VERSION
from auth_user_service.schemas.account_lifecycle import (
    CAPABILITIES_PATH,
    CAPABILITIES_VERSION,
    EMAIL_CHANGE_CONFIRM_PATH,
    PASSWORD_RESET_CONFIRM_PATH,
    PASSWORD_RESET_REQUEST_PATH,
    REGISTER_PATH,
    VERIFY_EMAIL_CONFIRM_PATH,
    VERIFY_EMAIL_REQUEST_PATH,
    AccountErrorCode,
)

_DOC = Path(__file__).resolve().parents[1] / "docs" / "account-lifecycle-contract.md"


@pytest.fixture(scope="module")
def doc() -> str:
    return _DOC.read_text(encoding="utf-8")


def _minutes(purpose: ChallengePurpose) -> tuple[int, int, int]:
    ttl = CHALLENGE_TTLS[purpose]
    return (
        int(ttl.minimum.total_seconds() // 60),
        int(ttl.default.total_seconds() // 60),
        int(ttl.maximum.total_seconds() // 60),
    )


def test_document_names_no_workspace_or_sibling_path(doc: str) -> None:
    for marker in (".workspace", "fa-workspace", "transmute", "../"):
        assert marker not in doc


def test_versions_match(doc: str) -> None:
    flat = " ".join(doc.split())
    assert f"Capability document version `{CAPABILITIES_VERSION}`" in flat
    assert f'`CONTRACT_VERSION` stays `"{CONTRACT_VERSION}"`' in flat
    assert f"`CONTRACT_RANGE` stays `{CONTRACT_RANGE}`" in flat


_TTL_SETTINGS = {
    ChallengePurpose.EMAIL_VERIFICATION: "EMAIL_VERIFICATION_TTL_MINUTES",
    ChallengePurpose.PASSWORD_RESET: "PASSWORD_RESET_TTL_MINUTES",
    ChallengePurpose.EMAIL_CHANGE: "EMAIL_CHANGE_TTL_MINUTES",
}


@pytest.mark.parametrize("purpose", list(ChallengePurpose))
def test_token_prefix_and_ttl_match_code(doc: str, purpose: ChallengePurpose) -> None:
    minimum, default, maximum = _minutes(purpose)
    assert f"| `{purpose.prefix}` |" in doc
    assert (
        f"| `{_TTL_SETTINGS[purpose]}` | `{default}` | {minimum} – {maximum}. |" in doc
    )


def test_routes_and_error_codes_are_documented(doc: str) -> None:
    for path in (
        CAPABILITIES_PATH,
        REGISTER_PATH,
        VERIFY_EMAIL_REQUEST_PATH,
        VERIFY_EMAIL_CONFIRM_PATH,
        PASSWORD_RESET_REQUEST_PATH,
        PASSWORD_RESET_CONFIRM_PATH,
        EMAIL_CHANGE_CONFIRM_PATH,
    ):
        assert f"`GET {path}`" in doc or f"`POST {path}`" in doc
    for code in AccountErrorCode:
        assert f"| `{code.value}` |" in doc
