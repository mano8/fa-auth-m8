"""Tests for the introspection-audience eligibility helper (APIKEY-AUD-01).

``get_introspection_audiences`` returns only the registered consumers explicitly
granted the dedicated ``api-key-introspection`` scope — the exact set a key may be
bound to, so a leaked key can never be introspected by a consumer that was never
permitted to.
"""

from unittest.mock import patch

from auth_user_service.core.config import ConsumerCredentialConfig
from auth_user_service.core.consumer_registry import get_introspection_audiences


def _consumers(mapping):
    return {
        cid: ConsumerCredentialConfig(secret="s" * 12, scopes=scopes)
        for cid, scopes in mapping.items()
    }


def _patch_consumers(mapping):
    return patch(
        "auth_user_service.core.consumer_registry.settings.PRIVATE_API_CONSUMERS",
        _consumers(mapping),
    )


def test_only_api_key_introspection_scoped_consumers_returned():
    with _patch_consumers(
        {
            "prompt-engine-m8": ["api-key-introspection"],
            "jti-only-m8": ["introspection"],
            "multi-m8": ["event-stream", "api-key-introspection"],
        }
    ):
        assert get_introspection_audiences() == frozenset(
            {"prompt-engine-m8", "multi-m8"}
        )


def test_empty_when_no_eligible_consumer():
    with _patch_consumers({"jti-only-m8": ["introspection"]}):
        assert get_introspection_audiences() == frozenset()
