"""Build the per-consumer credential registry from configuration (Phase 9.1).

The issuer side of 9.1 replaces the single shared ``PRIVATE_API_SECRET`` with a
**map of consumer ids → hashed, scoped per-consumer secrets**. The verification
primitives (hashing, constant-time compare, no-enumeration lookup, scope
enforcement) live in :mod:`auth_sdk_m8.security.consumer_auth`; this module only
turns the service's ``PRIVATE_API_CONSUMERS`` setting into a ready
:class:`~auth_sdk_m8.security.consumer_auth.ConsumerCredentialRegistry`.

Each configured secret is loaded by auto-detecting its form:

- ``sha256$<salt_hex>$<digest_hex>`` → the hashed-at-rest production form, loaded
  via :meth:`ConsumerCredential.from_encoded` (no plaintext ever touches the
  process beyond config parse time);
- anything else → a plaintext bootstrap secret (dev convenience), hashed on load
  via :meth:`ConsumerCredential.create`.

The built registry is cached per distinct configuration snapshot so the salted
digests are computed once, not per request; changing ``PRIVATE_API_CONSUMERS``
(e.g. in tests) yields a freshly built registry.
"""

from __future__ import annotations

from functools import lru_cache

from auth_sdk_m8.security.consumer_auth import (
    ConsumerCredential,
    ConsumerCredentialRegistry,
)

from auth_user_service.core.config import ConsumerCredentialConfig, settings

#: Prefix that marks a secret as the portable hashed form rather than plaintext.
_ENCODED_PREFIX = "sha256$"

#: One consumer as a hashable triple: (client_id, secret, sorted-scope-tuple).
_ConsumerSnapshot = tuple[str, str, tuple[str, ...]]


def _build_credential(client_id: str, secret: str, scopes: tuple[str, ...]):
    """Build one credential, auto-detecting the hashed-at-rest vs plaintext form."""
    if secret.startswith(_ENCODED_PREFIX):
        return ConsumerCredential.from_encoded(client_id, secret, scopes)
    return ConsumerCredential.create(client_id, secret, scopes)


@lru_cache(maxsize=8)
def _build_registry(
    snapshot: tuple[_ConsumerSnapshot, ...],
) -> ConsumerCredentialRegistry | None:
    """Build (and cache) a registry from a hashable configuration *snapshot*."""
    if not snapshot:
        return None
    return ConsumerCredentialRegistry(
        _build_credential(client_id, secret, scopes)
        for client_id, secret, scopes in snapshot
    )


def _snapshot(
    consumers: dict[str, ConsumerCredentialConfig],
) -> tuple[_ConsumerSnapshot, ...]:
    """Render the consumers mapping as a hashable, order-stable snapshot key."""
    return tuple(
        (client_id, cfg.secret.get_secret_value(), tuple(cfg.scopes))
        for client_id, cfg in sorted(consumers.items())
    )


def get_consumer_registry() -> ConsumerCredentialRegistry | None:
    """Return the configured registry, or ``None`` when no consumers are set.

    ``None`` signals the legacy single-``PRIVATE_API_SECRET`` posture to callers
    (homelab / back-compat); a registry signals the per-consumer model is active.
    """
    return _build_registry(_snapshot(settings.PRIVATE_API_CONSUMERS))
