"""Issuer-backed user directory lookup (transport layer).

A consumer service never reads the auth service's database: the user table is
owned by ``auth_user_service`` and every compose example gives the two services
separate databases. The only supported way to answer "does this user id exist?"
is the issuer's own HTTP contract, so this module calls its superadmin-gated
``GET {AUTH_PREFIX}/users/get/{user_id}/`` with the *caller's own* bearer token
— a lookup can therefore never see more than the caller already may.

Fail closed. A missing endpoint configuration, a missing token, a timeout, a
transport error, a redirect, or any unexpected status raises
:class:`UserDirectoryUnavailable`: an unconfirmable target owner never becomes
an owner. The error carries a bounded, secret-free reason code only — never the
bearer token, the target id, or the response body.
"""

from __future__ import annotations

import uuid
from typing import Callable, Optional

import httpx
from fastapi_m8 import ConsumerServiceSettings

# ``INTROSPECTION_URL`` points at ``…/private/v1/jti-status``; the user lookup
# lives at ``…/users/get/{user_id}/`` on the same host and API prefix. Mirrors
# fastapi-m8's ``derive_api_key_introspection_url`` so a consumer that already
# configures the issuer's base URL once need not repeat it.
_JTI_STATUS_SUFFIX = "/private/v1/jti-status"
_USER_LOOKUP_SUFFIX = "/users/get"

_OK = 200
_NOT_FOUND = 404

#: Resolves a user id to "this user exists at the issuer", or raises
#: :class:`UserDirectoryUnavailable`. Bound to a single request's bearer token
#: by ``core.deps.get_owner_verifier``.
OwnerVerifier = Callable[[uuid.UUID], bool]


class UserDirectoryUnavailable(RuntimeError):
    """Raised when a user id could not be confirmed with the issuer.

    Attributes:
        reason: A bounded, secret-free reason code safe to log.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def derive_user_directory_url(introspection_url: str) -> str:
    """Derive the issuer's user-lookup base URL from the JTI-status URL.

    Args:
        introspection_url: The configured ``INTROSPECTION_URL``.

    Returns:
        The ``…/users/get`` base URL on the same issuer host and API prefix.
    """
    url = introspection_url.rstrip("/")
    if url.endswith(_JTI_STATUS_SUFFIX):
        url = url[: -len(_JTI_STATUS_SUFFIX)]
    return url.rstrip("/") + _USER_LOOKUP_SUFFIX


class IssuerUserDirectory:
    """Resolve user ids against the issuer over its owned HTTP contract."""

    def __init__(
        self,
        base_url: Optional[str],
        *,
        connect_timeout: float = 2.0,
        read_timeout: float = 3.0,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        """Build a directory client.

        Args:
            base_url: The ``…/users/get`` base URL, or ``None`` when the issuer
                endpoint is not configured (every lookup then fails closed).
            connect_timeout: Connection timeout in seconds.
            read_timeout: Read timeout in seconds.
            transport: Optional httpx transport override (tests only).
        """
        self._base_url = base_url.rstrip("/") if base_url else None
        self._timeout = httpx.Timeout(read_timeout, connect=connect_timeout)
        self._transport = transport

    @classmethod
    def from_settings(cls, settings: ConsumerServiceSettings) -> "IssuerUserDirectory":
        """Build the directory from the consumer's configured issuer URL.

        Args:
            settings: This service's settings.

        Returns:
            A directory bound to the derived lookup URL, or one that fails
            closed when ``INTROSPECTION_URL`` is unset (stateless deployments).
        """
        introspection_url = settings.INTROSPECTION_URL
        base_url = (
            derive_user_directory_url(str(introspection_url))
            if introspection_url
            else None
        )
        return cls(base_url)

    def user_exists(self, user_id: uuid.UUID, *, bearer_token: str) -> bool:
        """Return whether *user_id* resolves to a user at the issuer.

        Args:
            user_id: The candidate owner id.
            bearer_token: The caller's raw access token, forwarded verbatim.

        Returns:
            ``True`` when the issuer returns the user, ``False`` when it
            answers ``404``.

        Raises:
            UserDirectoryUnavailable: On any outcome that is not a definitive
                yes or no — unconfigured endpoint, missing token, transport
                failure, or an unexpected status.
        """
        if self._base_url is None:
            raise UserDirectoryUnavailable("user_directory_not_configured")
        if not bearer_token:
            raise UserDirectoryUnavailable("bearer_token_missing")
        try:
            with httpx.Client(
                timeout=self._timeout,
                follow_redirects=False,
                transport=self._transport,
            ) as client:
                response = client.get(
                    f"{self._base_url}/{user_id}/",
                    headers={"Authorization": f"Bearer {bearer_token}"},
                )
        except httpx.HTTPError as ex:
            raise UserDirectoryUnavailable("user_directory_transport") from ex
        if response.status_code == _OK:
            return True
        if response.status_code == _NOT_FOUND:
            return False
        raise UserDirectoryUnavailable("user_directory_status")
