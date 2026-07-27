"""Ownership preservation rules for category mutations (Phase 7, G7-5).

Ownership used to survive an edit only because ``CategoryUpdate`` happened to
omit ``owner_id``. It is enforced here instead, so nothing about it is
incidental:

* ``owner_id`` is never settable from a request body. ``CategoryCreate`` and
  ``CategoryUpdate`` forbid unknown fields, so a body carrying ``owner_id`` is
  rejected rather than silently dropped, and :func:`category_update_values`
  additionally strips every ownership key before an update reaches the row.
* An edit or a delete operates on the ``owner_id`` already persisted on the
  fetched row. No mutation path writes an ownership column.
* A cross-owner create is superadmin-only, takes an explicit
  ``target_owner_id`` that must resolve to an existing user at the issuer, and
  never defaults to the actor: omitting it creates a row owned by the actor,
  supplying it creates a row owned by that exact user, and no refusal or
  outage substitutes one id for the other.

The rules live here rather than in the route bodies so the transport layer
stays free of business logic and each rule is directly testable.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi_m8 import UserModel, has_superuser_privileges

from fastapi_full.core.user_directory import OwnerVerifier, UserDirectoryUnavailable
from fastapi_full.db_models.categories import CategoryUpdate

# Keys that carry ownership and may therefore never travel from a request body
# into a persisted row.
_OWNERSHIP_FIELDS = ("owner_id", "target_owner_id")


class OwnershipError(Exception):
    """Base error for a refused ownership resolution.

    Carries the canonical HTTP status the route maps it to, so the rules stay
    independent of FastAPI while the mapping remains a single line.
    """

    status_code = 403
    detail = "Ownership could not be resolved"


class CrossOwnerForbidden(OwnershipError):
    """A non-superadmin tried to create data owned by another user."""

    status_code = 403
    detail = "Only a canonical superuser can create data owned by another user"


class TargetOwnerNotFound(OwnershipError):
    """``target_owner_id`` does not resolve to an existing user."""

    status_code = 404
    detail = "target_owner_id does not resolve to an existing user"


class OwnerVerificationUnavailable(OwnershipError):
    """The target owner could not be confirmed with the auth service."""

    status_code = 503
    detail = "target_owner_id could not be verified with the auth service"


def is_canonical_superuser(actor: UserModel) -> bool:
    """Return the canonical dual-evidence superuser predicate for *actor*.

    Args:
        actor: The authenticated principal.

    Returns:
        ``True`` only for a consistent ``SUPERADMIN``/``is_superuser`` pair —
        never for a stray flag or a role on its own (§3.1, §3.3.1).
    """
    return has_superuser_privileges(actor.role, actor.is_superuser)


def resolve_create_owner_id(
    *,
    actor_id: uuid.UUID,
    actor_is_canonical_superuser: bool,
    target_owner_id: Optional[uuid.UUID],
    verify_owner_exists: Optional[OwnerVerifier] = None,
) -> uuid.UUID:
    """Resolve the ``owner_id`` a create may persist.

    The actor's id is returned only when the actor is the intended owner. Every
    other outcome either returns the explicitly requested owner or raises — the
    actor id is never substituted for a target that was refused, unknown, or
    unverifiable.

    Args:
        actor_id: The authenticated actor's id.
        actor_is_canonical_superuser: Result of the dual-evidence superuser
            predicate for the actor. An API-key-authorized caller passes
            ``False``: §3.11 caps every key decision at ``WRITER``.
        target_owner_id: The explicit cross-owner target, or ``None`` for a
            self-owned create.
        verify_owner_exists: Resolves the target against the issuer. Omitted
            on paths that never perform a cross-owner create.

    Returns:
        The owner id to persist.

    Raises:
        CrossOwnerForbidden: The actor is not a canonical superuser.
        TargetOwnerNotFound: The issuer does not know *target_owner_id*.
        OwnerVerificationUnavailable: No verifier is available, or the issuer
            could not be reached.
    """
    if target_owner_id is None or target_owner_id == actor_id:
        return actor_id
    if not actor_is_canonical_superuser:
        raise CrossOwnerForbidden()
    if verify_owner_exists is None:
        raise OwnerVerificationUnavailable()
    try:
        target_exists = verify_owner_exists(target_owner_id)
    except UserDirectoryUnavailable as ex:
        raise OwnerVerificationUnavailable() from ex
    if not target_exists:
        raise TargetOwnerNotFound()
    return target_owner_id


def category_update_values(item_in: CategoryUpdate) -> dict[str, Any]:
    """Return the fields an edit may write — never an ownership column.

    ``CategoryUpdate`` already forbids unknown fields, so an ``owner_id`` in a
    request body is rejected before this point. Stripping the ownership keys
    here as well keeps the guarantee true for any programmatic caller.

    Args:
        item_in: The validated update payload.

    Returns:
        The writable field values, with every ownership key removed.
    """
    values: dict[str, Any] = item_in.model_dump(exclude_unset=True)
    for field in _OWNERSHIP_FIELDS:
        values.pop(field, None)
    return values
