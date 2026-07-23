"""API key management endpoints.

CRUD operations under /profile/api-keys — all require an authenticated user.
Key creation returns the plaintext once; subsequent reads show only metadata.
GET /verify accepts X-API-Key directly and enforces rate limits (no JWT needed).
"""

# pylint: disable=broad-exception-caught

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlmodel import Field, col, select

from auth_sdk_m8.controllers.base import BaseController
from auth_sdk_m8.models.shared import Message
from auth_sdk_m8.observability import metrics as _metrics
from auth_sdk_m8.schemas.user import UserModel
from auth_user_service.core.config import settings
from auth_user_service.core.deps import (
    CurrentApiKey,
    CurrentUser,
    SessionDep,
    get_current_active_superuser,
)
from auth_user_service.core.exceptions import handle_route_exception
from auth_user_service.db_models.api_keys import (
    ApiKey,
    ApiKeyAdminPublic,
    ApiKeyCreate,
    ApiKeyPublic,
    ApiKeysAdminPublic,
)
from auth_user_service.db_models.privileged_action_audit import AuditAction
from auth_user_service.services.api_keys import ApiKeyAudienceError, ApiKeyService
from auth_user_service.services.audit import record_privileged_action

router = APIRouter(prefix="/profile/api-keys", tags=["api-keys"])


class ApiKeyCreated(ApiKeyPublic):
    """Response model for key creation — includes plaintext shown exactly once."""

    plaintext: str
    audiences: list[str] = Field(
        default_factory=list,
        description="Registered consumer ids this key was bound to (APIKEY-AUD-01). "
        "Empty ⇒ issuer-local use only. Immutable after issuance.",
    )


@router.get(
    "/verify",
    response_model=ApiKeyPublic,
    summary="Verify an API key and enforce rate limits",
)
def verify_api_key(api_key: CurrentApiKey) -> Any:
    """Validate the ``X-API-Key`` header and return the key's public metadata.

    Rate limits are enforced; ``X-RateLimit-*`` headers are always present when
    Redis is available. Returns 429 when the rate limit is exceeded.
    """
    return api_key


@router.post(
    "/",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
    responses=BaseController.get_error_responses(),
)
def create_api_key(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    body: ApiKeyCreate,
) -> Any:
    """Create a new API key for the authenticated user.

    The plaintext key is returned exactly once and never stored. ``access_mode``
    and ``audiences`` are fixed at issuance (§3.12): the default is the
    security-first ``READ_ONLY`` key bound to no audience (issuer-local only). Any
    requested audiences are authorized against the enabled introspection consumers
    before the key is written (``409`` on an invalid/ineligible audience), and the
    key row plus its audience bindings are committed atomically.
    """
    try:
        # Authorize audiences before allocating the key so an invalid request
        # never leaves a persisted key (validation raises ApiKeyAudienceError).
        audiences: list[str] = (
            ApiKeyService.validate_audiences(body.audiences) if body.audiences else []
        )

        count_stmt = select(func.count()).where(
            ApiKey.user_id == current_user.id,
            col(ApiKey.revoked).is_(False),
        )
        active_count = session.exec(count_stmt).one()
        if active_count >= settings.API_KEY_MAX_PER_USER:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Maximum of {settings.API_KEY_MAX_PER_USER} active API keys reached. "
                    "Revoke an existing key before creating a new one."
                ),
            )

        plaintext, key_hash = ApiKeyService.generate_key()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=body.ttl_hours)

        api_key = ApiKey(
            name=body.name or f"key-{uuid.uuid4().hex[:8]}",
            key_hash=key_hash,
            user_id=current_user.id,
            expires_at=expires_at,
            access_mode=body.access_mode,
        )
        session.add(api_key)
        # Bind audiences in the same transaction as the key row so a key never
        # exists without its intended audience set (fail-closed cutover).
        if audiences:
            ApiKeyService.set_key_audiences_in_tx(session, api_key, audiences)
        session.commit()
        session.refresh(api_key)

        m = _metrics.get()
        if m and m.api_key_lifecycle_total:
            m.api_key_lifecycle_total.labels(action="created").inc()

        return ApiKeyCreated(
            **api_key.model_dump(), plaintext=plaintext, audiences=audiences
        )
    except ApiKeyAudienceError as ex:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(ex)
        ) from ex
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.get(
    "/",
    response_model=list[ApiKeyPublic],
    responses=BaseController.get_error_responses(),
)
def list_api_keys(
    *,
    session: SessionDep,
    current_user: CurrentUser,
) -> Any:
    """List all API keys belonging to the authenticated user."""
    try:
        stmt = select(ApiKey).where(ApiKey.user_id == current_user.id)
        keys = session.exec(stmt).all()
        return keys
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.get(
    "/{key_id}",
    response_model=ApiKeyPublic,
    responses=BaseController.get_error_responses(),
)
def get_api_key(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    key_id: uuid.UUID,
) -> Any:
    """Get metadata for a single API key owned by the authenticated user."""
    try:
        api_key = session.get(ApiKey, key_id)
        if api_key is None or api_key.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="API key not found"
            )
        return api_key
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.delete(
    "/{key_id}",
    response_model=Message,
    responses=BaseController.get_error_responses(),
)
def revoke_api_key(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    key_id: uuid.UUID,
) -> Any:
    """Revoke an API key. Revoked keys are rejected on next use."""
    try:
        api_key = session.get(ApiKey, key_id)
        if api_key is None or api_key.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="API key not found"
            )
        if api_key.revoked:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="API key is already revoked",
            )
        ApiKeyService.revoke_key_in_tx(session, api_key)
        session.commit()

        m = _metrics.get()
        if m and m.api_key_lifecycle_total:
            m.api_key_lifecycle_total.labels(action="revoked").inc()

        return Message(message="API key revoked successfully")
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


# ---------------------------------------------------------------------------
# Limited superadmin API-key surface (Phase 7, §3.11/§3.12 review).
#
# Superadmin data authority over API keys is deliberately narrowed to
# **list + revoke** of any user's keys — no create, no edit, and no secret-read
# path exists. Listing returns metadata only (never the raw or hashed key); the
# revoke reuses the same authoritative revocation path as the owner route and
# writes one ``delete`` privileged-action audit row atomically with the
# revocation. Deactivation-driven key revocation (services.role_admin) is
# unchanged. Every other route above stays ``current_user.id``-scoped.
# ---------------------------------------------------------------------------
admin_router = APIRouter(prefix="/api-keys", tags=["api-keys-admin"])


@admin_router.get(
    "/by-user/{user_id}/",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=ApiKeysAdminPublic,
    responses=BaseController.get_error_responses(),
)
def admin_list_user_api_keys(
    *,
    session: SessionDep,
    user_id: uuid.UUID,
) -> Any:
    """Superadmin-only: list a target user's API keys (metadata only).

    Returns id, label, derived status, ``created_at``/``last_used_at``, owner id,
    and the immutable access mode — **never** the raw key (never stored) or the
    stored ``key_hash``. This is a read, so it writes **no** audit row.
    """
    try:
        count = session.exec(
            select(func.count()).select_from(ApiKey).where(ApiKey.user_id == user_id)
        ).one()
        keys = session.exec(
            select(ApiKey)
            .where(ApiKey.user_id == user_id)
            .order_by(col(ApiKey.created_at).desc())
        ).all()
        return ApiKeysAdminPublic(
            data=[ApiKeyAdminPublic.from_key(key) for key in keys],
            count=count,
        )
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@admin_router.post(
    "/revoke/{key_id}/",
    response_model=Message,
    responses=BaseController.get_error_responses(),
)
def admin_revoke_api_key(
    *,
    session: SessionDep,
    current_user: UserModel = Depends(get_current_active_superuser),
    key_id: uuid.UUID,
) -> Any:
    """Superadmin-only: revoke any user's API key (delete-equivalent).

    A superadmin revoking another user's key is a privileged ``delete`` of
    non-owned data: the key id and owner id are captured **before** the
    revocation and one ``delete`` audit row is enqueued into the same
    transaction the revocation commits, so it lands atomically. The revocation
    itself reuses the shared authoritative path (``ApiKeyService.revoke_key_in_tx``).
    """
    try:
        api_key = session.get(ApiKey, key_id)
        if api_key is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="API key not found"
            )
        if api_key.revoked:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="API key is already revoked",
            )
        # Capture the forensic target before the mutation (the audit row has no
        # FK to the key and must survive it, 3.5.1).
        owner_id = api_key.user_id
        record_privileged_action(
            session,
            actor_user_id=current_user.id,
            actor_role=current_user.role,
            action=AuditAction.DELETE,
            table_name=ApiKey.__tablename__,
            row_pk=key_id,
            target_owner_id=owner_id,
        )
        ApiKeyService.revoke_key_in_tx(session, api_key)
        session.commit()

        m = _metrics.get()
        if m and m.api_key_lifecycle_total:
            m.api_key_lifecycle_total.labels(action="revoked").inc()

        return Message(message="API key revoked successfully")
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)
