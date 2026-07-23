"""Sessions routes"""

import uuid
from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import func, select
from auth_sdk_m8.schemas.base import AuthProviderType
from auth_sdk_m8.models.shared import Message
from auth_sdk_m8.controllers.base import BaseController
from auth_user_service.core.exceptions import handle_route_exception
from auth_user_service.core.config import settings
from auth_user_service.core.security import SecurityHelper
from auth_user_service.core.deps import (
    CurrentUser,
    RedisDep,
    SessionDep,
    get_current_active_superuser,
)
from auth_user_service.services.client_sessions import SessionController
from auth_user_service.services.audit import record_privileged_action
from auth_user_service.db_models.privileged_action_audit import AuditAction
from auth_user_service.db_models.sessions import (
    ClientSession,
    ClientSessionPublic,
    ClientSessionUpdateExternal,
    ClientSessionsPublic,
)

# pylint: disable=not-callable, broad-exception-caught

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get(
    "/",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=ClientSessionsPublic,
    responses=BaseController.get_error_responses(),
)
def session_list(session: SessionDep, skip: int = 0, limit: int = 100) -> Any:
    """
    Retrieve users.
    """
    try:
        count_statement = select(func.count()).select_from(ClientSession)
        count = session.exec(count_statement).one()

        statement = select(ClientSession).offset(skip).limit(limit)
        users = session.exec(statement).all()

        return ClientSessionsPublic(data=users, count=count)
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.get(
    "/get/{session_id}/",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=ClientSessionPublic,
    responses=BaseController.get_error_responses(),
)
def get_session_by_id(
    session_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> Any:
    """
    Get a specific user by id.
    """
    try:
        client_session = session.get(ClientSession, session_id)
        return client_session
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.get(
    "/get-by-user/{user_id}/",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=ClientSessionPublic,
    responses=BaseController.get_error_responses(),
)
def get_session_by_user(
    user_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> Any:
    """
    Get a specific user by id.
    """
    try:
        statement = select(ClientSession).where(ClientSession.user_id == user_id)
        client_session = session.exec(statement).first()
        return client_session
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.get(
    "/get-current/",
    response_model=ClientSessionPublic,
    responses=BaseController.get_error_responses(),
)
def get_my_session(session: SessionDep, current_user: CurrentUser) -> Any:
    """
    Get a specific user by id.
    """
    try:
        statement = select(ClientSession).where(
            ClientSession.user_id == current_user.id
        )
        client_session = session.exec(statement).first()
        if client_session is None:
            raise HTTPException(
                status_code=400,
                detail="The user session unavelable",
            )
        return client_session
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.post(
    "/refresh-google-tokens/",
    response_model=ClientSessionPublic,
    responses=BaseController.get_error_responses(),
)
def refresh_google_session_tokens(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    external_tokens: ClientSessionUpdateExternal,
) -> Any:
    """
    Create new user.
    """
    try:
        statement = select(ClientSession).where(
            ClientSession.user_id == current_user.id
        )
        client_session = session.exec(statement).first()
        if client_session is None:
            raise HTTPException(
                status_code=400,
                detail=("The user with this email already exists in the system."),
            )
        if client_session.provider != AuthProviderType.GOOGLE:
            raise HTTPException(
                status_code=400,
                detail=(
                    "You need google api auth Provider."
                    f"Current is {str(client_session.provider)}"
                ),
            )

        enc_key = settings.TOKENS_ENCRYPTION_KEY.get_secret_value()
        old_enc_key = (
            settings.TOKENS_ENCRYPTION_KEY_OLD.get_secret_value()
            if settings.TOKENS_ENCRYPTION_KEY_OLD
            else None
        )
        client_session.external_access_token = (
            SecurityHelper.encrypt_token(
                external_tokens.external_access_token, enc_key, old_enc_key
            )
            if external_tokens.external_access_token
            else None
        )
        client_session.external_refresh_token = (
            SecurityHelper.encrypt_token(
                external_tokens.external_refresh_token, enc_key, old_enc_key
            )
            if external_tokens.external_refresh_token
            else None
        )
        client_session.external_token_expires_at = (
            external_tokens.external_token_expires_at
        )
        session.add(client_session)
        session.commit()
        session.refresh(client_session)
        return client_session
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.delete(
    "/delete-by-user/{user_id}/",
    dependencies=[Depends(get_current_active_superuser)],
    responses=BaseController.get_error_responses(),
)
def delete_sessions_by_user(
    session: SessionDep,
    redis: RedisDep,
    current_user: CurrentUser,
    user_id: uuid.UUID,
) -> Message:
    """Administratively revoke every session of *user_id* (3.5.4).

    The authoritative ``ClientSession`` rows are deleted and committed first;
    the post-commit accelerator then blacklists each captured access JTI, drops
    the matching refresh allowlist entries, and emits the user-wide
    ``session-revoked`` event. Redis being unavailable degrades only the
    accelerator — the revocation is already persisted, so a fresh v2 JTI-status
    decision denies from database state alone.

    A superadmin revoking another user's sessions is a privileged ``delete`` of
    non-owned data: the audit row (keyed by the owning ``user_id`` for this
    user-wide bulk revocation) is enqueued into the same transaction the
    controller commits, so it lands atomically with the deletes (Phase 7).
    """
    try:
        record_privileged_action(
            session,
            actor_user_id=current_user.id,
            actor_role=current_user.role,
            action=AuditAction.DELETE,
            table_name=ClientSession.__tablename__,
            row_pk=user_id,
            target_owner_id=user_id,
        )
        SessionController.revoke_all_user_sessions(session, user_id, redis)
        return Message(message="User deleted successfully")
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.delete(
    "/delete/{session_id}/",
    dependencies=[Depends(get_current_active_superuser)],
    responses=BaseController.get_error_responses(),
)
def delete_session(
    session: SessionDep,
    redis: RedisDep,
    current_user: CurrentUser,
    session_id: uuid.UUID,
) -> Message:
    """Administratively revoke one session row (3.5.4).

    The delete of the authoritative row is the revocation; the accelerator
    blacklists that session's access JTI and emits the per-JTI event so a
    consumer's positive cache entry does not outlive the database decision.

    A superadmin revoking another user's session is a privileged ``delete`` of
    non-owned data: the session id and owner are captured **before** the delete
    and the audit row is enqueued into the same transaction the controller
    commits, so it lands atomically with the revocation (Phase 7).
    """
    try:
        client_session = session.get(ClientSession, session_id)
        if not client_session:
            raise HTTPException(status_code=404, detail="Session not found")
        record_privileged_action(
            session,
            actor_user_id=current_user.id,
            actor_role=current_user.role,
            action=AuditAction.DELETE,
            table_name=ClientSession.__tablename__,
            row_pk=session_id,
            target_owner_id=client_session.user_id,
        )
        SessionController.revoke_session_record(session, client_session, redis)
        return Message(message="Session deleted successfully")
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)
