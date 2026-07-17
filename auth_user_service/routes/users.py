"""Users routes"""

import uuid
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import func, select
from auth_user_service.services.users import UserController
from auth_user_service.services.role_admin import (
    LastSuperuserError,
    SelfPromotionError,
    change_user_authorization,
    delete_user_account,
)
from auth_user_service.core.deps import (
    CurrentUser,
    RedisDep,
    SessionDep,
    get_current_active_superuser,
)
from auth_sdk_m8.authorization import has_superuser_privileges
from auth_sdk_m8.models.shared import Message
from auth_user_service.db_models.users import (
    User,
    UserCreate,
    UserPublic,
    UserRegister,
    UsersPublic,
    UserUpdate,
)
from auth_sdk_m8.controllers.base import BaseController
from auth_sdk_m8.schemas.user_events import UserDeletedEvent
from auth_user_service.core.exceptions import handle_route_exception
from auth_user_service.events import EVENT_USER_DELETED, emit

# pylint: disable=not-callable, broad-exception-caught

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "/",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=UsersPublic,
    responses=BaseController.get_error_responses(),
)
def read_users(session: SessionDep, skip: int = 0, limit: int = 100) -> Any:
    """
    Retrieve users.
    """
    try:
        count_statement = select(func.count()).select_from(User)
        count = session.exec(count_statement).one()

        statement = select(User).offset(skip).limit(limit)
        users = session.exec(statement).all()

        return UsersPublic(data=users, count=count)
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.post(
    "/new_user/",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=UserPublic,
    responses=BaseController.get_error_responses(),
)
def create_new_user_with_password(*, session: SessionDep, user_in: UserCreate) -> Any:
    """
    Create new user.
    """
    try:
        user = UserController.get_user_by_email(session=session, email=user_in.email)
        if user:
            raise HTTPException(
                status_code=400,
                detail=("The user with this email already exists in the system."),
            )

        user = UserController.create_user(session=session, user_create=user_in)
        return user
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.post(
    "/signup/",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=UserPublic,
    responses=BaseController.get_error_responses(),
)
def register_user(session: SessionDep, user_in: UserRegister) -> Any:
    """
    Create new user without the need to be logged in.
    """
    try:
        user = UserController.get_user_by_email(session=session, email=user_in.email)
        if user:
            raise HTTPException(
                status_code=400,
                detail="The user with this email already exists in the system",
            )
        user_create = UserCreate.model_validate(user_in)
        user = UserController.create_user(session=session, user_create=user_create)
        return user
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.get(
    "/get/{user_id}/",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=UserPublic,
    responses=BaseController.get_error_responses(),
)
def read_user_by_id(
    user_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> Any:
    """
    Get a specific user by id.
    """
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id != current_user.id and not has_superuser_privileges(
        current_user.role, current_user.is_superuser
    ):
        raise HTTPException(
            status_code=403,
            detail="The user doesn't have enough privileges",
        )
    return user


@router.patch(
    "/update/{user_id}/",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=UserPublic,
    responses=BaseController.get_error_responses(),
)
def update_current_user(
    *,
    session: SessionDep,
    redis: RedisDep,
    current_user: CurrentUser,
    user_id: uuid.UUID,
    user_in: UserUpdate,
) -> Any:
    """
    Update a user.

    Role and activation changes run through the route-owned superuser-set
    transaction (``services.role_admin``): the last-superuser invariant and the
    no-self-promotion rule are enforced under the lock, sessions are revoked on
    any authorization transition, and deactivation revokes the owner's API keys.
    """
    try:
        db_user = session.get(User, user_id)
        if not db_user:
            raise HTTPException(
                status_code=404,
                detail="The user with this id does not exist in the system",
            )
        if user_in.email:
            existing_user = UserController.get_user_by_email(
                session=session, email=user_in.email
            )
            if existing_user and existing_user.id != user_id:
                raise HTTPException(
                    status_code=409, detail="User with this email already exists"
                )

        db_user = change_user_authorization(
            session=session,
            actor_id=current_user.id,
            db_user=db_user,
            user_in=user_in,
            redis=redis,
        )
        return db_user
    except SelfPromotionError as ex:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A user may not raise their own role",
        ) from ex
    except LastSuperuserError as ex:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="last_superuser_required",
        ) from ex
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.delete(
    "/delete/{user_id}/",
    dependencies=[Depends(get_current_active_superuser)],
    responses=BaseController.get_error_responses(),
)
def delete_user(
    session: SessionDep, current_user: CurrentUser, user_id: uuid.UUID
) -> Message:
    """
    Delete a user.

    Runs through the route-owned superuser-set transaction: the last-superuser
    invariant is enforced under the lock and a durable deletion tombstone is
    written so introspection treats every token ever minted for the subject as
    revoked (3.5.1). Self-deletion is permitted subject only to the last-superuser
    rule (3.10).
    """
    try:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        delete_user_account(
            session=session,
            actor_id=current_user.id,
            db_user=user,
        )
        # Best-effort push so consumers drop any cached state for the deleted
        # user; the account is already gone from the DB regardless of delivery.
        emit(EVENT_USER_DELETED, UserDeletedEvent(user_id=str(user_id)).model_dump())
        return Message(message="User deleted successfully")
    except LastSuperuserError as ex:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="last_superuser_required",
        ) from ex
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)
