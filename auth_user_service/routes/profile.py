"""Users routes"""

from typing import Any
from fastapi import APIRouter, HTTPException

from auth_user_service.core.deps import CurrentUser, SessionDep
from auth_user_service.db_models.users import (
    UpdatePassword,
    User,
    UserPublic,
    UserUpdateMe,
)
from auth_user_service.events import EVENT_USER_DELETED, emit
from auth_user_service.schemas.user import ResponseUser
from auth_user_service.services.password import (
    PASSWORD_NOT_ALLOWED_DETAIL,
    IncorrectCurrentPassword,
    PasswordController,
    PasswordNotAllowed,
    PasswordUnchanged,
)
from auth_user_service.services.profile import (
    CurrentPasswordRequired,
    EmailAlreadyInUse,
    EmailChangeNotAllowed,
    ProfileController,
)
from auth_user_service.services.role_admin import delete_user_account
from auth_sdk_m8.authorization import has_superuser_privileges
from auth_sdk_m8.controllers.base import BaseController
from auth_sdk_m8.models.shared import Message
from auth_sdk_m8.schemas.user_events import UserDeletedEvent
from auth_user_service.core.exceptions import handle_route_exception

# pylint: disable=not-callable, broad-exception-caught

router = APIRouter(prefix="/profile", tags=["profile"])


@router.patch(
    "/update/me/",
    response_model=ResponseUser,
    responses=BaseController.get_error_responses(),
)
def update_user_me(
    *, session: SessionDep, current_user: CurrentUser, user_in: UserUpdateMe
) -> Any:
    """
    Update own user.

    An email change needs ``current_password`` (PASSWORD accounts) and is
    refused for GOOGLE accounts. An applied change clears ``email_verified`` and
    revokes every session, this one included, so the client signs in again.
    """

    try:
        db_user = session.get(User, current_user.id)
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        result = ProfileController.update_me(session, db_user, user_in)
        return ResponseUser(success=True, user=result.user)
    except EmailChangeNotAllowed as ex:
        raise HTTPException(
            status_code=403,
            detail="The email of a Google account cannot be changed",
        ) from ex
    except CurrentPasswordRequired as ex:
        raise HTTPException(
            status_code=400,
            detail="current_password is required to change the email",
        ) from ex
    except IncorrectCurrentPassword as ex:
        raise HTTPException(status_code=400, detail="Incorrect password") from ex
    except EmailAlreadyInUse as ex:
        raise HTTPException(
            status_code=409, detail="User with this email already exists"
        ) from ex
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.patch(
    "/me/password/",
    response_model=Message,
    responses=BaseController.get_error_responses(),
)
def update_password_me(
    *, session: SessionDep, body: UpdatePassword, current_user: CurrentUser
) -> Any:
    """
    Update own password.

    Refused for an account that does not sign in with a password (GOOGLE). An
    applied change bumps ``auth_generation`` and revokes every session, this
    one included, so the client signs in again with the new password (``D-c``).
    """
    try:
        db_user = session.get(User, current_user.id)
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        PasswordController.change_own_password(
            session,
            db_user,
            current_password=body.current_password,
            new_password=body.new_password,
        )
        return Message(message="Password updated successfully")
    except PasswordNotAllowed as ex:
        raise HTTPException(status_code=403, detail=PASSWORD_NOT_ALLOWED_DETAIL) from ex
    except IncorrectCurrentPassword as ex:
        raise HTTPException(status_code=400, detail="Incorrect password") from ex
    except PasswordUnchanged as ex:
        raise HTTPException(
            status_code=400,
            detail="New password cannot be the same as the current one",
        ) from ex
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)


@router.get("/get/me/", response_model=UserPublic)
def read_user_me(current_user: CurrentUser) -> Any:
    """
    Get current user.
    """
    return current_user


@router.delete(
    "/delete/me/",
    response_model=Message,
    responses=BaseController.get_error_responses(),
)
def delete_user_me(session: SessionDep, current_user: CurrentUser) -> Any:
    """
    Delete own user.

    Tombstones the subject and revokes every session and token minted for it.
    """
    try:
        if has_superuser_privileges(current_user.role, current_user.is_superuser):
            raise HTTPException(
                status_code=403,
                detail="Super users are not allowed to delete themselves",
            )
        db_user = session.get(User, current_user.id)
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        user_id = str(db_user.id)
        # The same transaction as an admin deletion (tombstone, session
        # revocation, durable outbox effects), minus the identity block: a user
        # who deletes their own account may come back (D-j).
        delete_user_account(
            session=session,
            actor_id=current_user.id,
            actor_role=current_user.role,
            db_user=db_user,
        )
        emit(EVENT_USER_DELETED, UserDeletedEvent(user_id=user_id).model_dump())
        return Message(message="User deleted successfully")
    except HTTPException:
        raise
    except Exception as ex:
        return handle_route_exception(ex=ex, session=session)
