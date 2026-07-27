"""Category api routes."""

from typing import Any, Optional, Union
from fastapi import APIRouter, HTTPException, Depends
from sqlmodel import select
from sqlmodel import func

from fastapi_full.app.deps import (
    OwnerVerifierDep,
    SessionDep,
    get_current_active_reader,
    get_current_active_writer,
)
from fastapi_full.app.ownership import (
    OwnershipError,
    category_update_values,
    is_canonical_superuser,
    resolve_create_owner_id,
)

from fastapi_full.db_models.categories import (
    Category,
    CategoryCreate,
    CategoryUpdate,
    CategoriesPublic,
    build_category,
)
from fastapi_m8 import BaseController, ResponseMessage, ResponseModelBase, UserModel

router = APIRouter(prefix="/category", tags=["category"])
# pylint: disable=broad-exception-caught, not-callable


@router.get(
    "/",
    response_model=Optional[CategoriesPublic],
    responses=BaseController.get_error_responses(),
)
async def read_root(
    session: SessionDep,
    current_user: UserModel = Depends(get_current_active_reader),
    skip: int = 0,
    limit: int = 100,
) -> Any:
    """Retrieve category list."""
    try:
        if is_canonical_superuser(current_user):
            count_statement = select(func.count()).select_from(Category)
            count = session.exec(count_statement).one()
            statement = select(Category).offset(skip).limit(limit)
            items = session.exec(statement).all()
        else:
            count_statement = (
                select(func.count())
                .select_from(Category)
                .where(Category.owner_id == current_user.id)
            )
            count = session.exec(count_statement).one()
            statement = (
                select(Category)
                .where(Category.owner_id == current_user.id)
                .offset(skip)
                .limit(limit)
            )
            items = session.exec(statement).all()

        return CategoriesPublic(data=items, count=count)
    except Exception as ex:
        return BaseController.handle_exception(ex=ex, session=session)


@router.get(
    "/get/{item_id}/",
    response_model=Union[ResponseModelBase, ResponseMessage],
    responses=BaseController.get_error_responses(),
)
def read_item(
    item_id: int,
    session: SessionDep,
    current_user: UserModel = Depends(get_current_active_reader),
) -> Any:
    """
    Get item by ID.
    """
    try:
        item = session.get(Category, item_id)
        if not item:
            return ResponseMessage(success=False, msg="Item not found.")
        if not is_canonical_superuser(current_user) and (
            item.owner_id != current_user.id
        ):
            raise HTTPException(status_code=403, detail="Not enough permissions")
        return ResponseModelBase(success=True, data=dict(item))
    except HTTPException as ex:
        raise ex
    except Exception as ex:
        return BaseController.handle_exception(ex=ex, session=session)


@router.post(
    "/add/",
    response_model=ResponseModelBase,
    responses=BaseController.get_error_responses(),
)
def create_item(
    *,
    session: SessionDep,
    verify_owner_exists: OwnerVerifierDep,
    current_user: UserModel = Depends(get_current_active_writer),
    item_in: CategoryCreate,
) -> Any:
    """
    Create new item.

    The owner is resolved by the ownership rules, never taken from the body:
    without ``target_owner_id`` the row belongs to the actor, and with one it
    belongs to that exact user — a canonical superuser only, and only after the
    issuer confirms the user exists.
    """
    try:
        owner_id = resolve_create_owner_id(
            actor_id=current_user.id,
            actor_is_canonical_superuser=is_canonical_superuser(current_user),
            target_owner_id=item_in.target_owner_id,
            verify_owner_exists=verify_owner_exists,
        )
        item = build_category(item_in, owner_id=owner_id)
        session.add(item)
        session.commit()
        session.refresh(item)
        return ResponseModelBase(success=True, data=dict(item))
    except OwnershipError as ex:
        raise HTTPException(status_code=ex.status_code, detail=ex.detail) from ex
    except Exception as ex:
        BaseController.handle_exception(ex=ex, session=session)


@router.put(
    "/edit/{item_id}/",
    response_model=ResponseModelBase,
    responses=BaseController.get_error_responses(),
)
def update_item(
    *,
    item_id: int,
    session: SessionDep,
    current_user: UserModel = Depends(get_current_active_writer),
    item_in: CategoryUpdate,
) -> Any:
    """
    Update an item.

    The edit operates on the fetched row's existing ``owner_id``: the payload
    carries no ownership field and the applied values are stripped of every
    ownership key, so an edit can never re-home a category.
    """
    try:
        item = session.get(Category, item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Item not found")
        if not is_canonical_superuser(current_user) and (
            item.owner_id != current_user.id
        ):
            raise HTTPException(status_code=403, detail="Not enough permissions")
        item.sqlmodel_update(category_update_values(item_in))
        session.add(item)
        session.commit()
        session.refresh(item)
        return ResponseModelBase(success=True, data=dict(item))
    except Exception as ex:
        BaseController.handle_exception(ex=ex, session=session)


@router.delete(
    "/delete/{item_id}/",
    response_model=ResponseMessage,
    responses=BaseController.get_error_responses(),
)
def delete_item(
    item_id: int,
    session: SessionDep,
    current_user: UserModel = Depends(get_current_active_writer),
) -> ResponseMessage:
    """
    Delete an item.

    Authorization reads the fetched row's existing ``owner_id``; nothing about
    the actor is written onto the row on the way out.
    """
    try:
        item = session.get(Category, item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Item not found")
        if not is_canonical_superuser(current_user) and (
            item.owner_id != current_user.id
        ):
            raise HTTPException(status_code=403, detail="Not enough permissions")
        session.delete(item)
        session.commit()
        return ResponseMessage(success=True, msg="Category deleted successfully")
    except Exception as ex:
        BaseController.handle_exception(ex=ex, session=session)
