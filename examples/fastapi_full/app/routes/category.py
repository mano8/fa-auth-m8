"""Category api routes."""

from typing import Any, Optional, Union
from fastapi import APIRouter, HTTPException, Depends
from sqlmodel import select
from sqlmodel import func

from fastapi_full.app.deps import (
    CurrentUser,
    SessionDep,
    get_current_active_reader,
    get_current_active_writer,
)

from fastapi_full.db_models.categories import (
    Category,
    CategoryCreate,
    CategoryUpdate,
    CategoriesPublic,
)
from fastapi_m8 import BaseController, ResponseMessage, ResponseModelBase
from fastapi_m8 import has_superuser_privileges

router = APIRouter(prefix="/category", tags=["category"])
# pylint: disable=broad-exception-caught, not-callable


@router.get(
    "/",
    response_model=Optional[CategoriesPublic],
    responses=BaseController.get_error_responses(),
)
async def read_root(
    session: SessionDep,
    current_user: CurrentUser = Depends(get_current_active_reader),
    skip: int = 0,
    limit: int = 100,
) -> Any:
    """Retrieve category list."""
    try:
        if has_superuser_privileges(current_user.role, current_user.is_superuser):
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
    current_user: CurrentUser = Depends(get_current_active_reader),
) -> Any:
    """
    Get item by ID.
    """
    try:
        item = session.get(Category, item_id)
        if not item:
            return ResponseMessage(success=False, msg="Item not found.")
        if not has_superuser_privileges(
            current_user.role, current_user.is_superuser
        ) and (item.owner_id != current_user.id):
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
    current_user: CurrentUser = Depends(get_current_active_writer),
    item_in: CategoryCreate,
) -> Any:
    """
    Create new item.
    """
    try:
        item = Category.model_validate(item_in, update={"owner_id": current_user.id})
        session.add(item)
        session.commit()
        session.refresh(item)
        return ResponseModelBase(success=True, data=dict(item))
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
    current_user: CurrentUser = Depends(get_current_active_writer),
    item_in: CategoryUpdate,
) -> Any:
    """
    Update an item.
    """
    try:
        item = session.get(Category, item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Item not found")
        if not has_superuser_privileges(
            current_user.role, current_user.is_superuser
        ) and (item.owner_id != current_user.id):
            raise HTTPException(status_code=403, detail="Not enough permissions")
        update_dict = item_in.model_dump(exclude_unset=True)
        item.sqlmodel_update(update_dict)
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
    current_user: CurrentUser = Depends(get_current_active_writer),
) -> ResponseMessage:
    """
    Delete an item.
    """
    try:
        item = session.get(Category, item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Item not found")
        if not has_superuser_privileges(
            current_user.role, current_user.is_superuser
        ) and (item.owner_id != current_user.id):
            raise HTTPException(status_code=403, detail="Not enough permissions")
        session.delete(item)
        session.commit()
        return ResponseMessage(success=True, msg="Category deleted successfully")
    except Exception as ex:
        BaseController.handle_exception(ex=ex, session=session)
