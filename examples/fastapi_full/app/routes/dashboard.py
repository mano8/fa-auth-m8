"""DashBoard routes.

The dashboard reports how many categories were added and updated in a window,
so it is gated exactly like the mutations it summarises: ``get_current_active_writer``,
the same dependency ``POST``/``PUT``/``DELETE`` on ``/category`` use. A role that
cannot add or edit anything has nothing to read here.
"""

from typing import Union

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from fastapi_m8 import BaseController, UserModel

from fastapi_full.app.deps import SessionDep, get_current_active_writer
from fastapi_full.controllers.dashboard import DashboardController
from fastapi_full.schemas.dashboard import RangeActivityType, UsersActivity

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
# pylint: disable=broad-exception-caught, unused-argument


@router.get(
    "/users/activity/",
    response_model=UsersActivity,
    responses=BaseController.get_error_responses(),
)
def get_dash_users_stats(
    session: SessionDep,
    current_user: UserModel = Depends(get_current_active_writer),
) -> Union[UsersActivity, JSONResponse]:
    """Category add/update counts for the current month."""
    return DashboardController.get_dash_users_stats(
        session=session, current_user=current_user, time_range=RangeActivityType.MONTH
    )


@router.get(
    "/users/activity/current/",
    response_model=UsersActivity,
    responses=BaseController.get_error_responses(),
)
def get_dash_current_user_stats(
    session: SessionDep,
    current_user: UserModel = Depends(get_current_active_writer),
) -> Union[UsersActivity, JSONResponse]:
    """Category add/update counts for the current month, own rows only."""
    return DashboardController.get_dash_users_stats(
        session=session,
        current_user=current_user,
        time_range=RangeActivityType.MONTH,
        is_current=True,
    )
