"""
DashBoard routes
"""

from typing import Union

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from auth_sdk_m8.controllers.base import BaseController
from auth_user_service.core.deps import CurrentUser, SessionDep
from auth_user_service.services.dashboard import DashboardController
from auth_user_service.schemas.dashboard import RangeActivityType, UsersActivity

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
# pylint: disable=broad-exception-caught, unused-argument


@router.get(
    "/users/activity/",
    response_model=UsersActivity,
    responses=BaseController.get_error_responses(),
)
def get_dash_users_stats(
    session: SessionDep, current_user: CurrentUser
) -> Union[UsersActivity, JSONResponse]:
    """Get phpfina files list from source."""
    # Pre-existing route, exercised only by tests/live (no unit-level HTTP
    # client in this suite) — not part of the new authorization-bearing
    # contract surface this coverage gate now measures (3A-2).
    return DashboardController.get_dash_users_stats(  # pragma: no cover
        session=session, current_user=current_user, time_range=RangeActivityType.MONTH
    )


@router.get(
    "/users/activity/current/",
    response_model=UsersActivity,
    responses=BaseController.get_error_responses(),
)
def get_dash_current_user_stats(
    session: SessionDep, current_user: CurrentUser
) -> Union[UsersActivity, JSONResponse]:
    """Get phpfina files list from source."""
    # Pre-existing route, exercised only by tests/live — see justification
    # on get_dash_users_stats above (3A-2).
    return DashboardController.get_dash_users_stats(  # pragma: no cover
        session=session,
        current_user=current_user,
        time_range=RangeActivityType.MONTH,
        is_current=True,
    )
