"""API-key-gated category route (§3.12).

Demonstrates the remote API-key principal dependency: the route depends on
``get_current_api_key_writer`` — the single capability-capped dependency
``build_auth_deps`` builds from the issuer's introspection contract — never a
bare-key dependency and never a re-implemented role check (§3.3.1).

``build_router`` is called only when ``get_current_api_key_writer`` is not
None (see ``app/main.py``): the dependency itself is absent unless this
deployment enables ``API_KEY_INTROSPECTION_ENABLED``, so the route is never
decorated onto a missing dependency.
"""

import uuid
from typing import Any, Callable

from fastapi import APIRouter, Depends

from fastapi_m8 import BaseController, ResponseModelBase
from fastapi_full.app.deps import SessionDep
from fastapi_full.db_models.categories import Category, CategoryCreate

# pylint: disable=broad-exception-caught


def build_router(get_current_api_key_writer: Callable) -> APIRouter:
    """Build the API-key-gated category router bound to *get_current_api_key_writer*."""
    router = APIRouter(prefix="/category/api-key", tags=["category", "api-key"])

    @router.post(
        "/add/",
        response_model=ResponseModelBase,
        responses=BaseController.get_error_responses(),
    )
    def create_item_with_api_key(
        *,
        session: SessionDep,
        principal=Depends(get_current_api_key_writer),  # noqa: ANN001
        item_in: CategoryCreate,
    ) -> Any:
        """Create a category owned by the API key's current owner.

        The owner id and role are resolved live against the issuer on every
        call (never cached, never read off the key) — a ``writer -> reader``
        downgrade of the owner denies the very next request through this
        route.
        """
        try:
            item = Category.model_validate(
                item_in, update={"owner_id": uuid.UUID(principal.user_id)}
            )
            session.add(item)
            session.commit()
            session.refresh(item)
            return ResponseModelBase(success=True, data=dict(item))
        except Exception as ex:
            return BaseController.handle_exception(ex=ex, session=session)

    return router
