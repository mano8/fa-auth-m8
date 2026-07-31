"""
Main routes
"""

from fastapi import APIRouter

from fastapi_full.app.deps import get_current_api_key_writer
from fastapi_full.app.routes import api_key_category, audit, category, dashboard

api_router = APIRouter()
api_router.include_router(dashboard.router)
api_router.include_router(category.router)
api_router.include_router(audit.router)

# The API-key-gated route only exists when this deployment enables remote
# API-key introspection (API_KEY_INTROSPECTION_ENABLED=true, see
# .example_env); build_auth_deps returns None for the dependency otherwise, so
# the router is never built — there is nothing to gate the route with.
if get_current_api_key_writer is not None:  # pragma: no cover - see .coveragerc
    api_router.include_router(api_key_category.build_router(get_current_api_key_writer))
