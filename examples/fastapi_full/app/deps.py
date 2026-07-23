"""Re-export public dependencies consumed by route modules."""

__all__ = [
    "CurrentUser",
    "SessionDep",
    "get_current_api_key_writer",
    "get_current_active_reader",
    "get_current_active_writer",
    "get_current_active_superuser",
]

from fastapi_full.core.deps import (
    CurrentUser as CurrentUser,
    SessionDep as SessionDep,
    get_current_api_key_writer as get_current_api_key_writer,
    get_current_active_reader as get_current_active_reader,
    get_current_active_writer as get_current_active_writer,
    get_current_active_superuser as get_current_active_superuser,
)
