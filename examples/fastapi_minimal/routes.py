"""API routes for the minimal example.

Each route below depends directly on the matching shared SDK-authorized
``AuthDeps`` guard (``core/deps.py``) — no route re-implements a role or
``is_superuser`` check.
"""

from fastapi import APIRouter

from .core.deps import CurrentAdmin, CurrentSuperuser, CurrentUser, CurrentWriter

router = APIRouter(prefix="/hello", tags=["hello"])


@router.get("/")
def hello(current_user: CurrentUser) -> dict:  # type: ignore[valid-type]
    """Return a greeting for any authenticated user."""
    return {"hello": current_user.email}


@router.get("/writer")
def hello_writer(current_user: CurrentWriter) -> dict:  # type: ignore[valid-type]
    """Return a greeting for a user with at least WRITER role."""
    return {"hello": current_user.email, "role": current_user.role}


@router.get("/admin")
def hello_admin(current_user: CurrentAdmin) -> dict:  # type: ignore[valid-type]
    """Return a greeting for a user with at least ADMIN role."""
    return {"hello": current_user.email, "role": current_user.role}


@router.get("/superuser")
def hello_superuser(current_user: CurrentSuperuser) -> dict:  # type: ignore[valid-type]
    """Return a greeting for the canonical superuser (role and flag both required)."""
    return {"hello": current_user.email, "role": current_user.role}
