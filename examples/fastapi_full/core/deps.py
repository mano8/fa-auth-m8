"""Build-once site for auth and database dependencies.

Import ``auth``, ``engine``, ``CurrentUser``, and ``SessionDep`` from here.
Never call ``build_auth_deps`` or ``create_db_engine`` a second time.
"""

from functools import partial
from typing import Annotated

from fastapi import Depends, Request
from sqlmodel import Session

from fastapi_m8 import AuthDeps, DbEngine, build_auth_deps, create_db_engine

from .config import settings
from .user_directory import IssuerUserDirectory, OwnerVerifier

# Single instances shared across the entire process.
auth: AuthDeps = build_auth_deps(settings)
engine: DbEngine = create_db_engine(settings)

CurrentUser = auth.CurrentUser
get_current_user = auth.get_current_user
get_current_active_reader = auth.get_current_active_reader
get_current_active_writer = auth.get_current_active_writer
get_current_active_superuser = auth.get_current_active_superuser
get_db = engine.session_dep
SessionDep = Annotated[Session, Depends(get_db)]

# Remote API-key principal (§3.12) — the single dependency built by
# build_auth_deps above, capped at WRITER. None unless this deployment sets
# API_KEY_INTROSPECTION_ENABLED=true (see .example_env); app/main.py only
# wires the API-key-gated route when this is not None.
get_current_api_key_writer = auth.get_current_api_key_writer

# Issuer user directory — the only way this consumer can confirm that a
# superadmin's explicit ``target_owner_id`` names a real user, since the user
# table belongs to auth_user_service and is never read from here.
user_directory = IssuerUserDirectory.from_settings(settings)


def _bearer_token(request: Request) -> str:
    """Return the request's raw bearer token, or an empty string."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    return token if scheme.lower() == "bearer" else ""


def get_owner_verifier(request: Request) -> OwnerVerifier:
    """Bind the issuer user-directory lookup to this request's bearer token.

    Args:
        request: The incoming request; its token is forwarded to the issuer so
            the lookup is authorized as the caller, never as the service.

    Returns:
        A callable resolving a candidate owner id to whether it exists.
    """
    return partial(user_directory.user_exists, bearer_token=_bearer_token(request))


OwnerVerifierDep = Annotated[OwnerVerifier, Depends(get_owner_verifier)]
