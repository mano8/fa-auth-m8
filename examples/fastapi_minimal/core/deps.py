"""Build-once site: auth deps for the minimal example.

Import ``auth``, ``CurrentUser``, ``CurrentWriter``, ``CurrentAdmin``, and
``CurrentSuperuser`` from here; never call ``build_auth_deps`` a second time.
Every guard below is the shared SDK-authorized dependency built by
``build_auth_deps`` — no role/flag logic is reimplemented here.
"""

from typing import Annotated

from fastapi import Depends
from fastapi_m8 import AuthDeps, UserModel, build_auth_deps

from .config import settings

# Single instance shared across the entire process.
auth: AuthDeps = build_auth_deps(settings)

CurrentUser = auth.CurrentUser
CurrentWriter = Annotated[UserModel, Depends(auth.get_current_active_writer)]
CurrentAdmin = Annotated[UserModel, Depends(auth.get_current_active_admin)]
CurrentSuperuser = Annotated[UserModel, Depends(auth.get_current_active_superuser)]
