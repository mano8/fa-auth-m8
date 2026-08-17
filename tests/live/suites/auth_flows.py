"""Shared auth-flow helpers for live test modules.

This module is the single owner of the bootstrap superuser credential every
live fixture authenticates with (G9-6): every other module in ``tests/live``
imports ``_ADMIN_EMAIL``/``_ADMIN_PASSWORD`` from here rather than defining its
own copy, so the value cannot drift out of agreement with itself again. Set
``LIVE_ADMIN_EMAIL``/``LIVE_ADMIN_PASSWORD`` to point at a different stack;
the defaults match the maintained Compose examples' seeded
``FIRST_SUPERUSER``/``FIRST_SUPERUSER_PASSWORD``.

It is also the single owner of the stack endpoints. The defaults describe the
maintained Compose examples (issuer at ``/user``, the ``fastapi_full`` consumer
at ``/fastapi``); ``LIVE_AUTH_BASE``/``LIVE_SVC_BASE``/``LIVE_SVC_PROTECTED_PATH``
retarget the suite at any other ``fa-auth-m8`` + ``fastapi-m8`` stack without a
source edit, the same way ``examples/docker_compose/shared_live_tests`` is
retargeted by configuration alone.
"""

import os

import requests

AUTH_BASE = os.environ.get("LIVE_AUTH_BASE", "http://localhost:9000/user")
SVC_BASE = os.environ.get("LIVE_SVC_BASE", "http://localhost:9000/fastapi")
# An authenticated list route on the consumer: 200 for a valid token, 401/403
# without one, and no required path parameter.
SVC_PROTECTED_PATH = os.environ.get("LIVE_SVC_PROTECTED_PATH", "/category/")
TIMEOUT = 10

_ADMIN_EMAIL = os.environ.get("LIVE_ADMIN_EMAIL", "admin@example.com")
_ADMIN_PASSWORD = os.environ.get("LIVE_ADMIN_PASSWORD", "Ocoti123@#@")


def auth_header(bearer: str) -> dict:
    """Return an Authorization header dict for the given bearer token."""
    return {"Authorization": f"Bearer {bearer}"}


def fresh_login(
    email: str = _ADMIN_EMAIL,
    password: str = _ADMIN_PASSWORD,
) -> dict:
    """Perform a fresh login and return token + cookies."""
    r = requests.post(
        f"{AUTH_BASE}/login/access-token",
        data={"username": email, "password": password},
        timeout=TIMEOUT,
    )
    assert r.status_code == 200, f"Login failed for {email}: {r.text}"
    return {
        "token": r.json()["access_token"],
        "cookies": dict(r.cookies),
        "headers": auth_header(r.json()["access_token"]),
    }
