"""Shared auth-flow helpers for live test modules.

This module is the single owner of the bootstrap superuser credential every
live fixture authenticates with (G9-6): every other module in ``tests/live``
imports ``_ADMIN_EMAIL``/``_ADMIN_PASSWORD`` from here rather than defining its
own copy, so the value cannot drift out of agreement with itself again. Set
``LIVE_ADMIN_EMAIL``/``LIVE_ADMIN_PASSWORD`` to point at a different stack;
the defaults match the maintained Compose examples' seeded
``FIRST_SUPERUSER``/``FIRST_SUPERUSER_PASSWORD``.
"""

import os

import requests

AUTH_BASE = "http://localhost:9000/user"
SVC_BASE = "http://localhost:9000/fastapi"
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
