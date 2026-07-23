"""Redis per-service ACL policy tests (plan item 6.x.1).

Asserts the static security contract for the Redis ACL bootstrap that every
compose example runs in its ``redis_cache`` service:

- The auth app authenticates as a dedicated, **scoped** ``auth`` user — never
  the old open ``appuser ~* +@all``. The user is restricted to exactly the key
  prefixes the service writes and only the command categories it uses.
- The ``default`` user is stripped of all data/admin access (``-@all``); it
  keeps connection commands only so the healthcheck ``PING`` still works.
- ``REDIS_USER`` in the auth env examples matches the scoped ACL username, so
  the app actually authenticates as the restricted user.

A code-linked guard additionally re-derives the Redis key prefixes from the
source and fails if a prefix is introduced that the ACL does not cover.
"""

from __future__ import annotations

import re

import pytest

from tests.security._compose import REPO_ROOT, load_compose

_COMPOSE_DIR = REPO_ROOT / "examples" / "docker_compose"

# Every example stack that ships a redis_cache service with an ACL bootstrap.
_STACKS = [
    "hardened_m8",
    "metrics_m8",
    "postgres_m8",
    "quickstart_m8",
    "rs256_m8",
    "vault_dev_m8",
]

# Key prefixes the auth service + auth-sdk write to Redis (audited from
# auth_user_service/core/client.py, core/deps.py, and the auth-sdk stores).
# Each must be covered by an ACL ``~prefix*`` pattern. Kept in sync by
# test_acl_covers_every_source_key_prefix below.
_RUNTIME_KEY_PREFIXES = [
    "oauth_session:",
    "auth_code:",
    "login:attempts:",
    "login:ip:",
    "refresh:attempts:",
    "exchange:attempts:",
    "rt:",
    "jwt:blacklist:",
    "rate:api:",
    "api_key:luat",
    "security:superuser_probe:",
    "security:audit_log:",
]


def _redis_command(stack: str) -> str:
    """Return the redis_cache bootstrap script for *stack* as one string."""
    compose = load_compose(_COMPOSE_DIR / stack / "docker-compose.yml")
    command = compose["services"]["redis_cache"]["command"]
    assert isinstance(command, list), f"{stack}: redis_cache command must be a list"
    return "\n".join(str(part) for part in command)


def _setuser_line(script: str, username: str) -> str:
    """Return the single ``ACL SETUSER <username> ...`` line from *script*."""
    matches = [
        line
        for line in script.splitlines()
        if re.search(rf"\bACL SETUSER {re.escape(username)}\b", line)
    ]
    assert len(matches) == 1, (
        f"expected exactly one SETUSER for {username!r}, got {matches}"
    )
    return matches[0]


def _acl_key_patterns(setuser_line: str) -> list[str]:
    """Extract the ``~pattern`` key globs from an ACL SETUSER line."""
    return re.findall(r'~([^"\s]+)', setuser_line)


# ── the open appuser ACL is gone everywhere ──────────────────────────────────


@pytest.mark.parametrize("stack", _STACKS)
def test_no_open_appuser_acl(stack: str) -> None:
    script = _redis_command(stack)
    assert "appuser" not in script, (
        f"{stack}: the open 'appuser' ACL must be replaced by a scoped 'auth' user"
    )
    assert "+@all" not in script, f"{stack}: no ACL user may be granted +@all"


# ── scoped auth user ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("stack", _STACKS)
def test_auth_user_is_scoped_not_wildcard(stack: str) -> None:
    line = _setuser_line(_redis_command(stack), "auth")
    patterns = _acl_key_patterns(line)
    assert patterns, f"{stack}: auth user must declare explicit ~key patterns"
    assert "*" not in patterns, (
        f"{stack}: auth user must not have the '~*' wildcard keyspace"
    )
    assert "+@all" not in line, f"{stack}: auth user must not be granted +@all"


@pytest.mark.parametrize("stack", _STACKS)
def test_auth_user_grants_only_needed_categories(stack: str) -> None:
    line = _setuser_line(_redis_command(stack), "auth")
    # The exact command surface the service uses; dangerous/admin denied.
    for grant in (
        "+@read",
        "+@write",
        "+@transaction",
        "+@connection",
        "+eval",
        "-@dangerous",
    ):
        assert grant in line, f"{stack}: auth user is missing required grant {grant!r}"
    for forbidden in ("+@admin", "+@dangerous", "+@scripting", "+@pubsub"):
        assert forbidden not in line, f"{stack}: auth user must not grant {forbidden!r}"


@pytest.mark.parametrize("stack", _STACKS)
def test_acl_covers_every_source_key_prefix(stack: str) -> None:
    patterns = _acl_key_patterns(_setuser_line(_redis_command(stack), "auth"))
    globs = [p[:-1] if p.endswith("*") else p for p in patterns]
    for prefix in _RUNTIME_KEY_PREFIXES:
        assert any(prefix.startswith(g) for g in globs), (
            f"{stack}: runtime key prefix {prefix!r} is not covered by any ACL "
            f"pattern {patterns} — add it to the auth user's ~key list"
        )


# ── default user is locked down ───────────────────────────────────────────────


@pytest.mark.parametrize("stack", _STACKS)
def test_default_user_is_restricted(stack: str) -> None:
    line = _setuser_line(_redis_command(stack), "default")
    assert "-@all" in line, f"{stack}: default user must be stripped with -@all"
    assert "+@all" not in line, f"{stack}: default user must not be granted +@all"
    assert "*" not in _acl_key_patterns(line), (
        f"{stack}: default user must not retain '~*' key access (use resetkeys)"
    )


# ── env example wires the app to the scoped user ──────────────────────────────


@pytest.mark.parametrize("stack", _STACKS)
def test_redis_user_env_matches_scoped_acl(stack: str) -> None:
    env_path = _COMPOSE_DIR / stack / "auth.env.example"
    text = env_path.read_text(encoding="utf-8")
    assert "REDIS_USER=auth\n" in text or text.endswith("REDIS_USER=auth"), (
        f"{stack}: auth.env.example must set REDIS_USER=auth to authenticate as "
        "the scoped ACL user"
    )
    assert "REDIS_USER=appuser" not in text, (
        f"{stack}: stale REDIS_USER=appuser in env example"
    )


# ── the code-linked guard itself stays honest ─────────────────────────────────


def test_runtime_prefix_list_matches_source() -> None:
    """Fail if a new ``PREFIX``/key literal appears in client.py uncovered.

    Re-derives the Redis key prefixes declared in core/client.py and asserts
    each is represented in _RUNTIME_KEY_PREFIXES, so the audited list cannot
    silently drift from the source.
    """
    client_src = (REPO_ROOT / "auth_user_service" / "core" / "client.py").read_text(
        encoding="utf-8"
    )
    # PREFIX constants and the inline rate-limit key, e.g. PREFIX = "oauth_session:"
    declared = set(re.findall(r'PREFIX[^=]*=\s*"([a-z_]+:[a-z_:]*)"', client_src))
    declared.update(
        re.findall(r'f"([a-z_]+:[a-z_]+):', client_src)
    )  # f"rate:api:{...}"
    known = set(_RUNTIME_KEY_PREFIXES)
    uncovered = {
        d
        for d in declared
        if not any(d.startswith(k) or k.startswith(d) for k in known)
    }
    assert not uncovered, (
        f"client.py declares Redis key prefixes not in _RUNTIME_KEY_PREFIXES: "
        f"{sorted(uncovered)} — update the audited list and the compose ACLs"
    )
