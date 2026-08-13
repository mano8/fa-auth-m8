"""
Live Gate — stateful writer -> reader downgrade (Phase 5 / Phase 7 re-run)
==========================================================================
Target:  http://localhost:9000/user/  +  http://localhost:9000/fastapi/
Config:  TOKEN_MODE=stateful, and the consumer must run
         AUTH_SERVICE_ROLE=consumer with the revocation client and the
         event-stream bridge enabled (fail-closed is the default).

This is the plan's live stateful downgrade gate, re-run against the WRITER-gated
category route that Phase 7 introduced:

    1. a WRITER writes a category                    -> 200
    2. a superadmin downgrades the role to READER    -> 200 + auth_generation
                                                        + revocation_enqueued
    3. every session of that user is revoked and the session-revoked event is
       published, so the *already issued* token stops working entirely
       -- proven by the token being denied on the READER-tier *read* it would
       otherwise still be entitled to make
    4. a freshly minted READER token can read categories        -> 200
    5. the same fresh token cannot write one                    -> 403

Step 3 is the whole point: after a downgrade the old token must die, not merely
lose its write capability. The read denial in ``test_g3b`` is what separates
"the session was revoked" from "the role check now fails", because a READER is
allowed to read.

Precondition, and why the gate is skipped otherwise: in hybrid or stateless mode
the issuer never revokes an already-issued access token, so the old token stays
usable until it expires and step 3 cannot hold. The ``require_token_mode``
marker skips this module on such a stack rather than reporting a false failure.

Run:
    pytest tests/live/test_role_downgrade_gate.py -v --no-cov
    pytest tests/live -m live_stateful --no-cov
"""

import time
import uuid
from collections.abc import Iterator

import pytest
import requests

from tests.live.suites.auth_flows import (
    AUTH_BASE,
    SVC_BASE,
    TIMEOUT,
    auth_header,
    fresh_login,
)

pytestmark = [
    pytest.mark.live,
    pytest.mark.live_stateful,
    pytest.mark.require_token_mode("stateful"),
    pytest.mark.require_redis,
]

# The gate drives one concrete consumer contract — the WRITER-gated
# ``category`` routes of ``examples/fastapi_full``. Unlike the algorithm and
# token-mode preconditions, that one has no marker, so a stack whose consumer
# is a different ``fastapi-m8`` service used to report five red failures that
# said nothing about authorization. Detect it and skip with a reason instead,
# the way every other unmet precondition in this suite is reported.
_CATEGORY_CONTRACT = f"{SVC_BASE}/category/"

# How long the revocation may take to become observable. The issuer commits the
# role change and its outbox rows in one transaction; the drain loop then writes
# the Redis blacklist and publishes the event on OUTBOX_DRAIN_INTERVAL_SECONDS
# (default 1.0s). This bound is deliberately generous -- the gate is about the
# denial happening at all, not about a latency target.
_PROPAGATION_TIMEOUT_SECONDS = 30.0
_POLL_INTERVAL_SECONDS = 0.5

_WRITER_PASSWORD = "GateWriter!Pass9"


def _new_category_name(suffix: str) -> str:
    """Category names are globally unique, so every run mints its own."""
    return f"downgrade-gate-{suffix}"


@pytest.fixture(scope="module", autouse=True)
def _requires_category_contract() -> None:
    """Skip the module when the configured consumer does not serve ``category``.

    An unauthenticated probe is enough: the route answers 401/403 when it
    exists and the proxy answers 404 when this stack runs a different consumer
    behind ``SVC_BASE``.
    """
    try:
        probe = requests.get(_CATEGORY_CONTRACT, timeout=TIMEOUT)
    except requests.RequestException as exc:
        pytest.skip(f"downgrade gate: consumer {_CATEGORY_CONTRACT} unreachable: {exc}")
    if probe.status_code == 404:
        pytest.skip(
            f"downgrade gate: {_CATEGORY_CONTRACT} is not served (404) — this "
            "stack's consumer does not expose the WRITER-gated category contract "
            "the gate drives. Point LIVE_SVC_BASE at a fastapi_full-shaped "
            "consumer to run it."
        )


@pytest.fixture(scope="module")
def gate_run() -> Iterator[dict]:
    """Execute the downgrade sequence once; return every observed response.

    Running the sequence in a fixture rather than in one long test lets each
    stage be asserted -- and reported -- separately, while the live stack is
    still driven through the ordered flow exactly once.

    The superadmin is obtained through ``suites.auth_flows.fresh_login`` rather
    than the shared ``admin_headers`` fixture: the two carry different bootstrap
    passwords, and this module uses the one the rest of the live suite uses.
    """
    admin_headers = fresh_login()["headers"]
    suffix = uuid.uuid4().hex[:8]
    email = f"downgrade_gate_{suffix}@example.com"
    obs: dict = {"suffix": suffix, "email": email, "category_ids": []}

    created = requests.post(
        f"{AUTH_BASE}/users/new_user/",
        json={
            "email": email,
            "password": _WRITER_PASSWORD,
            "full_name": "Downgrade Gate Writer",
            "role": "writer",
        },
        headers=admin_headers,
        timeout=TIMEOUT,
    )
    assert created.status_code == 200, f"Could not provision writer: {created.text}"
    obs["created"] = created
    user_id = created.json()["id"]
    obs["user_id"] = user_id

    def _login() -> str:
        resp = requests.post(
            f"{AUTH_BASE}/login/access-token",
            data={"username": email, "password": _WRITER_PASSWORD},
            timeout=TIMEOUT,
        )
        assert resp.status_code == 200, f"Login failed for {email}: {resp.text}"
        return resp.json()["access_token"]

    writer_headers = auth_header(_login())

    # ── 1. the WRITER-gated write succeeds while the role still allows it ─────
    obs["writer_write"] = requests.post(
        f"{SVC_BASE}/category/add/",
        json={"name": _new_category_name(suffix)},
        headers=writer_headers,
        timeout=TIMEOUT,
    )
    if obs["writer_write"].status_code == 200:
        obs["category_ids"].append(obs["writer_write"].json()["data"]["id"])

    # ── 2. the issuer downgrades the role ─────────────────────────────────────
    started = time.monotonic()
    obs["downgrade"] = requests.patch(
        f"{AUTH_BASE}/users/update/{user_id}/",
        json={"role": "reader"},
        headers=admin_headers,
        timeout=TIMEOUT,
    )

    # ── 3. the already-issued token stops working ─────────────────────────────
    # Each attempt carries its own name: category names are globally unique, so
    # on a stack where the old token keeps writing, a repeated name would
    # collide and mask the authorization answer this loop is reading.
    deadline = started + _PROPAGATION_TIMEOUT_SECONDS
    attempt = 0
    while True:
        old_write = requests.post(
            f"{SVC_BASE}/category/add/",
            json={"name": f"{_new_category_name(suffix)}-after-{attempt}"},
            headers=writer_headers,
            timeout=TIMEOUT,
        )
        attempt += 1
        if old_write.status_code == 200:
            # The write landed -- record it before deciding whether to stop, so
            # the last attempt of a failing run is torn down like the others.
            obs["category_ids"].append(old_write.json()["data"]["id"])
        if old_write.status_code != 200 or time.monotonic() >= deadline:
            break
        time.sleep(_POLL_INTERVAL_SECONDS)

    obs["old_token_write"] = old_write
    obs["propagation_seconds"] = time.monotonic() - started
    obs["old_token_read"] = requests.get(
        f"{SVC_BASE}/category/",
        headers=writer_headers,
        timeout=TIMEOUT,
    )

    # ── 4/5. a fresh token carries the new, lower authority ───────────────────
    reader_headers = auth_header(_login())
    obs["reader_read"] = requests.get(
        f"{SVC_BASE}/category/",
        headers=reader_headers,
        timeout=TIMEOUT,
    )
    obs["reader_write"] = requests.post(
        f"{SVC_BASE}/category/add/",
        json={"name": f"{_new_category_name(suffix)}-reader"},
        headers=reader_headers,
        timeout=TIMEOUT,
    )
    if obs["reader_write"].status_code == 200:
        obs["category_ids"].append(obs["reader_write"].json()["data"]["id"])

    yield obs

    # ── teardown: the gate leaves no account or row behind ────────────────────
    for category_id in obs["category_ids"]:
        requests.delete(
            f"{SVC_BASE}/category/delete/{category_id}/",
            headers=admin_headers,
            timeout=TIMEOUT,
        )
    requests.delete(
        f"{AUTH_BASE}/users/delete/{user_id}/",
        headers=admin_headers,
        timeout=TIMEOUT,
    )


class TestStatefulDowngradeGate:
    """The five ordered observations that make up the gate."""

    def test_g1_writer_write_succeeds_before_downgrade(self, gate_run: dict):
        """A WRITER may create a category, and owns the row it created."""
        resp = gate_run["writer_write"]
        assert resp.status_code == 200, f"writer write refused: {resp.text}"
        body = resp.json()
        assert body["success"] is True
        assert body["data"]["owner_id"] == gate_run["user_id"], (
            "the created row must belong to the acting writer, never to the actor "
            "substituted by the route"
        )

    def test_g2_downgrade_reports_generation_and_enqueued_revocation(
        self, gate_run: dict
    ):
        """The role change commits and reports its revocation side effects."""
        resp = gate_run["downgrade"]
        assert resp.status_code == 200, f"downgrade refused: {resp.text}"
        body = resp.json()
        assert body["role"] == "reader"
        assert body["is_superuser"] is False
        assert body["auth_generation"] > 1, (
            "an authorization transition must advance the user's generation"
        )
        assert body["revocation_enqueued"] is True, (
            "the role change must enqueue its revocation effects in the same "
            "transaction -- never a post-commit 503/202"
        )

    def test_g3a_old_token_cannot_write_after_downgrade(self, gate_run: dict):
        """The pre-downgrade token loses the capability it was minted with."""
        resp = gate_run["old_token_write"]
        assert resp.status_code != 200, (
            "the pre-downgrade token still wrote "
            f"{gate_run['propagation_seconds']:.1f}s after the downgrade "
            f"committed: {resp.text}"
        )
        assert resp.status_code in (401, 403), f"unexpected denial: {resp.status_code}"

    def test_g3b_old_token_is_revoked_not_merely_demoted(self, gate_run: dict):
        """The old session is gone, not just capped at the new role.

        A READER is entitled to read categories, so a denial on the read can
        only come from the session revocation the downgrade triggered. This is
        the assertion that fails if a stack is running hybrid/stateless or with
        the revocation client disabled.
        """
        resp = gate_run["old_token_read"]
        assert resp.status_code != 200, (
            "the pre-downgrade token still reads after the downgrade -- the "
            "session was demoted but not revoked (is the consumer stateful and "
            "fail-closed?)"
        )
        assert "revoked" in resp.text.lower(), (
            f"expected a revocation denial, got: {resp.status_code} {resp.text}"
        )

    def test_g4_fresh_reader_token_can_read(self, gate_run: dict):
        """A newly minted token carries the new role and may read."""
        resp = gate_run["reader_read"]
        assert resp.status_code == 200, f"fresh reader read refused: {resp.text}"
        assert resp.json()["count"] >= 1

    def test_g5_fresh_reader_token_cannot_write(self, gate_run: dict):
        """The new role is a real ceiling, with the canonical 403."""
        resp = gate_run["reader_write"]
        assert resp.status_code == 403, (
            f"expected the canonical 403 for a reader write, got "
            f"{resp.status_code}: {resp.text}"
        )
        assert "revoked" not in resp.text.lower(), (
            "the fresh token must be denied by the role guard, not by revocation"
        )
