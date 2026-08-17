"""
Live Compose Exposure-Matrix Tests — item 5.2 (parameterized by topology)
=========================================================================
Target (public):   https://localhost:4430   (Traefik ``websecure`` entryPoint)
Target (internal): http://localhost:9000     (loopback-bound services entryPoint)

Run against a running compose stack::

    pytest tests/live/test_compose_exposure_matrix.py -v --no-cov
    EXPOSURE_TOPOLOGY=case_a pytest tests/live/test_compose_exposure_matrix.py

These tests assert the public/internal route-exposure *contract* from two
deployment topologies (see the combined remediation plan, item 5.2):

* **Case A — UI-only / closed (most secure).** Only the UI/gateway and the
  auth surface it fronts (login, JWKS) are public, plus the shallow liveness
  ``{API_PREFIX}/ping``. **No backend microservice route is public on its own**
  — ``/fastapi/*`` is reached only via the gateway.
* **Case B — external clients.** The selected service APIs are public over
  HTTPS (``/fastapi/*``), alongside ``/user/login/*``, JWKS, ``/user/google-api/*``
  and the shallow ``{API_PREFIX}/ping`` of each public service.

Select the topology with ``EXPOSURE_TOPOLOGY={case_a|case_b}``. The default is
``case_b`` because the shipped ``hardened_m8`` example routes **both** ``/user``
and ``/fastapi`` on the public entryPoint; deploy a UI-only profile (only the
gateway public) and set ``EXPOSURE_TOPOLOGY=case_a`` to assert the closed
topology.

**Public denied in BOTH topologies** (the real security contract, asserted
unconditionally): private inter-service routes, ``/metrics``, the *detailed*
``/health/`` body, and infra surfaces (Traefik dashboard/API, Prometheus,
Grafana). ``/health/`` may answer publicly with shallow ``{"status": ...}``;
only the infrastructure **detail** body must never leave the network — that
gate lives in the app (1.4), proxy route-hiding is defense-in-depth.

The whole module auto-skips when the stack is unreachable (see conftest +
the ``public_entrypoint`` / ``internal_entrypoint`` fixtures).
"""

import os
import uuid

import pytest
import requests
import urllib3

from tests.live.suites.auth_flows import TIMEOUT

pytestmark = [pytest.mark.live, pytest.mark.live_security]

# The public entryPoint serves a self-signed cert in the example stacks; quiet
# the per-request warning so the matrix output stays readable.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Entry points & prefixes ──────────────────────────────────────────────────
# Defaults describe the maintained Compose examples; the ``LIVE_*`` overrides
# retarget the matrix at another stack's entryPoints and consumer prefix.
PUBLIC_BASE = os.environ.get("LIVE_PUBLIC_BASE", "https://localhost:4430")
INTERNAL_BASE = os.environ.get("LIVE_INTERNAL_BASE", "http://localhost:9000")
AUTH_PREFIX = os.environ.get("LIVE_AUTH_PREFIX", "/user")
SVC_PREFIX = os.environ.get("LIVE_SVC_PREFIX", "/fastapi")

# ── Topology selection ───────────────────────────────────────────────────────
CASE_A = "case_a"
CASE_B = "case_b"
TOPOLOGY = os.environ.get("EXPOSURE_TOPOLOGY", CASE_B).strip().lower()

# ── Allow-lists (table-driven, per topology) ─────────────────────────────────
# Routes that MUST be publicly reachable (routed to the app — not a proxy 404).
_PUBLIC_ALLOWED_COMMON: list[tuple[str, str]] = [
    (f"{AUTH_PREFIX}/login/access-token", "POST"),
    (f"{AUTH_PREFIX}/.well-known/jwks.json", "GET"),
    (f"{AUTH_PREFIX}/ping", "GET"),
]
_PUBLIC_ALLOWED_CASE_B_EXTRA: list[tuple[str, str]] = [
    (f"{AUTH_PREFIX}/google-api/login-url/", "GET"),
    (f"{SVC_PREFIX}/ping", "GET"),
    (f"{SVC_PREFIX}/meta", "GET"),
]

# Case A additionally requires that no backend service route is public at all.
_CASE_A_DENIED_SERVICE: list[tuple[str, str]] = [
    (f"{SVC_PREFIX}/ping", "GET"),
    (f"{SVC_PREFIX}/meta", "GET"),
    (f"{SVC_PREFIX}/", "GET"),
]


def _public_allowed() -> list[tuple[str, str]]:
    """Allowed public routes for the active topology."""
    if TOPOLOGY == CASE_A:
        return _PUBLIC_ALLOWED_COMMON
    return _PUBLIC_ALLOWED_COMMON + _PUBLIC_ALLOWED_CASE_B_EXTRA


# ── Deny-lists (table-driven, shared by BOTH topologies) ─────────────────────
_PRIVATE_ROUTES: list[tuple[str, str]] = [
    (f"{AUTH_PREFIX}/private/users/", "POST"),
    (f"{AUTH_PREFIX}/private/v1/jti-status", "POST"),
    (f"{AUTH_PREFIX}/private/v1/events/stream", "GET"),
]
_METRICS_ROUTES: list[str] = [
    f"{AUTH_PREFIX}/metrics",
    f"{SVC_PREFIX}/metrics",
]
_DEEP_HEALTH_ROUTES: list[str] = [
    f"{AUTH_PREFIX}/health/",
    f"{SVC_PREFIX}/health/",
]
# Infra/control-plane surfaces that must never answer on the public entryPoint.
_INFRA_PUBLIC_DENIED: list[str] = [
    "/dashboard/",
    "/api/overview",
    "/metrics",
]
# Keys that only appear in the *detailed* health body (1.4 token-gated detail).
_HEALTH_DETAIL_KEYS = frozenset(
    {
        "redis",
        "database",
        "token_mode",
        "effective_mode",
        "circuit_breaker",
        "degradation_modes",
    }
)


# ── Request helpers ──────────────────────────────────────────────────────────


def _public_request(path: str, method: str = "GET") -> requests.Response:
    """Issue a request to the public HTTPS entryPoint (self-signed cert)."""
    return requests.request(
        method,
        f"{PUBLIC_BASE}{path}",
        timeout=TIMEOUT,
        verify=False,  # noqa: S501 — example stacks use a self-signed cert
    )


# ── Reachability fixtures (skip when the stack is down) ──────────────────────


@pytest.fixture(scope="session")
def public_entrypoint() -> str:
    """Public HTTPS entryPoint; skip the matrix when it is unreachable."""
    try:
        _public_request(f"{AUTH_PREFIX}/ping")
    except requests.exceptions.RequestException as exc:
        pytest.skip(f"public entrypoint {PUBLIC_BASE} unreachable: {exc}")
    return PUBLIC_BASE


@pytest.fixture(scope="session")
def internal_entrypoint() -> str:
    """Internal services entryPoint; skip when it is unreachable."""
    try:
        requests.get(f"{INTERNAL_BASE}{AUTH_PREFIX}/ping", timeout=TIMEOUT)
    except requests.exceptions.RequestException as exc:
        pytest.skip(f"internal entrypoint {INTERNAL_BASE} unreachable: {exc}")
    return INTERNAL_BASE


@pytest.fixture(scope="session")
def private_api_secret() -> str:
    """The live stack's inter-service secret (positive control only).

    Read from ``LIVE_PRIVATE_API_SECRET`` and never from ``PRIVATE_API_SECRET``:
    the suite's root conftest seeds the latter with a hermetic throwaway before
    any import, so keying on it would defeat this fixture's own skip and send a
    wrong secret to the live stack instead.
    """
    secret = os.environ.get("LIVE_PRIVATE_API_SECRET")
    if not secret:
        pytest.skip(
            "LIVE_PRIVATE_API_SECRET not set — internal positive control skipped"
        )
    return secret


@pytest.fixture(scope="session")
def private_api_client_id() -> str | None:
    """The consumer id this positive control authenticates as, if any.

    ``fa-auth-m8`` >= 1.0.0 runs a per-consumer private API: the secret alone is
    rejected 401 by design and the caller must also identify itself with
    ``X-Internal-Client``. Leave ``LIVE_PRIVATE_API_CLIENT_ID`` unset for a
    legacy single-secret stack.
    """
    return os.environ.get("LIVE_PRIVATE_API_CLIENT_ID") or None


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC — allowed surface (per topology)
# ═══════════════════════════════════════════════════════════════════════════


class TestPublicAllowed:
    """The intended public surface for the active topology is routed."""

    @pytest.mark.parametrize("path,method", _public_allowed())
    def test_allowed_route_is_publicly_routed(
        self, public_entrypoint: str, path: str, method: str
    ) -> None:
        """An allowed route reaches the app (any status except a proxy 404)."""
        r = _public_request(path, method)
        assert r.status_code != 404, (
            f"[EXPOSURE {TOPOLOGY}] {method} {path} should be public but the "
            f"proxy returned 404 (route not exposed). "
            f"Check the public router rule for this prefix."
        )


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC — denied surface (BOTH topologies)
# ═══════════════════════════════════════════════════════════════════════════


class TestPublicDeniedPrivate:
    """Inter-service ``/private`` routes are never publicly reachable."""

    @pytest.mark.parametrize("path,method", _PRIVATE_ROUTES)
    def test_private_route_not_public(
        self, public_entrypoint: str, path: str, method: str
    ) -> None:
        """Private routes return 401/403/404 publicly — never a 2xx success."""
        r = _public_request(path, method)
        assert r.status_code in (401, 403, 404), (
            f"[EXPOSURE] {method} {path} is reachable from the public internet "
            f"(status {r.status_code}). Private routes must be excluded at the "
            f"proxy AND require X-Internal-Token at the app layer."
        )


class TestPublicDeniedMetrics:
    """``/metrics`` never serves a Prometheus body to the public internet."""

    @pytest.mark.parametrize("path", _METRICS_ROUTES)
    def test_metrics_not_public(self, public_entrypoint: str, path: str) -> None:
        r = _public_request(path)
        assert r.status_code in (401, 403, 404), (
            f"[EXPOSURE] {path} answered publicly with status {r.status_code}; "
            f"metrics must be internal-only or scrape-credential gated."
        )
        assert "# HELP" not in r.text and "# TYPE" not in r.text, (
            f"[EXPOSURE] {path} leaked a Prometheus metrics body to the public "
            f"internet."
        )


class TestPublicDeniedHealthDetail:
    """``/health/`` may answer shallow publicly; the detail body must not leak."""

    @pytest.mark.parametrize("path", _DEEP_HEALTH_ROUTES)
    def test_health_detail_not_public(self, public_entrypoint: str, path: str) -> None:
        r = _public_request(path)
        if r.status_code == 404:
            return  # route-excluded at the proxy — detail unreachable either way
        assert r.status_code == 200, (
            f"[EXPOSURE] {path} returned unexpected status {r.status_code}."
        )
        leaked = _HEALTH_DETAIL_KEYS & set(r.json())
        assert not leaked, (
            f"[EXPOSURE] {path} leaked infrastructure health detail publicly: "
            f"{sorted(leaked)}. The detail body must be token-gated (1.4)."
        )


class TestPublicDeniedInfra:
    """Traefik dashboard/API and scrape surfaces are not on the public port."""

    @pytest.mark.parametrize("path", _INFRA_PUBLIC_DENIED)
    def test_infra_not_public(self, public_entrypoint: str, path: str) -> None:
        r = _public_request(path)
        assert r.status_code == 404, (
            f"[EXPOSURE] infra surface {path} answered on the public entryPoint "
            f"(status {r.status_code}); it must not be routed there."
        )


@pytest.mark.skipif(
    TOPOLOGY != CASE_A, reason="Case A (UI-only) closed-topology assertion only"
)
class TestCaseAClosedBackend:
    """Case A: no backend microservice route is public on its own."""

    @pytest.mark.parametrize("path,method", _CASE_A_DENIED_SERVICE)
    def test_backend_service_not_public(
        self, public_entrypoint: str, path: str, method: str
    ) -> None:
        r = _public_request(path, method)
        assert r.status_code == 404, (
            f"[EXPOSURE case_a] {method} {path} is public, but Case A (UI-only) "
            f"requires backend services to be reachable only via the gateway. "
            f"Got status {r.status_code}."
        )


# ═══════════════════════════════════════════════════════════════════════════
# INTERNAL — reachable with source + secret only
# ═══════════════════════════════════════════════════════════════════════════


class TestInternalSecretGated:
    """Private routes answer on the internal entryPoint only with the secret."""

    _JTI = f"{AUTH_PREFIX}/private/v1/jti-status"

    def test_jti_status_rejected_without_token(self, internal_entrypoint: str) -> None:
        """Internally reachable, but rejected without X-Internal-Token."""
        r = requests.post(
            f"{INTERNAL_BASE}{self._JTI}",
            json={"jti": uuid.uuid4().hex},
            timeout=TIMEOUT,
        )
        assert r.status_code in (401, 403), (
            f"[EXPOSURE] {self._JTI} accepted an unauthenticated internal call "
            f"(status {r.status_code}); it must require X-Internal-Token."
        )

    def test_jti_status_reachable_with_token(
        self,
        internal_entrypoint: str,
        private_api_secret: str,
        private_api_client_id: "str | None",
    ) -> None:
        """With the correct credential the route is reachable and authorized."""
        headers = {"X-Internal-Token": private_api_secret}
        if private_api_client_id:
            headers["X-Internal-Client"] = private_api_client_id
        r = requests.post(
            f"{INTERNAL_BASE}{self._JTI}",
            json={"jti": uuid.uuid4().hex},
            headers=headers,
            timeout=TIMEOUT,
        )
        assert r.status_code not in (401, 403, 404), (
            f"[EXPOSURE] {self._JTI} unreachable with a valid internal token "
            f"(status {r.status_code})."
        )
