"""11.11 — Route inventory and exposure classification.

Locks the fa-auth-m8 route surface so:
- Adding or removing a route requires an explicit update to
  ``auth_user_service/route_inventory.json``.
- Every route in the inventory carries an exposure label
  (public / authenticated / admin / internal / health / metrics / api-key).
- Private and internal routes are absent from the OpenAPI schema.
- The metrics endpoint, when enabled, is excluded from the schema.
- The Traefik router classification of internal routes matches the
  internal-only exposure declared in the inventory.

The test reads the live app route table (not a subprocess) to avoid the
gap between static analysis and what FastAPI actually registers.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.routing import APIRoute

from auth_user_service.main import app

_REPO_ROOT = Path(__file__).resolve().parents[2]
_INVENTORY_FILE = _REPO_ROOT / "auth_user_service" / "route_inventory.json"

# Exposure classes that must NEVER appear in the OpenAPI schema.
_SCHEMA_EXCLUDED_EXPOSURES = {"internal", "health", "metrics"}

# Exposure classes that must be routed via the internal (non-public) entrypoint.
_INTERNAL_TRAEFIK_EXPOSURES = {"internal", "metrics"}


def _load_inventory() -> list[dict]:
    return json.loads(_INVENTORY_FILE.read_text(encoding="utf-8"))


def _app_routes() -> list[dict]:
    """Return (path, method) pairs for every APIRoute registered in the app."""
    result = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            for method in sorted(route.methods or {"GET"}):
                result.append(
                    {
                        "path": route.path,
                        "method": method,
                        "include_in_schema": route.include_in_schema,
                    }
                )
    return result


class TestInventoryFile:
    """The committed inventory file is valid and complete."""

    def test_inventory_file_exists(self):
        assert _INVENTORY_FILE.exists(), (
            f"Route inventory not found at {_INVENTORY_FILE}. "
            "Generate it and commit before shipping."
        )

    def test_inventory_is_valid_json(self):
        data = json.loads(_INVENTORY_FILE.read_text(encoding="utf-8"))
        assert isinstance(data, list) and len(data) > 0

    def test_every_entry_has_required_fields(self):
        required = {"path", "method", "tag", "exposure", "in_openapi", "traefik_router"}
        for entry in _load_inventory():
            missing = required - entry.keys()
            assert not missing, (
                f"Inventory entry {entry.get('path')} is missing fields: {missing}"
            )

    def test_exposure_labels_are_known(self):
        known = {
            "public",
            "authenticated",
            "admin",
            "internal",
            "health",
            "metrics",
            "api-key",
        }
        for entry in _load_inventory():
            assert entry["exposure"] in known, (
                f"Unknown exposure '{entry['exposure']}' on {entry['path']}"
            )

    def test_traefik_router_labels_are_known(self):
        known = {"public", "internal"}
        for entry in _load_inventory():
            assert entry["traefik_router"] in known, (
                f"Unknown traefik_router '{entry['traefik_router']}' on {entry['path']}"
            )


class TestRouteInventoryMatchesApp:
    """The inventory matches the live app route table — fails if routes drift."""

    def test_inventory_covers_all_app_routes(self):
        """Every route the app registers must appear in the inventory.

        Fails when a route is added without updating route_inventory.json.
        """
        inventory_keys = {(e["path"], e["method"]) for e in _load_inventory()}
        app_routes = _app_routes()
        missing = []
        for route in app_routes:
            key = (route["path"], route["method"])
            if key not in inventory_keys:
                missing.append(f"{route['method']} {route['path']}")

        assert not missing, (
            "These app routes are missing from route_inventory.json — "
            "add them with an exposure label before merging:\n"
            + "\n".join(f"  {r}" for r in sorted(missing))
        )

    def test_no_stale_inventory_entries(self):
        """Every inventory entry must correspond to an actual app route.

        Fails when a route is removed without updating route_inventory.json.
        """
        app_keys = {(r["path"], r["method"]) for r in _app_routes()}
        stale = []
        for entry in _load_inventory():
            key = (entry["path"], entry["method"])
            if key not in app_keys:
                stale.append(f"{entry['method']} {entry['path']}")

        assert not stale, (
            "These inventory entries have no matching app route — "
            "remove them from route_inventory.json:\n"
            + "\n".join(f"  {r}" for r in sorted(stale))
        )

    def test_in_openapi_flag_matches_app(self):
        """The inventory's in_openapi flag must match route.include_in_schema."""
        # Build a lookup of (path, method) → include_in_schema from the live app.
        app_schema_map = {
            (r["path"], r["method"]): r["include_in_schema"] for r in _app_routes()
        }
        mismatches = []
        for entry in _load_inventory():
            key = (entry["path"], entry["method"])
            if key not in app_schema_map:
                continue  # covered by test_no_stale_inventory_entries
            actual = app_schema_map[key]
            declared = entry["in_openapi"]
            if actual != declared:
                mismatches.append(
                    f"{entry['method']} {entry['path']}: "
                    f"inventory says in_openapi={declared}, app says {actual}"
                )
        assert not mismatches, (
            "in_openapi flag mismatch between inventory and app:\n"
            + "\n".join(f"  {m}" for m in mismatches)
        )


class TestExposureClassification:
    """Exposure labels drive the security boundary — invariants must hold."""

    def test_internal_routes_excluded_from_openapi(self):
        """Internal routes must not appear in the OpenAPI schema."""
        violations = [
            f"{e['method']} {e['path']}"
            for e in _load_inventory()
            if e["exposure"] in _SCHEMA_EXCLUDED_EXPOSURES and e["in_openapi"]
        ]
        assert not violations, (
            "These routes have an excluded exposure class but in_openapi=true:\n"
            + "\n".join(f"  {v}" for v in violations)
        )

    def test_internal_routes_use_internal_traefik_router(self):
        """Routes with internal exposure must declare the internal Traefik router."""
        violations = [
            f"{e['method']} {e['path']}"
            for e in _load_inventory()
            if e["exposure"] in _INTERNAL_TRAEFIK_EXPOSURES
            and e["traefik_router"] != "internal"
        ]
        assert not violations, (
            "These internal-exposure routes declare traefik_router=public:\n"
            + "\n".join(f"  {v}" for v in violations)
        )

    def test_private_tag_routes_are_classified_internal(self):
        """All routes tagged 'private' must have exposure=internal."""
        violations = [
            f"{e['method']} {e['path']}"
            for e in _load_inventory()
            if e["tag"] == "private" and e["exposure"] != "internal"
        ]
        assert not violations, (
            "These 'private' tagged routes are not classified as internal:\n"
            + "\n".join(f"  {v}" for v in violations)
        )

    def test_health_route_not_in_openapi(self):
        """The health endpoint must not be in the OpenAPI schema (exposure=health)."""
        health_entries = [e for e in _load_inventory() if e["exposure"] == "health"]
        assert health_entries, "No health-exposure routes found in inventory"
        for entry in health_entries:
            assert not entry["in_openapi"], (
                f"Health route {entry['path']} must not appear in OpenAPI schema"
            )


class TestOpenApiExcludesSecuritySensitivePaths:
    """The live OpenAPI spec must not expose internal/private/health paths."""

    def test_private_prefix_absent_from_openapi_paths(self):
        """No /private path appears in the generated OpenAPI spec."""
        spec = app.openapi()
        paths = spec.get("paths", {})
        private_paths = [p for p in paths if "/private" in p]
        assert not private_paths, (
            "Private paths found in OpenAPI spec — add include_in_schema=False:\n"
            + "\n".join(f"  {p}" for p in private_paths)
        )

    def test_health_path_absent_from_openapi_paths(self):
        """The /health path is excluded from the OpenAPI spec."""
        spec = app.openapi()
        paths = spec.get("paths", {})
        health_paths = [
            p for p in paths if p.endswith("/health/") or p.endswith("/health")
        ]
        assert not health_paths, (
            "Health paths found in OpenAPI spec — add include_in_schema=False:\n"
            + "\n".join(f"  {p}" for p in health_paths)
        )

    def test_metrics_path_absent_from_openapi_paths(self):
        """The /metrics path is excluded from the OpenAPI spec."""
        spec = app.openapi()
        paths = spec.get("paths", {})
        metrics_paths = [p for p in paths if p.endswith("/metrics")]
        assert not metrics_paths, (
            "Metrics paths found in OpenAPI spec — add include_in_schema=False:\n"
            + "\n".join(f"  {p}" for p in metrics_paths)
        )
