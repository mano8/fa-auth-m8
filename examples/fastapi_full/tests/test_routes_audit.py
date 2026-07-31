"""Audit-route tests for the consumer example (Phase 7).

Covers what the routes are responsible for and the audit rules are not: which
guard each route is wired to, that neither is published in the OpenAPI schema,
that no write/update/targeted-delete endpoint exists for the table at all, and
the read-scope and floor-rejection behaviour as an operator actually sees it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi_m8 import UserModel
from pydantic import ValidationError

from fastapi_full.app.routes import audit as audit_routes
from fastapi_full.core.deps import (
    get_current_active_admin,
    get_current_active_superuser,
    get_db,
)
from fastapi_full.db_models.categories import Category
from fastapi_full.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)

ACTOR_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")

AUDIT_LOG_PATH = "/security/audit-log"
AUDIT_PURGE_PATH = "/security/audit-log/purge"


def _user(role: str, is_superuser: bool, user_id: uuid.UUID = ACTOR_ID) -> UserModel:
    return UserModel(
        id=user_id,
        email="actor@example.com",
        role=role,  # type: ignore[arg-type]
        is_superuser=is_superuser,
    )


def _audit_row(actor: uuid.UUID, *, created_at: datetime) -> PrivilegedActionAudit:
    return PrivilegedActionAudit(
        actor_user_id=actor,
        actor_role="superadmin",
        action=AuditAction.EDIT,
        table_name=str(Category.__tablename__),
        row_pk="5",
        target_owner_id=str(OTHER_ID),
        created_at=created_at,
    )


def _route(path: str, method: str):
    """Return the audit router's route for *path*/*method*."""
    for route in audit_routes.router.routes:
        if getattr(route, "path", None) == path and method in getattr(
            route, "methods", set()
        ):
            return route
    raise AssertionError(f"no {method} route for {path}")


@pytest.fixture
def client(db_session):
    """A minimal app carrying only the audit router, with both guards stubbed.

    Every test overrides the principal it needs; the guards themselves belong to
    ``fastapi-m8`` and are covered by that package's own suite.
    """
    app = FastAPI()
    app.include_router(audit_routes.router)
    app.dependency_overrides[get_db] = lambda: db_session
    with TestClient(app) as test_client:
        yield test_client, app


class TestRouteWiring:
    """The surface itself: two read/maintenance routes, nothing else."""

    def test_no_create_update_or_targeted_delete_endpoint_exists(self) -> None:
        methods = {
            (getattr(route, "path", None), method)
            for route in audit_routes.router.routes
            for method in getattr(route, "methods", set())
        }
        assert methods == {
            (AUDIT_LOG_PATH, "GET"),
            (AUDIT_PURGE_PATH, "POST"),
        }

    def test_read_route_is_gated_at_admin(self) -> None:
        route = _route(AUDIT_LOG_PATH, "GET")
        dependants = {d.call for d in route.dependant.dependencies}
        assert get_current_active_admin in dependants

    def test_purge_route_is_gated_at_superuser(self) -> None:
        route = _route(AUDIT_PURGE_PATH, "POST")
        dependants = {d.call for d in route.dependant.dependencies}
        assert get_current_active_superuser in dependants

    @pytest.mark.parametrize(
        ("path", "method"),
        [(AUDIT_LOG_PATH, "GET"), (AUDIT_PURGE_PATH, "POST")],
    )
    def test_routes_are_excluded_from_the_openapi_schema(
        self, path: str, method: str
    ) -> None:
        assert _route(path, method).include_in_schema is False


class TestReadAuditLogRoute:
    def test_superadmin_sees_every_row(self, client, db_session) -> None:
        test_client, app = client
        db_session.add(_audit_row(ACTOR_ID, created_at=datetime.now(timezone.utc)))
        db_session.add(_audit_row(OTHER_ID, created_at=datetime.now(timezone.utc)))
        db_session.commit()
        app.dependency_overrides[get_current_active_admin] = lambda: _user(
            "superadmin", True
        )

        body = test_client.get(AUDIT_LOG_PATH).json()

        assert body["count"] == 2
        assert len(body["data"]) == 2

    def test_admin_sees_only_rows_it_authored(self, client, db_session) -> None:
        test_client, app = client
        db_session.add(_audit_row(ACTOR_ID, created_at=datetime.now(timezone.utc)))
        db_session.add(_audit_row(OTHER_ID, created_at=datetime.now(timezone.utc)))
        db_session.commit()
        app.dependency_overrides[get_current_active_admin] = lambda: _user(
            "admin", False
        )

        body = test_client.get(AUDIT_LOG_PATH).json()

        assert body["count"] == 1
        assert body["data"][0]["actor_user_id"] == str(ACTOR_ID)

    def test_admin_view_is_empty_when_it_authored_nothing(
        self, client, db_session
    ) -> None:
        """Only a superadmin can mutate non-owned data here, so this is the
        expected admin-own result rather than a filter that silently passes."""
        test_client, app = client
        db_session.add(_audit_row(OTHER_ID, created_at=datetime.now(timezone.utc)))
        db_session.commit()
        app.dependency_overrides[get_current_active_admin] = lambda: _user(
            "admin", False
        )

        body = test_client.get(AUDIT_LOG_PATH).json()

        assert body == {"data": [], "count": 0}

    def test_a_stray_superuser_flag_cannot_reach_the_read_scope(self) -> None:
        """The read scope uses the canonical dual-evidence predicate, and an
        inconsistent claim pair is rejected a layer earlier: a principal with
        ``is_superuser=True`` on a non-SUPERADMIN role does not validate at all,
        so no such caller ever arrives at the widening branch."""
        with pytest.raises(ValidationError):
            _user("admin", True)

    def test_response_carries_only_the_recorded_fields(self, client, db_session):
        test_client, app = client
        db_session.add(_audit_row(ACTOR_ID, created_at=datetime.now(timezone.utc)))
        db_session.commit()
        app.dependency_overrides[get_current_active_admin] = lambda: _user(
            "superadmin", True
        )

        row = test_client.get(AUDIT_LOG_PATH).json()["data"][0]

        assert set(row) == {
            "id",
            "created_at",
            "actor_user_id",
            "actor_role",
            "action",
            "table_name",
            "row_pk",
            "target_owner_id",
        }


class TestPurgeAuditLogRoute:
    def test_purges_rows_older_than_the_window(self, client, db_session) -> None:
        test_client, app = client
        db_session.add(
            _audit_row(
                ACTOR_ID,
                created_at=datetime.now(timezone.utc) - timedelta(days=400),
            )
        )
        db_session.commit()
        app.dependency_overrides[get_current_active_superuser] = lambda: _user(
            "superadmin", True
        )

        response = test_client.post(AUDIT_PURGE_PATH, json={"window": "1y"})

        assert response.status_code == 200
        assert response.json() == {"window": "1y", "removed": 1}

    def test_window_below_the_retention_floor_is_rejected(self, client) -> None:
        test_client, app = client
        app.dependency_overrides[get_current_active_superuser] = lambda: _user(
            "superadmin", True
        )

        response = test_client.post(AUDIT_PURGE_PATH, json={"window": "1w"})

        assert response.status_code == 400
        assert "minimum-retention floor" in response.json()["detail"]

    def test_an_unknown_window_is_rejected_by_validation(self, client) -> None:
        test_client, app = client
        app.dependency_overrides[get_current_active_superuser] = lambda: _user(
            "superadmin", True
        )

        assert (
            test_client.post(AUDIT_PURGE_PATH, json={"window": "1d"}).status_code == 422
        )

    def test_request_body_carries_no_row_identifier(self, client) -> None:
        """A targeted purge is not expressible: the body has one field."""
        assert set(audit_routes.AuditPurgeRequest.model_fields) == {"window"}
