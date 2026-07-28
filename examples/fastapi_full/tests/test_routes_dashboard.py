"""Dashboard route and controller regressions.

Three properties, each of which failed in a running PostgreSQL deployment:

* the dashboard is gated like the mutations it summarises, not merely
  authenticated — a role that cannot add or edit a category has nothing here;
* the owner-scoped filter binds the ``CHAR(36)`` column's **text** form, never
  a raw ``uuid.UUID`` (psycopg2 adapts one to ``uuid``, which PostgreSQL
  refuses to compare against a ``character`` column);
* a failed query answers with a generic message — never the statement, its
  bound parameters, or the server hint.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Iterator

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from fastapi_m8 import UserModel
from sqlalchemy import event
from sqlalchemy.exc import ProgrammingError

from fastapi_full.app.deps import get_current_active_writer
from fastapi_full.app.ownership import as_stored_owner_id
from fastapi_full.app.routes import dashboard as dashboard_routes
from fastapi_full.controllers.dashboard import DashboardController
from fastapi_full.core.deps import get_db
from fastapi_full.db_models.categories import Category
from fastapi_full.schemas.dashboard import RangeActivityType

WRITER_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
WRITER = UserModel(
    id=WRITER_ID,
    email="writer@example.com",
    role="writer",  # type: ignore[arg-type]
    is_superuser=False,
)
PLAIN_USER = UserModel(
    id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
    email="user@example.com",
    role="user",  # type: ignore[arg-type]
    is_superuser=False,
)

DASHBOARD_PATHS = ["/dashboard/users/activity/", "/dashboard/users/activity/current/"]


def _body(response: object) -> dict:
    """Decode the JSON error envelope a failed controller call answers with."""
    assert isinstance(response, JSONResponse)
    return json.loads(bytes(response.body))


def _route(path: str) -> Any:
    return next(r for r in dashboard_routes.router.routes if r.path == path)  # type: ignore[attr-defined]


def _principal_dependency(path: str) -> Any:
    """The callable the writer gate resolves its principal through.

    Overriding it authenticates the route while leaving the real role check in
    place, which is the thing under test.
    """
    gate = next(
        d
        for d in _route(path).dependant.dependencies
        if d.call is get_current_active_writer
    )
    return gate.dependencies[0].call


@pytest.fixture
def app_client(db_session) -> Iterator[tuple[TestClient, FastAPI]]:
    """The dashboard router with the DB and the writer gate stubbed."""
    app = FastAPI()
    app.include_router(dashboard_routes.router)
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_active_writer] = lambda: WRITER
    with TestClient(app) as client:
        yield client, app


class TestWriterGate:
    """The dashboard reports adds and edits, so it takes the add/edit gate."""

    @pytest.mark.parametrize("path", DASHBOARD_PATHS)
    def test_route_declares_the_writer_dependency(self, path: str) -> None:
        calls = [d.call for d in _route(path).dependant.dependencies]
        assert get_current_active_writer in calls

    def test_a_gated_principal_gets_its_activity(self, app_client) -> None:
        client, _ = app_client
        response = client.get("/dashboard/users/activity/")
        assert response.status_code == 200
        assert response.json()["activity"]["activity"][0]["model"] == "Category"

    @pytest.mark.parametrize("path", DASHBOARD_PATHS)
    def test_the_user_role_is_refused(self, db_session, path: str) -> None:
        """``user`` cannot add or edit a category, so it cannot read the summary."""
        app = FastAPI()
        app.include_router(dashboard_routes.router)
        app.dependency_overrides[get_db] = lambda: db_session
        app.dependency_overrides[_principal_dependency(path)] = lambda: PLAIN_USER

        with TestClient(app) as client:
            response = client.get(path)

        assert response.status_code == 403
        assert response.json() == {"detail": "The user doesn't have enough privileges"}


class TestOwnerFilterBinding:
    """``Category.owner_id`` is ``CHAR(36)``: the predicate binds text."""

    def test_stored_form_is_the_canonical_text(self) -> None:
        assert as_stored_owner_id(WRITER_ID) == str(WRITER_ID)
        assert as_stored_owner_id(str(WRITER_ID)) == str(WRITER_ID)

    def test_owner_scoped_query_never_binds_a_raw_uuid(self, db_session) -> None:
        """A raw ``uuid.UUID`` here is what PostgreSQL rejects at runtime.

        The SQLite surrogate adapts a ``uuid.UUID`` to text and would pass
        either way, so the parameters themselves are inspected.
        """
        bound: list[Any] = []

        def capture(conn, cursor, statement, parameters, context, executemany):
            bound.extend(
                parameters.values() if isinstance(parameters, dict) else parameters
            )

        engine = db_session.get_bind()
        event.listen(engine, "before_cursor_execute", capture)
        try:
            DashboardController.get_activity_count_by_model(
                session=db_session,
                current_user=WRITER,
                time_range=RangeActivityType.MONTH,
            )
        finally:
            event.remove(engine, "before_cursor_execute", capture)

        assert str(WRITER_ID) in bound
        assert not any(isinstance(value, uuid.UUID) for value in bound)

    def test_an_owner_only_counts_their_own_rows(self, db_session) -> None:
        db_session.add(Category(name="Mine", slug="mine", owner_id=WRITER_ID))
        db_session.add(Category(name="Theirs", slug="theirs", owner_id=uuid.uuid4()))
        db_session.commit()

        stats = DashboardController.get_activity_count_by_model(
            session=db_session,
            current_user=WRITER,
            time_range=RangeActivityType.MONTH,
        )
        assert stats["activity"][0]["added"] == 1


class TestNoStatementDisclosure:
    """A failed query never returns the statement it failed on."""

    @staticmethod
    def _failing_session() -> Any:
        class _Session:
            def exec(self, *_args: Any, **_kwargs: Any) -> Any:
                raise ProgrammingError(
                    "SELECT sum(...) FROM app_category WHERE app_category.owner_id = %(id)s",
                    {"id": str(WRITER_ID)},
                    Exception(
                        "operator does not exist: character = uuid\n"
                        "HINT:  No operator matches the given name."
                    ),
                )

            def rollback(self) -> None:
                return None

        return _Session()

    def test_body_carries_no_statement(self, caplog) -> None:
        with caplog.at_level(logging.WARNING):
            response = DashboardController.get_dash_users_stats(
                session=self._failing_session(),
                current_user=WRITER,
                time_range=RangeActivityType.MONTH,
            )
        serialized = json.dumps(_body(response))
        for leaked in ("SELECT", "app_category", "operator does not exist", "HINT"):
            assert leaked not in serialized

    def test_body_carries_a_generic_message(self) -> None:
        response = DashboardController.get_dash_users_stats(
            session=self._failing_session(),
            current_user=WRITER,
            time_range=RangeActivityType.MONTH,
        )
        body = _body(response)
        assert body["success"] is False
        assert body["errors"][0]["error"].startswith("An internal error occurred.")

    def test_the_statement_reaches_the_log(self, caplog) -> None:
        with caplog.at_level(logging.WARNING, logger="fastapi_full.core.exceptions"):
            DashboardController.get_dash_users_stats(
                session=self._failing_session(),
                current_user=WRITER,
                time_range=RangeActivityType.MONTH,
            )
        record = caplog.records[0]
        assert record.exc_info is not None
        assert "app_category" in str(record.exc_info[1])
