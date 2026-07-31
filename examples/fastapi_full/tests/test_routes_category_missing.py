"""Category-route missing-item tests (P9-15, G9-12).

The bundled example's ``app/routes/category.py`` carried three uncovered
not-found branches. They are not authorization branches, so the Phase 6
final-review criterion held without them — but the example's suite ran with no
coverage gate at all, and these are exactly the lines a gate exists to keep
measured.

They also record a real asymmetry rather than hiding it: ``read_item`` answers
``200`` with ``success=False`` for a missing row, while ``update_item`` and
``delete_item`` answer ``404``. The shapes are asserted here as they ship; no
item owns changing the example's response contract.
"""

from __future__ import annotations

import uuid
from typing import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi_m8 import UserModel
from sqlmodel import select

from fastapi_full.app.routes import category as category_routes
from fastapi_full.core.deps import (
    get_current_active_reader,
    get_current_active_writer,
    get_db,
    get_owner_verifier,
)
from fastapi_full.db_models.categories import Category
from fastapi_full.db_models.privileged_action_audit import PrivilegedActionAudit

OWNER_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")
MISSING_ID = 999999

WRITER = UserModel(
    id=OWNER_ID,
    email="actor@example.com",
    role="writer",  # type: ignore[arg-type]
    is_superuser=False,
)


@pytest.fixture
def app_client(db_session) -> Iterator[TestClient]:
    """The category router with the DB, guards, and owner lookup stubbed."""
    app = FastAPI()
    app.include_router(category_routes.router)
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_owner_verifier] = lambda: lambda user_id: True
    app.dependency_overrides[get_current_active_reader] = lambda: WRITER
    app.dependency_overrides[get_current_active_writer] = lambda: WRITER
    with TestClient(app) as client:
        yield client


def _audit_rows(session) -> list[PrivilegedActionAudit]:
    return list(session.exec(select(PrivilegedActionAudit)).all())


class TestReadMissingItem:
    def test_read_reports_not_found_without_raising(self, app_client):
        response = app_client.get(f"/category/get/{MISSING_ID}/")

        assert response.status_code == 200
        body = response.json()
        assert body["success"] is False
        assert body["msg"] == "Item not found."


class TestUpdateMissingItem:
    def test_update_answers_404(self, app_client):
        response = app_client.put(
            f"/category/edit/{MISSING_ID}/", json={"name": "Renamed"}
        )

        assert response.status_code == 404
        assert response.json()["detail"] == "Item not found"

    def test_update_writes_no_audit_row_and_creates_nothing(
        self, app_client, db_session
    ):
        app_client.put(f"/category/edit/{MISSING_ID}/", json={"name": "Renamed"})

        assert _audit_rows(db_session) == []
        assert db_session.exec(select(Category)).all() == []


class TestDeleteMissingItem:
    def test_delete_answers_404(self, app_client):
        response = app_client.delete(f"/category/delete/{MISSING_ID}/")

        assert response.status_code == 404
        assert response.json()["detail"] == "Item not found"

    def test_delete_writes_no_audit_row(self, app_client, db_session):
        app_client.delete(f"/category/delete/{MISSING_ID}/")

        assert _audit_rows(db_session) == []
