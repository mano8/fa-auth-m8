"""Category-route unique-name collision tests (G9-7).

The example previously routed the ``Category.name``/``slug`` unique-constraint
``IntegrityError`` through ``handle_route_exception``, which answers ``500`` —
indistinguishable from a genuine server failure. These tests prove both the
create and edit paths now answer ``409`` with a non-enumerating detail,
mirroring the issuer's email-``409`` branch in ``routes/users.py``.
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

OWNER_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")


def _writer(user_id: uuid.UUID = OWNER_ID) -> UserModel:
    return UserModel(
        id=user_id,
        email="actor@example.com",
        role="writer",  # type: ignore[arg-type]
        is_superuser=False,
    )


WRITER = _writer()


@pytest.fixture
def app_client(db_session) -> Iterator[tuple[TestClient, FastAPI]]:
    """The category router with the DB, guards, and owner lookup stubbed."""
    app = FastAPI()
    app.include_router(category_routes.router)
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_owner_verifier] = lambda: lambda user_id: True
    app.dependency_overrides[get_current_active_reader] = lambda: WRITER
    app.dependency_overrides[get_current_active_writer] = lambda: WRITER
    with TestClient(app) as client:
        yield client, app


def _audit_rows(session) -> list[PrivilegedActionAudit]:
    return list(session.exec(select(PrivilegedActionAudit)).all())


def _category(session, *, owner_id: uuid.UUID, name: str = "News") -> Category:
    item = Category(name=name, slug=name.lower(), owner_id=owner_id)
    session.add(item)
    session.commit()
    session.refresh(item)
    return item


class TestCreateDuplicateNameAnswers409:
    def test_duplicate_name_on_create_answers_409_not_500(self, app_client, db_session):
        client, _ = app_client
        _category(db_session, owner_id=OWNER_ID, name="News")

        response = client.post("/category/add/", json={"name": "News"})

        assert response.status_code == 409
        assert response.json()["detail"] == "A category with this name already exists"

    def test_duplicate_name_on_create_leaves_no_audit_row(self, app_client, db_session):
        client, _ = app_client
        _category(db_session, owner_id=OWNER_ID, name="News")

        client.post("/category/add/", json={"name": "News"})

        assert _audit_rows(db_session) == []
        assert len(db_session.exec(select(Category)).all()) == 1


class TestEditDuplicateNameAnswers409:
    def test_rename_to_an_existing_name_answers_409_not_500(
        self, app_client, db_session
    ):
        client, _ = app_client
        _category(db_session, owner_id=OWNER_ID, name="News")
        target = _category(db_session, owner_id=OWNER_ID, name="Sports")

        response = client.put(f"/category/edit/{target.id}/", json={"name": "News"})

        assert response.status_code == 409
        assert response.json()["detail"] == "A category with this name already exists"

    def test_rename_to_an_existing_name_leaves_the_original_row_unchanged(
        self, app_client, db_session
    ):
        client, _ = app_client
        _category(db_session, owner_id=OWNER_ID, name="News")
        target = _category(db_session, owner_id=OWNER_ID, name="Sports")

        client.put(f"/category/edit/{target.id}/", json={"name": "News"})

        db_session.refresh(target)
        assert target.name == "Sports"
        assert _audit_rows(db_session) == []
