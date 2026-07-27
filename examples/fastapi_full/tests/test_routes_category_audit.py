"""Category-route audit integration tests (Phase 7).

Proves the property the recorder exists for, end to end over the routes an
operator actually calls: a superadmin's mutation of **non-owned** category data
commits together with exactly one audit row, ordinary work on one's own data
records nothing, and a refused mutation leaves no audit row behind.
"""

from __future__ import annotations

import uuid
from typing import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi_m8 import UserModel
from sqlmodel import select

from fastapi_full.app.ownership import as_owner_id
from fastapi_full.app.routes import category as category_routes
from fastapi_full.core.deps import (
    get_current_active_reader,
    get_current_active_writer,
    get_db,
    get_owner_verifier,
)
from fastapi_full.db_models.categories import Category
from fastapi_full.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)

SUPERADMIN_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
OWNER_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")


def _user(role: str, is_superuser: bool, user_id: uuid.UUID) -> UserModel:
    return UserModel(
        id=user_id,
        email="actor@example.com",
        role=role,  # type: ignore[arg-type]
        is_superuser=is_superuser,
    )


SUPERADMIN = _user("superadmin", True, SUPERADMIN_ID)
WRITER = _user("writer", False, OWNER_ID)


@pytest.fixture
def app_client(db_session) -> Iterator[tuple[TestClient, FastAPI]]:
    """The category router with the DB, guards, and owner lookup stubbed."""
    app = FastAPI()
    app.include_router(category_routes.router)
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_owner_verifier] = lambda: lambda user_id: True
    app.dependency_overrides[get_current_active_reader] = lambda: SUPERADMIN
    with TestClient(app) as client:
        yield client, app


def _as(app: FastAPI, actor: UserModel) -> None:
    """Authenticate the writer-gated routes as *actor*."""
    app.dependency_overrides[get_current_active_writer] = lambda: actor


def _audit_rows(session) -> list[PrivilegedActionAudit]:
    return list(session.exec(select(PrivilegedActionAudit)).all())


def _category(session, *, owner_id: uuid.UUID, name: str = "News") -> Category:
    item = Category(name=name, slug=name.lower(), owner_id=owner_id)
    session.add(item)
    session.commit()
    session.refresh(item)
    return item


class TestCreateIsAudited:
    def test_cross_owner_create_writes_one_add_row(self, app_client, db_session):
        client, app = app_client
        _as(app, SUPERADMIN)

        response = client.post(
            "/category/add/",
            json={"name": "News", "target_owner_id": str(OWNER_ID)},
        )

        assert response.status_code == 200
        rows = _audit_rows(db_session)
        assert len(rows) == 1
        row = rows[0]
        assert row.action == AuditAction.ADD
        assert row.actor_user_id == SUPERADMIN_ID
        assert row.actor_role == "superadmin"
        assert row.table_name == str(Category.__tablename__)
        assert row.target_owner_id == str(OWNER_ID)
        # The audit row names the row that was actually persisted.
        created = db_session.exec(select(Category)).one()
        assert row.row_pk == str(created.id)
        assert as_owner_id(created.owner_id) == OWNER_ID

    def test_self_owned_create_writes_no_audit_row(self, app_client, db_session):
        client, app = app_client
        _as(app, WRITER)

        assert client.post("/category/add/", json={"name": "News"}).status_code == 200
        assert _audit_rows(db_session) == []

    def test_refused_cross_owner_create_writes_nothing_at_all(
        self, app_client, db_session
    ):
        """A writer cannot create on another's behalf — neither the category nor
        an audit row may survive the refusal."""
        client, app = app_client
        _as(app, WRITER)

        response = client.post(
            "/category/add/",
            json={"name": "News", "target_owner_id": str(SUPERADMIN_ID)},
        )

        assert response.status_code == 403
        assert _audit_rows(db_session) == []
        assert db_session.exec(select(Category)).all() == []


class TestUpdateIsAudited:
    def test_cross_owner_edit_writes_one_edit_row(self, app_client, db_session):
        client, app = app_client
        item = _category(db_session, owner_id=OWNER_ID)
        _as(app, SUPERADMIN)

        response = client.put(f"/category/edit/{item.id}/", json={"name": "Sports"})

        assert response.status_code == 200
        rows = _audit_rows(db_session)
        assert len(rows) == 1
        assert rows[0].action == AuditAction.EDIT
        assert rows[0].row_pk == str(item.id)
        # The recorded owner is the persisted one, never the acting superadmin.
        assert rows[0].target_owner_id == str(OWNER_ID)
        db_session.refresh(item)
        assert as_owner_id(item.owner_id) == OWNER_ID
        assert item.name == "Sports"

    def test_editing_own_category_writes_no_audit_row(self, app_client, db_session):
        client, app = app_client
        item = _category(db_session, owner_id=OWNER_ID)
        _as(app, WRITER)

        response = client.put(f"/category/edit/{item.id}/", json={"name": "Sports"})

        assert response.status_code == 200
        assert _audit_rows(db_session) == []

    def test_denied_edit_writes_no_audit_row(self, app_client, db_session):
        client, app = app_client
        item = _category(db_session, owner_id=SUPERADMIN_ID)
        _as(app, WRITER)

        response = client.put(f"/category/edit/{item.id}/", json={"name": "Sports"})

        assert response.status_code == 403
        assert _audit_rows(db_session) == []


class TestDeleteIsAudited:
    def test_cross_owner_delete_writes_one_delete_row(self, app_client, db_session):
        client, app = app_client
        item = _category(db_session, owner_id=OWNER_ID)
        item_id = item.id
        _as(app, SUPERADMIN)

        response = client.delete(f"/category/delete/{item_id}/")

        assert response.status_code == 200
        assert db_session.exec(select(Category)).all() == []
        rows = _audit_rows(db_session)
        assert len(rows) == 1
        # Captured before the row was removed, so the record outlives it.
        assert rows[0].action == AuditAction.DELETE
        assert rows[0].row_pk == str(item_id)
        assert rows[0].target_owner_id == str(OWNER_ID)

    def test_deleting_own_category_writes_no_audit_row(self, app_client, db_session):
        client, app = app_client
        item = _category(db_session, owner_id=OWNER_ID)
        _as(app, WRITER)

        assert client.delete(f"/category/delete/{item.id}/").status_code == 200
        assert _audit_rows(db_session) == []

    def test_denied_delete_leaves_the_row_and_writes_no_audit_row(
        self, app_client, db_session
    ):
        client, app = app_client
        item = _category(db_session, owner_id=SUPERADMIN_ID)
        _as(app, WRITER)

        response = client.delete(f"/category/delete/{item.id}/")

        assert response.status_code == 403
        assert _audit_rows(db_session) == []
        assert len(db_session.exec(select(Category)).all()) == 1
