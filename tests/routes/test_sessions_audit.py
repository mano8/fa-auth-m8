"""Phase 7 audit-trail integration for the administrative session routes.

``routes/sessions.py`` is a pre-existing live-tested surface (coverage-omitted),
so these unit tests focus on the new recorder integration: a superadmin revoking
another user's session(s) writes exactly one durable ``delete`` audit row,
atomically with the authoritative revocation.
"""

import uuid
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from sqlmodel import select

from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)
from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.routes.sessions import (
    delete_session,
    delete_sessions_by_user,
)


def _audit_for_pk(db_session, row_pk) -> list[PrivilegedActionAudit]:
    # Session-scoped in-memory engine + committing siblings → scope by row_pk.
    return list(
        db_session.exec(
            select(PrivilegedActionAudit).where(
                PrivilegedActionAudit.row_pk == str(row_pk)
            )
        ).all()
    )


def _audit_count(db_session) -> int:
    return len(db_session.exec(select(PrivilegedActionAudit)).all())


class TestSessionRevocationAudit:
    def test_delete_session_writes_delete_audit_row(
        self, db_session, sample_client_session, sample_user, superuser
    ) -> None:
        session_id = sample_client_session.id
        with patch("auth_user_service.services.client_sessions.emit"):
            delete_session(
                session=db_session,
                redis=None,
                current_user=superuser,
                session_id=session_id,
            )
        # The authoritative row is revoked and the audit row committed with it.
        assert db_session.get(ClientSession, session_id) is None
        rows = _audit_for_pk(db_session, session_id)
        assert len(rows) == 1
        row = rows[0]
        assert row.action == AuditAction.DELETE
        assert row.actor_user_id == superuser.id
        assert row.actor_role == RoleType.SUPERADMIN
        assert row.table_name == ClientSession.__tablename__
        assert row.row_pk == str(session_id)
        assert row.target_owner_id == str(sample_user.id)

    def test_delete_by_user_writes_one_user_keyed_audit_row(
        self, db_session, sample_client_session, sample_user, superuser
    ) -> None:
        user_id = sample_user.id
        with patch("auth_user_service.services.client_sessions.emit"):
            delete_sessions_by_user(
                session=db_session,
                redis=None,
                current_user=superuser,
                user_id=user_id,
            )
        remaining = db_session.exec(
            select(ClientSession).where(ClientSession.user_id == user_id)
        ).all()
        assert remaining == []
        rows = _audit_for_pk(db_session, user_id)
        assert len(rows) == 1
        row = rows[0]
        assert row.action == AuditAction.DELETE
        # A user-wide bulk revocation is keyed by the owning user id.
        assert row.row_pk == str(user_id)
        assert row.target_owner_id == str(user_id)

    def test_missing_session_writes_no_audit_row(self, db_session, superuser) -> None:
        before = _audit_count(db_session)
        with pytest.raises(HTTPException) as exc:
            delete_session(
                session=db_session,
                redis=None,
                current_user=superuser,
                session_id=uuid.uuid4(),
            )
        assert exc.value.status_code == 404
        assert _audit_count(db_session) == before
