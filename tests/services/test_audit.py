"""Tests for the transaction-bound privileged-action recorder (Phase 7)."""

import uuid

from sqlmodel import select

from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)
from auth_user_service.services.audit import record_privileged_action


def _rows_for_actor(session, actor) -> list[PrivilegedActionAudit]:
    # The in-memory test engine is session-scoped and sibling tests commit audit
    # rows, so scope every assertion to this test's unique actor id.
    return list(
        session.exec(
            select(PrivilegedActionAudit).where(
                PrivilegedActionAudit.actor_user_id == actor
            )
        ).all()
    )


class TestRecordPrivilegedAction:
    def test_writes_exactly_one_row_with_the_recorded_fields(self, db_session) -> None:
        actor = uuid.uuid4()
        owner = uuid.uuid4()
        row_pk = uuid.uuid4()

        returned = record_privileged_action(
            db_session,
            actor_user_id=actor,
            actor_role=RoleType.SUPERADMIN,
            action=AuditAction.EDIT,
            table_name="auth_user",
            row_pk=row_pk,
            target_owner_id=owner,
        )

        rows = _rows_for_actor(db_session, actor)
        assert len(rows) == 1
        row = rows[0]
        assert row.id == returned.id
        assert row.actor_user_id == actor
        assert row.actor_role == RoleType.SUPERADMIN
        assert row.action == AuditAction.EDIT
        assert row.table_name == "auth_user"
        # int and UUID PKs alike are stored as their text form.
        assert row.row_pk == str(row_pk)
        assert row.target_owner_id == str(owner)
        assert row.created_at is not None

    def test_coerces_string_actor_sub_to_uuid(self, db_session) -> None:
        # The authenticated principal carries its id as a JWT ``sub`` string.
        actor = uuid.uuid4()
        record_privileged_action(
            db_session,
            actor_user_id=str(actor),
            actor_role=RoleType.ADMIN,
            action=AuditAction.ADD,
            table_name="auth_user",
            row_pk=str(actor),
        )
        rows = _rows_for_actor(db_session, actor)
        assert len(rows) == 1
        assert rows[0].actor_user_id == actor

    def test_int_row_pk_and_absent_owner_are_stored(self, db_session) -> None:
        actor = uuid.uuid4()
        record_privileged_action(
            db_session,
            actor_user_id=actor,
            actor_role=RoleType.SUPERADMIN,
            action=AuditAction.DELETE,
            table_name="example_category",
            row_pk=42,
        )
        row = _rows_for_actor(db_session, actor)[0]
        assert row.row_pk == "42"
        assert row.target_owner_id is None

    def test_flushes_without_committing_so_it_shares_the_txn(self, db_session) -> None:
        # Recorded but not committed: a rollback discards it exactly as it would
        # discard the mutation it accompanies (atomic unit of work).
        actor = uuid.uuid4()
        record_privileged_action(
            db_session,
            actor_user_id=actor,
            actor_role=RoleType.SUPERADMIN,
            action=AuditAction.ADD,
            table_name="auth_user",
            row_pk=uuid.uuid4(),
        )
        assert len(_rows_for_actor(db_session, actor)) == 1
        db_session.rollback()
        assert _rows_for_actor(db_session, actor) == []
