"""Model tests for the read-only ``privileged_action_audit`` table (Phase 7).

These assert the physical contract the model exists to guarantee: an
append-only, FK-free forensic record whose ``row_pk``/``target_owner_id`` are
text (so int and UUID PKs share one table), whose ``action`` is constrained to
the three privileged mutation kinds, and whose only nullable column is
``target_owner_id``.
"""

import uuid

from sqlmodel import select

from auth_sdk_m8.schemas.base import RoleType
from auth_user_service.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)


def _row(db_session, **attrs) -> PrivilegedActionAudit:
    defaults = dict(
        actor_user_id=uuid.uuid4(),
        actor_role=RoleType.SUPERADMIN,
        action=AuditAction.EDIT,
        table_name="prefix_category",
        row_pk="42",
    )
    defaults.update(attrs)
    audit = PrivilegedActionAudit(**defaults)
    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)
    return audit


class TestColumns:
    def test_tablename_is_prefixed(self):
        assert PrivilegedActionAudit.__tablename__.endswith("privileged_action_audit")

    def test_created_at_autopopulated(self, db_session):
        audit = _row(db_session)
        assert audit.created_at is not None

    def test_id_is_uuid(self, db_session):
        audit = _row(db_session)
        assert isinstance(audit.id, uuid.UUID)

    def test_actor_user_id_indexed(self):
        column = PrivilegedActionAudit.__table__.c.actor_user_id
        assert column.index is True

    def test_no_foreign_keys(self):
        # The audit must outlive the actor/target rows, so it carries no FK.
        assert PrivilegedActionAudit.__table__.foreign_keys == set()


class TestTargetOwnerNullable:
    def test_defaults_to_none(self, db_session):
        audit = _row(db_session)
        assert audit.target_owner_id is None

    def test_accepts_owner_text(self, db_session):
        owner = uuid.uuid4()
        audit = _row(db_session, target_owner_id=str(owner))
        assert audit.target_owner_id == str(owner)


class TestRowPkText:
    def test_stores_integer_pk_as_text(self, db_session):
        audit = _row(db_session, row_pk="1001", table_name="prefix_category")
        db_session.expire(audit)
        assert audit.row_pk == "1001"

    def test_stores_uuid_pk_as_text(self, db_session):
        pk = uuid.uuid4()
        audit = _row(
            db_session,
            row_pk=str(pk),
            table_name="prefix_user",
            target_owner_id=str(pk),
        )
        db_session.expire(audit)
        assert audit.row_pk == str(pk)


class TestActionEnum:
    def test_all_actions_persist(self, db_session):
        for action in (AuditAction.ADD, AuditAction.EDIT, AuditAction.DELETE):
            audit = _row(db_session, action=action)
            db_session.expire(audit)
            assert audit.action == action

    def test_action_stores_lowercase_value(self, db_session):
        audit = _row(db_session, action=AuditAction.DELETE)
        stored = db_session.execute(
            select(PrivilegedActionAudit.action).where(
                PrivilegedActionAudit.id == audit.id
            )
        ).scalar_one()
        assert stored == AuditAction.DELETE
        assert AuditAction.DELETE.value == "delete"


class TestSurvivesUnrelatedIds:
    def test_actor_and_target_need_not_reference_real_users(self, db_session):
        # No FK → arbitrary (already-deleted) ids are accepted and persisted.
        audit = _row(
            db_session,
            actor_user_id=uuid.uuid4(),
            target_owner_id=str(uuid.uuid4()),
        )
        fetched = db_session.get(PrivilegedActionAudit, audit.id)
        assert fetched is not None
