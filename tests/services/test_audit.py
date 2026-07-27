"""Tests for the transaction-bound privileged-action recorder (Phase 7)."""

import inspect
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlmodel import select

from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)
from auth_user_service.services import audit as audit_service
from auth_user_service.services.audit import (
    AuditRetentionFloorError,
    RetentionWindow,
    purge_expired_audit_rows,
    record_privileged_action,
)


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


def _old_row(actor: uuid.UUID, *, created_at: datetime) -> PrivilegedActionAudit:
    return PrivilegedActionAudit(
        actor_user_id=actor,
        actor_role=RoleType.SUPERADMIN,
        action=AuditAction.EDIT,
        table_name="auth_user",
        row_pk=str(uuid.uuid4()),
        created_at=created_at,
    )


class TestPurgeExpiredAuditRows:
    def test_rejects_window_below_the_default_floor(self, db_session) -> None:
        actor = uuid.uuid4()
        with pytest.raises(AuditRetentionFloorError):
            purge_expired_audit_rows(
                db_session,
                window=RetentionWindow.ONE_WEEK,
                actor_user_id=actor,
                actor_role=RoleType.SUPERADMIN,
            )
        # Nothing was deleted and no maintenance row was written on rejection.
        assert _rows_for_actor(db_session, actor) == []

    def test_naive_now_is_normalised_to_aware_utc(self, db_session) -> None:
        actor = uuid.uuid4()
        naive_now = datetime.now(timezone.utc).replace(tzinfo=None)
        old_row = _old_row(actor, created_at=naive_now - timedelta(days=400))
        db_session.add(old_row)
        db_session.commit()

        result = purge_expired_audit_rows(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=actor,
            actor_role=RoleType.SUPERADMIN,
            now=naive_now,
        )

        assert result.removed == 1

    def test_allows_window_at_the_default_floor(self, db_session) -> None:
        actor = uuid.uuid4()
        result = purge_expired_audit_rows(
            db_session,
            window=RetentionWindow.THREE_MONTHS,
            actor_user_id=actor,
            actor_role=RoleType.SUPERADMIN,
        )
        assert result.window == RetentionWindow.THREE_MONTHS
        assert result.removed == 0

    def test_shorter_window_allowed_under_explicit_config_opt_in(
        self, db_session
    ) -> None:
        actor = uuid.uuid4()
        with patch(
            "auth_user_service.services.audit.settings.AUDIT_PURGE_MIN_RETENTION_SECONDS",
            0,
        ):
            result = purge_expired_audit_rows(
                db_session,
                window=RetentionWindow.ONE_WEEK,
                actor_user_id=actor,
                actor_role=RoleType.SUPERADMIN,
            )
        assert result.window == RetentionWindow.ONE_WEEK

    def test_deletes_only_rows_older_than_the_window_horizon(self, db_session) -> None:
        actor = uuid.uuid4()
        now = datetime.now(timezone.utc)
        old_row = _old_row(actor, created_at=now - timedelta(days=400))
        recent_row = _old_row(actor, created_at=now - timedelta(days=10))
        db_session.add(old_row)
        db_session.add(recent_row)
        db_session.commit()

        result = purge_expired_audit_rows(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=actor,
            actor_role=RoleType.SUPERADMIN,
            now=now,
        )

        assert result.removed == 1
        remaining_ids = {r.id for r in _rows_for_actor(db_session, actor)}
        assert recent_row.id in remaining_ids
        assert old_row.id not in remaining_ids

    def test_never_deletes_a_row_at_or_after_the_horizon(self, db_session) -> None:
        actor = uuid.uuid4()
        now = datetime.now(timezone.utc)
        # A comfortable margin (not exactly 365 days) so this row's age can
        # never drift past the horizon relative to a later test's own `now`
        # in this session-scoped engine/table.
        boundary_row = _old_row(
            actor, created_at=now - timedelta(days=365) + timedelta(minutes=5)
        )
        db_session.add(boundary_row)
        db_session.commit()

        purge_expired_audit_rows(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=actor,
            actor_role=RoleType.SUPERADMIN,
            now=now,
        )

        remaining_ids = {r.id for r in _rows_for_actor(db_session, actor)}
        assert boundary_row.id in remaining_ids

        # The db_engine fixture is session-scoped and the purge is table-wide
        # (no actor filter, by design) — clean up this ~1-year-old row so it
        # cannot become collateral damage of a *different* test's purge call
        # using a shorter window later in the same test session.
        db_session.delete(boundary_row)
        db_session.commit()

    def test_batches_deletes_across_multiple_batch_iterations(self, db_session) -> None:
        actor = uuid.uuid4()
        now = datetime.now(timezone.utc)
        old_rows = [
            _old_row(actor, created_at=now - timedelta(days=400)) for _ in range(5)
        ]
        for row in old_rows:
            db_session.add(row)
        db_session.commit()

        result = purge_expired_audit_rows(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=actor,
            actor_role=RoleType.SUPERADMIN,
            batch_size=2,
            now=now,
        )

        assert result.removed == 5

    def test_writes_its_own_maintenance_row_that_survives_the_purge(
        self, db_session
    ) -> None:
        actor = uuid.uuid4()
        result = purge_expired_audit_rows(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=actor,
            actor_role=RoleType.SUPERADMIN,
        )
        rows = _rows_for_actor(db_session, actor)
        assert len(rows) == 1
        maintenance_row = rows[0]
        assert maintenance_row.action == AuditAction.DELETE
        assert maintenance_row.table_name == PrivilegedActionAudit.__tablename__
        assert "1y" in maintenance_row.row_pk
        assert f"removed={result.removed}" in maintenance_row.row_pk
        assert maintenance_row.actor_role == RoleType.SUPERADMIN

    def test_uses_batch_size_setting_when_not_overridden(self, db_session) -> None:
        actor = uuid.uuid4()
        with patch(
            "auth_user_service.services.audit.settings.AUDIT_PURGE_BATCH_SIZE",
            2,
        ):
            now = datetime.now(timezone.utc)
            old_rows = [
                _old_row(actor, created_at=now - timedelta(days=400)) for _ in range(3)
            ]
            for row in old_rows:
                db_session.add(row)
            db_session.commit()

            result = purge_expired_audit_rows(
                db_session,
                window=RetentionWindow.ONE_YEAR,
                actor_user_id=actor,
                actor_role=RoleType.SUPERADMIN,
                now=now,
            )
        assert result.removed == 3


class TestPurgeDeleteAuthorizationDialectHelper:
    """The purge's dialect-specific flag toggle (which the Expand migration's
    ``BEFORE DELETE`` guard trigger checks, 4.6) is a no-op on any dialect the
    migration never runs against — in particular SQLite, the unit-test
    surrogate the ``db_session`` fixture uses, which carries no such trigger.
    """

    def test_unguarded_dialect_is_a_no_op(self, db_session) -> None:
        assert audit_service._dialect_name(db_session) not in (
            audit_service._PURGE_GUARDED_DIALECTS
        )
        # No trigger exists on the sqlite unit-test schema, so if this were
        # anything other than a no-op it would raise here.
        audit_service._set_purge_delete_authorized(
            db_session, audit_service._dialect_name(db_session), active=True
        )
        audit_service._set_purge_delete_authorized(
            db_session, audit_service._dialect_name(db_session), active=False
        )

    def test_purge_still_deletes_on_the_unguarded_unit_test_dialect(
        self, db_session
    ) -> None:
        # End-to-end proof the authorization toggle never blocks the purge's
        # own deletes on the dialect the rest of this module's tests run on.
        actor = uuid.uuid4()
        now = datetime.now(timezone.utc)
        old_row = _old_row(actor, created_at=now - timedelta(days=400))
        db_session.add(old_row)
        db_session.commit()

        result = purge_expired_audit_rows(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=actor,
            actor_role=RoleType.SUPERADMIN,
            now=now,
        )
        assert result.removed == 1

    @pytest.mark.parametrize("dialect", ["postgresql", "mysql"])
    def test_guarded_dialects_emit_the_expected_statement(self, dialect: str) -> None:
        session = MagicMock()
        audit_service._set_purge_delete_authorized(session, dialect, active=True)
        session.execute.assert_called_once()
        statement_text = str(session.execute.call_args[0][0])
        if dialect == "postgresql":
            assert "set_config" in statement_text
        else:
            assert "@audit_purge_active" in statement_text

    def test_purge_toggles_authorization_around_each_batch_on_a_guarded_dialect(
        self, db_session
    ) -> None:
        # Forces the guarded branch the real Postgres/MySQL dialects take
        # (unreachable on the sqlite unit-test engine otherwise) without
        # sending dialect-specific SQL to sqlite: the toggle itself is
        # mocked, isolating this test to the call sequence purge performs.
        actor = uuid.uuid4()
        now = datetime.now(timezone.utc)
        old_row = _old_row(actor, created_at=now - timedelta(days=400))
        db_session.add(old_row)
        db_session.commit()

        with (
            patch.object(audit_service, "_dialect_name", return_value="postgresql"),
            patch.object(audit_service, "_set_purge_delete_authorized") as mock_toggle,
        ):
            result = purge_expired_audit_rows(
                db_session,
                window=RetentionWindow.ONE_YEAR,
                actor_user_id=actor,
                actor_role=RoleType.SUPERADMIN,
                now=now,
            )

        assert result.removed == 1
        mock_toggle.assert_any_call(db_session, "postgresql", active=True)
        mock_toggle.assert_any_call(db_session, "postgresql", active=False)

    def test_purge_guarded_dialects_are_exactly_postgres_and_mysql(self) -> None:
        # Locks the guarded-dialect set: MariaDB shares the "mysql" dialect
        # name via the mysql+pymysql driver family (4.6), so no separate
        # "mariadb" entry is expected here.
        assert audit_service._PURGE_GUARDED_DIALECTS == frozenset(
            {"postgresql", "mysql"}
        )


class TestPurgeHasNoTargetedDeletePath:
    def test_signature_has_no_row_scoping_parameter(self) -> None:
        # The horizon is the only selector — locking the signature shape
        # prevents a future change from adding a row-id/target parameter that
        # would turn this into a targeted single-row delete.
        params = set(inspect.signature(purge_expired_audit_rows).parameters)
        assert params == {
            "session",
            "window",
            "actor_user_id",
            "actor_role",
            "batch_size",
            "now",
        }
