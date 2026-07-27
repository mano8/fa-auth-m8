"""Privileged-action audit tests for the consumer example (Phase 7).

The properties defended here are the issuer's, applied to the data this example
owns: an audited mutation and its record share one transaction, only a mutation
of *non-owned* data is audited, the table is write-once with no targeted delete,
and the read scope is decided from the authenticated principal alone.
"""

from __future__ import annotations

import inspect
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi_m8 import UserModel
from sqlmodel import select

from fastapi_full.app import audit as audit_module
from fastapi_full.app.audit import (
    AuditRetentionFloorError,
    RetentionWindow,
    purge_expired_audit_rows,
    read_audit_page,
    record_cross_owner_category_action,
    record_privileged_action,
    role_text,
)
from fastapi_full.db_models.categories import Category
from fastapi_full.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)

ACTOR_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")


def _user(
    role: str = "superadmin",
    is_superuser: bool = True,
    user_id: uuid.UUID = ACTOR_ID,
) -> UserModel:
    """Build an authenticated principal with a canonical claim pair."""
    return UserModel(
        id=user_id,
        email="actor@example.com",
        role=role,  # type: ignore[arg-type]
        is_superuser=is_superuser,
    )


def _all_rows(session) -> list[PrivilegedActionAudit]:
    return list(session.exec(select(PrivilegedActionAudit)).all())


def _audit_row(
    actor: uuid.UUID = ACTOR_ID, *, created_at: datetime
) -> PrivilegedActionAudit:
    return PrivilegedActionAudit(
        actor_user_id=actor,
        actor_role="superadmin",
        action=AuditAction.EDIT,
        table_name=str(Category.__tablename__),
        row_pk=str(uuid.uuid4()),
        created_at=created_at,
    )


class TestRoleText:
    """The stored role is the enum's value, never its member repr."""

    def test_enum_member_stores_its_value(self) -> None:
        assert role_text(_user("admin", False).role) == "admin"

    def test_plain_string_passes_through(self) -> None:
        assert role_text("superadmin") == "superadmin"


class TestRecordPrivilegedAction:
    """Exactly one row, with the fields the caller supplied, in its transaction."""

    def test_writes_exactly_one_row_with_the_recorded_fields(self, db_session) -> None:
        returned = record_privileged_action(
            db_session,
            actor_user_id=ACTOR_ID,
            actor_role="superadmin",
            action=AuditAction.EDIT,
            table_name="app_category",
            row_pk=42,
            target_owner_id=OTHER_ID,
        )

        rows = _all_rows(db_session)
        assert len(rows) == 1
        row = rows[0]
        assert row.id == returned.id
        assert row.actor_user_id == ACTOR_ID
        assert row.actor_role == "superadmin"
        assert row.action == AuditAction.EDIT
        assert row.table_name == "app_category"
        # int and UUID PKs alike are stored as their text form.
        assert row.row_pk == "42"
        assert row.target_owner_id == str(OTHER_ID)
        assert row.created_at is not None

    def test_coerces_string_actor_sub_to_uuid(self, db_session) -> None:
        # The authenticated principal carries its id as a JWT ``sub`` string.
        record_privileged_action(
            db_session,
            actor_user_id=str(ACTOR_ID),
            actor_role="admin",
            action=AuditAction.ADD,
            table_name="app_category",
            row_pk=1,
        )
        assert _all_rows(db_session)[0].actor_user_id == ACTOR_ID

    def test_absent_owner_is_stored_as_null(self, db_session) -> None:
        record_privileged_action(
            db_session,
            actor_user_id=ACTOR_ID,
            actor_role="superadmin",
            action=AuditAction.DELETE,
            table_name="app_category",
            row_pk=7,
        )
        assert _all_rows(db_session)[0].target_owner_id is None

    def test_flushes_without_committing_so_it_shares_the_txn(self, db_session) -> None:
        # Recorded but not committed: a rollback discards it exactly as it would
        # discard the mutation it accompanies (atomic unit of work).
        record_privileged_action(
            db_session,
            actor_user_id=ACTOR_ID,
            actor_role="superadmin",
            action=AuditAction.ADD,
            table_name="app_category",
            row_pk=1,
        )
        assert len(_all_rows(db_session)) == 1
        db_session.rollback()
        assert _all_rows(db_session) == []


class TestRecordCrossOwnerCategoryAction:
    """Only a mutation of *non-owned* data is a privileged action."""

    def test_own_data_writes_no_row(self, db_session) -> None:
        written = record_cross_owner_category_action(
            db_session,
            actor=_user(),
            action=AuditAction.EDIT,
            row_pk=5,
            target_owner_id=ACTOR_ID,
        )
        assert written is None
        assert _all_rows(db_session) == []

    @pytest.mark.parametrize(
        "action", [AuditAction.ADD, AuditAction.EDIT, AuditAction.DELETE]
    )
    def test_cross_owner_mutation_is_recorded(self, db_session, action) -> None:
        written = record_cross_owner_category_action(
            db_session,
            actor=_user(),
            action=action,
            row_pk=5,
            target_owner_id=OTHER_ID,
        )
        assert written is not None
        row = _all_rows(db_session)[0]
        assert row.action == action
        assert row.table_name == str(Category.__tablename__)
        assert row.row_pk == "5"

    def test_records_the_target_owner_not_the_actor(self, db_session) -> None:
        """The audit answers "whose data was touched", not "who touched it"."""
        record_cross_owner_category_action(
            db_session,
            actor=_user(),
            action=AuditAction.DELETE,
            row_pk=5,
            target_owner_id=OTHER_ID,
        )
        row = _all_rows(db_session)[0]
        assert row.target_owner_id == str(OTHER_ID)
        assert row.target_owner_id != str(ACTOR_ID)
        assert row.actor_user_id == ACTOR_ID

    def test_actor_role_comes_from_the_principal(self, db_session) -> None:
        record_cross_owner_category_action(
            db_session,
            actor=_user("superadmin", True),
            action=AuditAction.ADD,
            row_pk=5,
            target_owner_id=OTHER_ID,
        )
        assert _all_rows(db_session)[0].actor_role == "superadmin"


class TestAuditRowsAreWriteOnce:
    """No update path and no targeted single-row delete exists in the module."""

    def test_module_exposes_no_update_or_targeted_delete_helper(self) -> None:
        public = {
            name
            for name in vars(audit_module)
            if not name.startswith("_") and callable(getattr(audit_module, name))
        }
        assert not {
            name
            for name in public
            if "update" in name.lower()
            or ("delete" in name.lower() and "purge" not in name.lower())
        }

    def test_the_only_write_helpers_are_the_two_recorders(self) -> None:
        assert {name for name in vars(audit_module) if name.startswith("record_")} == {
            "record_privileged_action",
            "record_cross_owner_category_action",
        }


class TestReadAuditPage:
    """Superadmin sees everything; anyone else sees only rows it authored."""

    @pytest.fixture
    def populated(self, db_session):
        now = datetime.now(timezone.utc)
        mine = _audit_row(ACTOR_ID, created_at=now - timedelta(minutes=1))
        theirs = _audit_row(OTHER_ID, created_at=now - timedelta(minutes=2))
        db_session.add(mine)
        db_session.add(theirs)
        db_session.commit()
        return mine, theirs

    def test_superuser_sees_every_row(self, db_session, populated) -> None:
        rows, count = read_audit_page(
            db_session, actor_id=ACTOR_ID, actor_is_canonical_superuser=True
        )
        assert count == 2
        assert {row.id for row in rows} == {populated[0].id, populated[1].id}

    def test_non_superuser_sees_only_its_own_rows(self, db_session, populated) -> None:
        rows, count = read_audit_page(
            db_session, actor_id=ACTOR_ID, actor_is_canonical_superuser=False
        )
        assert count == 1
        assert [row.id for row in rows] == [populated[0].id]

    def test_an_admin_with_no_rows_sees_an_empty_page(
        self, db_session, populated
    ) -> None:
        """In this example only a superadmin mutates non-owned data, so an
        admin's own view is legitimately empty rather than merely unfiltered."""
        stranger = uuid.uuid4()
        rows, count = read_audit_page(
            db_session, actor_id=stranger, actor_is_canonical_superuser=False
        )
        assert (rows, count) == ([], 0)

    def test_newest_first(self, db_session, populated) -> None:
        rows, _ = read_audit_page(
            db_session, actor_id=ACTOR_ID, actor_is_canonical_superuser=True
        )
        assert [row.id for row in rows] == [populated[0].id, populated[1].id]

    def test_pagination_bounds_the_page(self, db_session, populated) -> None:
        rows, count = read_audit_page(
            db_session,
            actor_id=ACTOR_ID,
            actor_is_canonical_superuser=True,
            skip=1,
            limit=1,
        )
        assert count == 2
        assert [row.id for row in rows] == [populated[1].id]


class TestPurgeExpiredAuditRows:
    """The horizon-bounded bulk purge — the table's only removal path."""

    def test_rejects_window_below_the_default_floor(self, db_session) -> None:
        with pytest.raises(AuditRetentionFloorError):
            purge_expired_audit_rows(
                db_session,
                window=RetentionWindow.ONE_WEEK,
                actor_user_id=ACTOR_ID,
                actor_role="superadmin",
            )
        # Nothing was deleted and no maintenance row was written on rejection.
        assert _all_rows(db_session) == []

    def test_allows_window_at_the_default_floor(self, db_session) -> None:
        result = purge_expired_audit_rows(
            db_session,
            window=RetentionWindow.THREE_MONTHS,
            actor_user_id=ACTOR_ID,
            actor_role="superadmin",
        )
        assert result.window == RetentionWindow.THREE_MONTHS
        assert result.removed == 0

    def test_shorter_window_allowed_under_explicit_config_opt_in(
        self, db_session
    ) -> None:
        with patch.object(
            audit_module.settings, "AUDIT_PURGE_MIN_RETENTION_SECONDS", 0
        ):
            result = purge_expired_audit_rows(
                db_session,
                window=RetentionWindow.ONE_WEEK,
                actor_user_id=ACTOR_ID,
                actor_role="superadmin",
            )
        assert result.window == RetentionWindow.ONE_WEEK

    def test_deletes_only_rows_older_than_the_window_horizon(self, db_session) -> None:
        now = datetime.now(timezone.utc)
        old_row = _audit_row(created_at=now - timedelta(days=400))
        recent_row = _audit_row(created_at=now - timedelta(days=10))
        db_session.add(old_row)
        db_session.add(recent_row)
        db_session.commit()

        result = purge_expired_audit_rows(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=ACTOR_ID,
            actor_role="superadmin",
            now=now,
        )

        assert result.removed == 1
        remaining = {row.id for row in _all_rows(db_session)}
        assert recent_row.id in remaining
        assert old_row.id not in remaining

    def test_never_deletes_a_row_at_the_horizon(self, db_session) -> None:
        now = datetime.now(timezone.utc)
        boundary_row = _audit_row(created_at=now - timedelta(days=365))
        db_session.add(boundary_row)
        db_session.commit()

        purge_expired_audit_rows(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=ACTOR_ID,
            actor_role="superadmin",
            now=now,
        )

        assert boundary_row.id in {row.id for row in _all_rows(db_session)}

    def test_batches_deletes_across_multiple_batch_iterations(self, db_session) -> None:
        now = datetime.now(timezone.utc)
        for _ in range(5):
            db_session.add(_audit_row(created_at=now - timedelta(days=400)))
        db_session.commit()

        result = purge_expired_audit_rows(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=ACTOR_ID,
            actor_role="superadmin",
            batch_size=2,
            now=now,
        )

        assert result.removed == 5

    def test_uses_batch_size_setting_when_not_overridden(self, db_session) -> None:
        now = datetime.now(timezone.utc)
        for _ in range(3):
            db_session.add(_audit_row(created_at=now - timedelta(days=400)))
        db_session.commit()

        with patch.object(audit_module.settings, "AUDIT_PURGE_BATCH_SIZE", 2):
            result = purge_expired_audit_rows(
                db_session,
                window=RetentionWindow.ONE_YEAR,
                actor_user_id=ACTOR_ID,
                actor_role="superadmin",
                now=now,
            )
        assert result.removed == 3

    def test_naive_now_is_normalised_to_aware_utc(self, db_session) -> None:
        naive_now = datetime.now(timezone.utc).replace(tzinfo=None)
        db_session.add(_audit_row(created_at=naive_now - timedelta(days=400)))
        db_session.commit()

        result = purge_expired_audit_rows(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=ACTOR_ID,
            actor_role="superadmin",
            now=naive_now,
        )

        assert result.removed == 1

    def test_writes_its_own_maintenance_row_that_survives_the_purge(
        self, db_session
    ) -> None:
        now = datetime.now(timezone.utc)
        db_session.add(_audit_row(created_at=now - timedelta(days=400)))
        db_session.commit()

        result = purge_expired_audit_rows(
            db_session,
            window=RetentionWindow.ONE_YEAR,
            actor_user_id=ACTOR_ID,
            actor_role="superadmin",
            now=now,
        )

        rows = _all_rows(db_session)
        assert len(rows) == 1
        maintenance_row = rows[0]
        assert maintenance_row.action == AuditAction.DELETE
        assert maintenance_row.table_name == str(PrivilegedActionAudit.__tablename__)
        assert "1y" in maintenance_row.row_pk
        assert f"removed={result.removed}" in maintenance_row.row_pk
        assert maintenance_row.actor_role == "superadmin"


class TestPurgeDeleteAuthorizationDialectHelper:
    """The dialect toggle the Expand migration's ``BEFORE DELETE`` guard checks.

    It is a no-op on any dialect the migration never runs against — in
    particular SQLite, the unit-test surrogate this suite uses, which carries no
    such trigger.
    """

    def test_unguarded_dialect_is_a_no_op(self, db_session) -> None:
        dialect = audit_module._dialect_name(db_session)
        assert dialect not in audit_module._PURGE_GUARDED_DIALECTS
        # No trigger exists on the sqlite unit-test schema, so if this were
        # anything other than a no-op it would raise here.
        audit_module._set_purge_delete_authorized(db_session, dialect, active=True)
        audit_module._set_purge_delete_authorized(db_session, dialect, active=False)

    @pytest.mark.parametrize("dialect", ["postgresql", "mysql"])
    def test_guarded_dialects_emit_the_expected_statement(self, dialect: str) -> None:
        session = MagicMock()
        audit_module._set_purge_delete_authorized(session, dialect, active=True)
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
        # without sending dialect-specific SQL to sqlite: the toggle itself is
        # mocked, isolating this test to the call sequence the purge performs.
        now = datetime.now(timezone.utc)
        db_session.add(_audit_row(created_at=now - timedelta(days=400)))
        db_session.commit()

        with (
            patch.object(audit_module, "_dialect_name", return_value="postgresql"),
            patch.object(audit_module, "_set_purge_delete_authorized") as mock_toggle,
        ):
            result = purge_expired_audit_rows(
                db_session,
                window=RetentionWindow.ONE_YEAR,
                actor_user_id=ACTOR_ID,
                actor_role="superadmin",
                now=now,
            )

        assert result.removed == 1
        mock_toggle.assert_any_call(db_session, "postgresql", active=True)
        mock_toggle.assert_any_call(db_session, "postgresql", active=False)

    def test_purge_guarded_dialects_are_exactly_postgres_and_mysql(self) -> None:
        # Locks the guarded-dialect set: MariaDB shares the "mysql" dialect name
        # via the mysql+pymysql driver family, so no separate "mariadb" entry is
        # expected here.
        assert audit_module._PURGE_GUARDED_DIALECTS == frozenset(
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
