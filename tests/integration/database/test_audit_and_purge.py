"""Layer B: the audit table's schema-level write-once contract (``TEST-DB-01``).

The privileged-action audit trail's guarantee is *schema-level*: a ``BEFORE
UPDATE`` guard rejects every update, and a ``BEFORE DELETE`` guard rejects every
delete that is not the horizon-bounded retention purge. Triggers do not exist on
the SQLite surrogate, so until this suite ran, the entire enforcement mechanism
was unverified by anything continuous.

That gap was not theoretical: the PostgreSQL guard function returned ``NULL``,
which in a ``BEFORE ... FOR EACH ROW`` trigger *silently suppresses* the row
operation — so the authorized purge deleted nothing and
:func:`purge_expired_audit_rows` looped forever on PostgreSQL. The pre-existing
live test asserted only that the authorized delete raised no exception, which it
did not. Hence the assertions here are stated as *"the rows are gone"*, never as
*"no error was raised"*.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError
from sqlmodel import Session, col, select

from auth_sdk_m8.schemas.base import RoleType

from auth_user_service.db_models.api_keys import ApiKey
from auth_user_service.db_models.privileged_action_audit import (
    AuditAction,
    PrivilegedActionAudit,
)
from auth_user_service.db_models.users import User
from auth_user_service.services.api_keys import (
    ApiKeyPurgeRetentionFloorError,
    purge_dead_api_keys,
)
from auth_user_service.services.audit import (
    AuditRetentionFloorError,
    RetentionWindow,
    purge_expired_audit_rows,
    record_privileged_action,
)
from tests.integration.database._factories import (
    make_api_key,
    make_user,
    uuid_literal,
)

pytestmark = pytest.mark.database_integration

GUARD_VIOLATION = DBAPIError

#: ``THREE_MONTHS`` (90 days) sits exactly on the default retention floor, so it
#: is the shortest window the purge accepts without a config change.
FLOOR_WINDOW = RetentionWindow.THREE_MONTHS
FLOOR_DAYS = 90


def _audit_row(actor_id: uuid.UUID, *, age_days: float) -> PrivilegedActionAudit:
    return PrivilegedActionAudit(
        id=uuid.uuid4(),
        created_at=datetime.now(timezone.utc) - timedelta(days=age_days),
        actor_user_id=actor_id,
        actor_role=RoleType.SUPERADMIN,
        action=AuditAction.EDIT,
        table_name="auth_user",
        row_pk=str(uuid.uuid4()),
        target_owner_id=None,
    )


def _audit_count(session: Session) -> int:
    return len(session.exec(select(PrivilegedActionAudit)).all())


# ── write-once enforcement ────────────────────────────────────────────────────


class TestWriteOnceEnforcement:
    def test_update_is_rejected_by_the_engine(
        self, it_session: Session, clean_database: sa.Engine
    ) -> None:
        """No code path — application or ad hoc — can rewrite a written row."""
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        row = _audit_row(actor.id, age_days=1)
        it_session.add(row)
        it_session.commit()

        with pytest.raises(GUARD_VIOLATION):
            with clean_database.begin() as conn:
                conn.execute(
                    sa.text(
                        "UPDATE auth_privileged_action_audit SET row_pk = 'tampered' "
                        "WHERE id = :id"
                    ),
                    {"id": uuid_literal(clean_database, row.id)},
                )

    def test_targeted_delete_is_rejected_without_purge_authorization(
        self, it_session: Session, clean_database: sa.Engine
    ) -> None:
        """A self-incriminating row cannot be surgically erased."""
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        row = _audit_row(actor.id, age_days=1)
        it_session.add(row)
        it_session.commit()

        with pytest.raises(GUARD_VIOLATION):
            with clean_database.begin() as conn:
                conn.execute(
                    sa.text("DELETE FROM auth_privileged_action_audit WHERE id = :id"),
                    {"id": uuid_literal(clean_database, row.id)},
                )

        with Session(clean_database) as check:
            assert _audit_count(check) == 1

    def test_audit_row_survives_the_deletion_of_its_actor(
        self, it_session: Session
    ) -> None:
        """No FK to the actor — the record outlives the account it names."""
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        actor_id = actor.id
        it_session.add(_audit_row(actor_id, age_days=1))
        it_session.commit()

        it_session.execute(
            sa.text("DELETE FROM auth_user WHERE id = :id"),
            {"id": uuid_literal(it_session.get_bind(), actor_id)},
        )
        it_session.commit()

        surviving = it_session.exec(select(PrivilegedActionAudit)).all()
        assert len(surviving) == 1
        assert surviving[0].actor_user_id == actor_id


# ── the retention purge is the one and only removal path ──────────────────────


class TestRetentionPurge:
    def test_authorized_purge_actually_removes_the_rows(
        self, it_session: Session
    ) -> None:
        """The purge's exemption from the delete guard is real, not nominal.

        Asserting on the surviving row count (rather than on the absence of an
        exception) is what makes this test catch a guard that silently discards
        the delete.
        """
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        for _ in range(3):
            it_session.add(_audit_row(actor.id, age_days=FLOOR_DAYS + 10))
        it_session.commit()

        result = purge_expired_audit_rows(
            it_session,
            window=FLOOR_WINDOW,
            actor_user_id=actor.id,
            actor_role=RoleType.SUPERADMIN,
        )

        assert result.removed == 3
        surviving = it_session.exec(select(PrivilegedActionAudit)).all()
        assert [row.row_pk for row in surviving] == [
            f"retention_purge:window={FLOOR_WINDOW.value}:removed=3"
        ]

    def test_window_below_the_floor_deletes_nothing(self, it_session: Session) -> None:
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        it_session.add(_audit_row(actor.id, age_days=400))
        it_session.commit()

        with pytest.raises(AuditRetentionFloorError):
            purge_expired_audit_rows(
                it_session,
                window=RetentionWindow.ONE_MONTH,
                actor_user_id=actor.id,
                actor_role=RoleType.SUPERADMIN,
            )

        assert _audit_count(it_session) == 1

    def test_rows_inside_the_horizon_are_never_touched(
        self, it_session: Session
    ) -> None:
        """The horizon is exact: one day younger than the window survives."""
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        it_session.add(_audit_row(actor.id, age_days=FLOOR_DAYS - 1))
        it_session.add(_audit_row(actor.id, age_days=FLOOR_DAYS + 1))
        it_session.commit()

        result = purge_expired_audit_rows(
            it_session,
            window=FLOOR_WINDOW,
            actor_user_id=actor.id,
            actor_role=RoleType.SUPERADMIN,
        )

        assert result.removed == 1
        assert _audit_count(it_session) == 2  # the young row + the maintenance row

    def test_multi_batch_purge_removes_every_eligible_row(
        self, it_session: Session
    ) -> None:
        """Batching commits per batch; the sweep still finishes the table."""
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        for _ in range(11):
            it_session.add(_audit_row(actor.id, age_days=FLOOR_DAYS + 5))
        it_session.commit()

        result = purge_expired_audit_rows(
            it_session,
            window=FLOOR_WINDOW,
            actor_user_id=actor.id,
            actor_role=RoleType.SUPERADMIN,
            batch_size=3,
        )

        assert result.removed == 11
        assert _audit_count(it_session) == 1

    def test_the_maintenance_row_survives_its_own_and_later_purges(
        self, it_session: Session
    ) -> None:
        """The purge's own record is newer than the horizon it computed."""
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        it_session.add(_audit_row(actor.id, age_days=FLOOR_DAYS + 5))
        it_session.commit()

        for _ in range(2):
            purge_expired_audit_rows(
                it_session,
                window=FLOOR_WINDOW,
                actor_user_id=actor.id,
                actor_role=RoleType.SUPERADMIN,
            )

        surviving = it_session.exec(select(PrivilegedActionAudit)).all()
        assert len(surviving) == 2
        assert all(row.row_pk.startswith("retention_purge:") for row in surviving)


# ── the recorder writes inside the caller's transaction ───────────────────────


class TestRecorderAtomicity:
    def test_no_audit_row_survives_a_rolled_back_mutation(
        self, it_session: Session, second_engine: sa.Engine
    ) -> None:
        """One unit of work: no audited mutation, no record — and vice versa."""
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        target = make_user(it_session)
        target_id = target.id

        target.full_name = "renamed in a doomed transaction"
        record_privileged_action(
            it_session,
            actor_user_id=actor.id,
            actor_role=RoleType.SUPERADMIN,
            action=AuditAction.EDIT,
            table_name=User.__tablename__,
            row_pk=target_id,
            target_owner_id=target_id,
        )
        it_session.flush()
        it_session.rollback()

        with Session(second_engine) as check:
            assert _audit_count(check) == 0
            reloaded = check.get(User, target_id)
            assert reloaded is not None
            assert reloaded.full_name != "renamed in a doomed transaction"


# ── dead-key retention purge (APIKEY-LIFECYCLE-01) ────────────────────────────


class TestDeadKeyPurge:
    def test_window_below_the_floor_deletes_nothing(self, it_session: Session) -> None:
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        owner = make_user(it_session)
        make_api_key(
            it_session,
            owner,
            revoked=True,
            updated_at=datetime.now(timezone.utc) - timedelta(days=400),
        )

        with pytest.raises(ApiKeyPurgeRetentionFloorError):
            purge_dead_api_keys(
                it_session,
                window=RetentionWindow.ONE_MONTH,
                actor_user_id=actor.id,
                actor_role=RoleType.SUPERADMIN,
            )

        assert len(it_session.exec(select(ApiKey)).all()) == 1

    def test_only_long_dead_keys_are_removed(self, it_session: Session) -> None:
        """Live keys, recently revoked keys, and never-expiring keys all stay."""
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        owner = make_user(it_session)
        long_dead = make_api_key(
            it_session,
            owner,
            revoked=True,
            updated_at=datetime.now(timezone.utc) - timedelta(days=FLOOR_DAYS + 10),
        )
        recently_revoked = make_api_key(it_session, owner, revoked=True)
        live = make_api_key(it_session, owner)
        long_expired = make_api_key(
            it_session,
            owner,
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None)
            - timedelta(days=FLOOR_DAYS + 10),
        )
        dead_ids = {long_dead.id, long_expired.id}
        survivor_ids = {recently_revoked.id, live.id}

        result = purge_dead_api_keys(
            it_session,
            window=FLOOR_WINDOW,
            actor_user_id=actor.id,
            actor_role=RoleType.SUPERADMIN,
        )

        assert result.removed == 2
        remaining = {key.id for key in it_session.exec(select(ApiKey)).all()}
        assert remaining == survivor_ids
        assert not (remaining & dead_ids)

    def test_purge_writes_a_surviving_maintenance_record(
        self, it_session: Session
    ) -> None:
        actor = make_user(it_session, role=RoleType.SUPERADMIN, is_superuser=True)
        owner = make_user(it_session)
        make_api_key(
            it_session,
            owner,
            revoked=True,
            updated_at=datetime.now(timezone.utc) - timedelta(days=FLOOR_DAYS + 10),
        )

        purge_dead_api_keys(
            it_session,
            window=FLOOR_WINDOW,
            actor_user_id=actor.id,
            actor_role=RoleType.SUPERADMIN,
        )

        records = it_session.exec(
            select(PrivilegedActionAudit).where(
                col(PrivilegedActionAudit.action) == AuditAction.DELETE
            )
        ).all()
        assert len(records) == 1
        assert "removed=1" in records[0].row_pk
