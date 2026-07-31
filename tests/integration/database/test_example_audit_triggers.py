"""Layer B: the bundled example's audit guards, on a real engine (``TEST-DB-01``).

The consumer example in ``examples/fastapi_full`` mirrors the issuer's audit
contract: ``app_privileged_action_audit`` rows are write-once, no targeted
delete exists, and the horizon-bounded retention purge is the sole removal path
— enforced by a ``BEFORE UPDATE OR DELETE`` trigger its Expand migration
installs, exactly as the issuer's ``auth_privileged_action_audit`` is.

Until this module existed the example's half of that mirror was **unproven**.
Its unit suite runs on SQLite, which never applies the migration and therefore
carries no trigger at all — the example's own ``_PURGE_GUARDED_DIALECTS`` set
says so — and ``example-smoke.yaml`` proves the migration *applies*, not that an
``UPDATE`` or a targeted ``DELETE`` is *rejected*. So the guarantee was attested
rather than gated, which is the distinction Layer B exists to remove.

This module asserts against the real engine exactly what
``test_audit_and_purge.py`` asserts for the issuer's table, and it asserts them
through the example's shipped code — the purge exercised here is
``fastapi_full.app.audit.purge_expired_audit_rows``, not a re-implementation, so
the ``_PURGE_GUARDED_DIALECTS`` toggle is what performs the authorization dance.

As there, every assertion is stated as *"the rows are gone"* rather than *"no
error was raised"*: the PostgreSQL guard function that returned ``NULL``
silently suppressed the row operation instead of failing, and only a surviving-
row count catches that.

**One deliberate divergence, recorded rather than glossed.** The issuer's suite
proves an audit row survives *its actor's* deletion. The example has no actor
table to delete from: the actor is a user of the auth service, which this
consumer never joins against (``ARCH-NO-CROSS-SERVICE-DATA``). The faithful
analogue — same guarantee, same failure mode — is that the row survives the
deletion of the **target** it describes, proven here alongside the structural
fact that the table declares no foreign key at all, which is what makes it
immune to any cascade from either side.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterator

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError
from sqlmodel import Session, select

from tests.integration.database._engines import Endpoint, EngineSpec
from tests.integration.database._example_chain import (
    AUDIT_TABLE,
    CATEGORY_TABLE,
    ExampleAudit,
    apply_example_chain,
    clear_example_audit_rows,
    loaded_example,
)
from tests.integration.database._factories import naive_utc, uuid_literal

pytestmark = pytest.mark.database_integration

GUARD_VIOLATION = DBAPIError

#: The guard's own messages, identical in the PostgreSQL (``RAISE EXCEPTION``)
#: and MySQL/MariaDB (``SIGNAL SQLSTATE '45000'``) revisions. Matching on them
#: is what distinguishes "the trigger rejected this" from "something else went
#: wrong" — a raw statement can fail for plenty of reasons that prove nothing.
UPDATE_REJECTED = "write-once and cannot be updated"
DELETE_REJECTED = "horizon-bounded retention purge"

#: ``THREE_MONTHS`` sits exactly on the example's default retention floor
#: (``AUDIT_PURGE_MIN_RETENTION_SECONDS``), so it is the shortest window the
#: purge accepts without a config change — the same choice the issuer suite makes.
FLOOR_DAYS = 90


@pytest.fixture(scope="module")
def example_audit(
    engine_spec: EngineSpec, db_endpoint: Endpoint, migrated_database: sa.Engine
) -> Iterator[ExampleAudit]:
    """The example's audit surface, with its ``m8_app`` chain applied.

    Depends on ``migrated_database`` rather than on the raw engine so the
    example chain is applied *after* the session's one schema reset, never
    before it.
    """
    with loaded_example(engine_spec, db_endpoint) as surface:
        apply_example_chain(migrated_database, engine_spec)
        yield surface


@pytest.fixture
def example_database(
    example_audit: ExampleAudit, migrated_database: sa.Engine
) -> Iterator[sa.Engine]:
    """The Layer B target with the example's tables empty before each test."""
    clear_example_audit_rows(migrated_database)
    yield migrated_database


@pytest.fixture
def example_session(example_database: sa.Engine) -> Iterator[Session]:
    """A session on the ephemeral target, on an empty example schema."""
    with Session(example_database) as session:
        yield session
        session.rollback()


def _audit_row(
    surface: ExampleAudit, actor_id: uuid.UUID, *, age_days: float
) -> object:
    """One example audit row, aged *age_days* relative to now."""
    return surface.model(
        id=uuid.uuid4(),
        created_at=datetime.now(timezone.utc) - timedelta(days=age_days),
        actor_user_id=actor_id,
        actor_role="superadmin",
        action=surface.action.EDIT,
        table_name=CATEGORY_TABLE,
        row_pk=str(uuid.uuid4()),
        target_owner_id=None,
    )


def _audit_count(surface: ExampleAudit, session: Session) -> int:
    return len(session.exec(select(surface.model)).all())


def _insert_category(engine: sa.Engine, owner_id: uuid.UUID) -> int:
    """Insert one owned category with raw SQL and return its primary key.

    Raw SQL rather than the ORM so the target row this test deletes is built
    with no dependency on how the example adapts a ``uuid.UUID`` to its
    ``CHAR(36)`` ownership column — that is the category routes' concern, not
    this module's.
    """
    suffix = uuid.uuid4().hex[:8]
    with engine.begin() as connection:
        connection.execute(
            sa.text(
                f"INSERT INTO {CATEGORY_TABLE} "  # nosec B608 — fixed table name
                "(name, slug, created_at, updated_at, owner_id) "
                "VALUES (:name, :slug, :now, :now, :owner_id)"
            ),
            {
                "name": f"layer-b {suffix}",
                "slug": f"layer-b-{suffix}",
                "now": naive_utc(),
                "owner_id": str(owner_id),
            },
        )
        return int(
            connection.execute(
                sa.text(
                    f"SELECT id FROM {CATEGORY_TABLE} "  # nosec B608
                    "WHERE slug = :slug"
                ),
                {"slug": f"layer-b-{suffix}"},
            ).scalar_one()
        )


# ── write-once enforcement ────────────────────────────────────────────────────


class TestExampleWriteOnceEnforcement:
    def test_update_is_rejected_by_the_engine(
        self,
        example_audit: ExampleAudit,
        example_session: Session,
        example_database: sa.Engine,
    ) -> None:
        """No code path — application or ad hoc — can rewrite a written row."""
        row = _audit_row(example_audit, uuid.uuid4(), age_days=1)
        example_session.add(row)
        example_session.commit()

        with pytest.raises(GUARD_VIOLATION, match=UPDATE_REJECTED):
            with example_database.begin() as connection:
                connection.execute(
                    sa.text(
                        f"UPDATE {AUDIT_TABLE} "  # nosec B608 — fixed table name
                        "SET row_pk = 'tampered' WHERE id = :id"
                    ),
                    {"id": uuid_literal(example_database, row.id)},
                )

    def test_targeted_delete_is_rejected_without_purge_authorization(
        self,
        example_audit: ExampleAudit,
        example_session: Session,
        example_database: sa.Engine,
    ) -> None:
        """A self-incriminating row cannot be surgically erased."""
        row = _audit_row(example_audit, uuid.uuid4(), age_days=1)
        example_session.add(row)
        example_session.commit()

        with pytest.raises(GUARD_VIOLATION, match=DELETE_REJECTED):
            with example_database.begin() as connection:
                connection.execute(
                    sa.text(
                        f"DELETE FROM {AUDIT_TABLE} "  # nosec B608
                        "WHERE id = :id"
                    ),
                    {"id": uuid_literal(example_database, row.id)},
                )

        with Session(example_database) as check:
            assert _audit_count(example_audit, check) == 1

    def test_audit_row_survives_the_deletion_of_its_target(
        self,
        example_audit: ExampleAudit,
        example_session: Session,
        example_database: sa.Engine,
    ) -> None:
        """The record outlives the row it describes — and carries no cascade.

        The issuer proves this by deleting the *actor*; the example's actor
        lives in the auth service, so the deletable counterpart here is the
        audited category. The no-foreign-key assertion is what generalises it:
        with none declared on a real engine, no cascade from any direction can
        reach the audit trail.
        """
        owner_id = uuid.uuid4()
        category_id = _insert_category(example_database, owner_id)

        example_audit.module.record_privileged_action(
            example_session,
            actor_user_id=uuid.uuid4(),
            actor_role="superadmin",
            action=example_audit.action.DELETE,
            table_name=CATEGORY_TABLE,
            row_pk=category_id,
            target_owner_id=owner_id,
        )
        example_session.commit()

        with example_database.begin() as connection:
            connection.execute(
                sa.text(
                    f"DELETE FROM {CATEGORY_TABLE} "  # nosec B608
                    "WHERE id = :id"
                ),
                {"id": category_id},
            )

        assert sa.inspect(example_database).get_foreign_keys(AUDIT_TABLE) == []
        with Session(example_database) as check:
            surviving = check.exec(select(example_audit.model)).all()
            assert len(surviving) == 1
            assert surviving[0].row_pk == str(category_id)
            assert surviving[0].target_owner_id == str(owner_id)


# ── the retention purge is the one and only removal path ──────────────────────


class TestExampleRetentionPurge:
    def test_authorized_purge_actually_removes_the_rows(
        self, example_audit: ExampleAudit, example_session: Session
    ) -> None:
        """The example's own purge clears the guard, and the rows are gone.

        This is the assertion the SQLite unit layer structurally cannot make:
        there the guard does not exist, so the authorization dance is a no-op
        and a suppressed delete is indistinguishable from a successful one.
        Counting survivors — rather than checking that nothing raised — is what
        catches a guard that discards the delete instead of performing it.
        """
        actor_id = uuid.uuid4()
        for _ in range(3):
            example_session.add(
                _audit_row(example_audit, actor_id, age_days=FLOOR_DAYS + 10)
            )
        example_session.commit()

        window = example_audit.window.THREE_MONTHS
        result = example_audit.module.purge_expired_audit_rows(
            example_session,
            window=window,
            actor_user_id=actor_id,
            actor_role="superadmin",
        )

        assert result.removed == 3
        surviving = example_session.exec(select(example_audit.model)).all()
        assert [row.row_pk for row in surviving] == [
            f"retention_purge:window={window.value}:removed=3"
        ]
