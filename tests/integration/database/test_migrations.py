"""Layer B: real Alembic execution on the certified dialects (``TEST-DB-01``, 4.6).

Alembic correctness is established by *executing* migrations on a real engine,
never by reaching migration source lines and never on the SQLite surrogate
(``TEST-LAYER-01``). Covered here:

* ``alembic upgrade head`` from an empty database;
* upgrade from **every** explicitly supported previous schema revision;
* ORM-metadata versus migrated-schema consistency;
* failure and rollback of an invalid migration state (Enforce over
  inconsistent rows must fail and leave the schema untouched);
* the Expand → repair → **global legacy-session revocation** → Enforce cutover
  ordering (4.1 step 5), proving legacy sessions are *revoked, never
  backfilled* — the migration-level half of that proof, which until now
  existed only at service level;
* the downgrade → re-upgrade round trip (4.5).

This module owns the schema: it resets the database repeatedly and restores
``head`` at teardown, so every other Layer B module can rely on
``migrated_database`` regardless of execution order.
"""

from __future__ import annotations

import uuid
from typing import Iterator

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlmodel import SQLModel

from auth_user_service.db_models.privileged_action_audit import PrivilegedActionAudit
from auth_user_service.db_models.security_policy import SecurityPolicy
from auth_user_service.db_models.sessions import ClientSession
from auth_user_service.db_models.users import User
from auth_user_service.services.legacy_session_revocation import (
    GlobalLegacySessionRevocationController,
)
from tests.integration.database._engines import EngineSpec
from tests.integration.database._schema import (
    column_names,
    has_check_constraint,
    reset_database,
    table_names,
)
from tests.integration.database.conftest import (
    build_alembic_config,
    selected_engine_spec,
)

pytestmark = pytest.mark.database_integration

_CHECK_NAME = "ck_user_superuser_role_consistency"


def _ordered_revisions(spec: EngineSpec) -> list[str]:
    """Every revision of this dialect's certified chain, oldest first."""
    script = ScriptDirectory.from_config(build_alembic_config(spec))
    return [rev.revision for rev in reversed(list(script.walk_revisions()))]


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Parametrize the prior-revision upgrade over the selected chain."""
    if "prior_revision" in metafunc.fixturenames:
        spec = selected_engine_spec(metafunc.config)
        revisions = _ordered_revisions(spec)
        # The head revision is not a *prior* revision; upgrading from it is the
        # no-op the "from empty" test already covers.
        metafunc.parametrize("prior_revision", revisions[:-1])


@pytest.fixture(scope="module", autouse=True)
def restore_head(it_engine: sa.Engine, alembic_config: Config) -> Iterator[None]:
    """Leave the target at ``head`` however this module ends."""
    yield
    reset_database(it_engine)
    command.upgrade(alembic_config, "head")


@pytest.fixture
def empty_database(it_engine: sa.Engine) -> sa.Engine:
    """A genuinely empty target — no tables, no enum types, no triggers."""
    reset_database(it_engine)
    return it_engine


# ── upgrade from empty ────────────────────────────────────────────────────────


def test_upgrade_head_from_empty_database(
    empty_database: sa.Engine, alembic_config: Config
) -> None:
    """The full chain applies to an empty database and lands on ``head``."""
    command.upgrade(alembic_config, "head")

    present = table_names(empty_database)
    for table in (
        User.__tablename__,
        ClientSession.__tablename__,
        SecurityPolicy.__tablename__,
        PrivilegedActionAudit.__tablename__,
        "auth_revocation_outbox",
        "auth_tombstone",
        "auth_api_key",
        "auth_api_key_audiences",
    ):
        assert table in present, f"{table} missing after upgrade head"

    script = ScriptDirectory.from_config(alembic_config)
    with empty_database.connect() as conn:
        applied = conn.execute(
            sa.text("SELECT version_num FROM alembic_version_auth_integration")
        ).scalar_one()
    assert applied == script.get_current_head()


def test_orm_metadata_matches_migrated_schema(
    empty_database: sa.Engine, alembic_config: Config
) -> None:
    """Every mapped table's column set matches what the migrations created.

    Guards the drift the unit suite structurally cannot see: it builds its
    schema from ``SQLModel.metadata`` itself, so a model change that no
    migration carries is invisible there and fatal in production.
    """
    command.upgrade(alembic_config, "head")

    present = table_names(empty_database)
    checked = 0
    for table_name, table in SQLModel.metadata.tables.items():
        if table_name not in present:
            # Bundled-example models share the metadata registry; only the
            # issuer's own tables are created by the issuer's chain.
            continue
        expected = {column.name for column in table.columns}
        assert column_names(empty_database, table_name) == expected, (
            f"{table_name}: migrated schema does not match the ORM metadata"
        )
        checked += 1
    assert checked >= 8, "expected the issuer's mapped tables to be reflected"


# ── upgrade from every supported prior revision ───────────────────────────────


def test_upgrade_to_head_from_prior_revision(
    empty_database: sa.Engine, alembic_config: Config, prior_revision: str
) -> None:
    """A database parked at any supported prior revision upgrades cleanly.

    Parametrized over the whole certified chain, so a migration that only works
    when applied in one particular batch is caught here rather than during a
    maintenance window.
    """
    command.upgrade(alembic_config, prior_revision)
    command.upgrade(alembic_config, "head")

    assert has_check_constraint(empty_database, User.__tablename__, _CHECK_NAME)
    session_columns = {
        c["name"]: c
        for c in sa.inspect(empty_database).get_columns(ClientSession.__tablename__)
    }
    assert session_columns["auth_generation"]["nullable"] is False
    assert PrivilegedActionAudit.__tablename__ in table_names(empty_database)


# ── invalid migration state fails and rolls back ──────────────────────────────


def _expand_revision(alembic_config: Config) -> str:
    """The generation **Expand** revision — the pre-Enforce cutover checkpoint."""
    script = ScriptDirectory.from_config(alembic_config)
    for rev in reversed(list(script.walk_revisions())):
        doc = (rev.doc or "").lower()
        if doc.startswith("expand") and "generation" in doc:
            return rev.revision
    raise AssertionError("no generation Expand revision found in the certified chain")


def _insert_mismatched_user(engine: sa.Engine, email: str) -> None:
    """Raw-insert a role/flag-mismatched row, as a real pre-repair DB holds."""
    if engine.dialect.name == "postgresql":
        id_sql = "gen_random_uuid()"
    else:
        id_sql = "REPLACE(UUID(), '-', '')"
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO auth_user (created_at, updated_at, provider, email, "
                "is_active, email_verified, is_superuser, role, auth_generation, id) "
                "VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'PASSWORD', :email, "
                f"true, true, true, 'READER', 1, {id_sql})"  # nosec B608 — literal
            ),
            {"email": email},
        )


def test_enforce_fails_and_rolls_back_over_inconsistent_rows(
    empty_database: sa.Engine, alembic_config: Config
) -> None:
    """Enforce over un-repaired rows fails cleanly and changes nothing.

    This is the migration-level statement of the 4.1 precondition: the operator
    must repair every mismatched account *before* Enforce. If the failure left
    a half-applied schema behind, the maintenance window would have no safe
    resume point — so the assertion is not just "it raised" but "the CHECK is
    absent and the recorded revision is unchanged".
    """
    expand = _expand_revision(alembic_config)
    command.upgrade(alembic_config, expand)
    _insert_mismatched_user(empty_database, "enforce-blocker@example.com")

    with pytest.raises(Exception):  # noqa: B017 — dialect-specific DDL failure
        command.upgrade(alembic_config, "head")

    assert not has_check_constraint(empty_database, User.__tablename__, _CHECK_NAME)
    with empty_database.connect() as conn:
        recorded = conn.execute(
            sa.text("SELECT version_num FROM alembic_version_auth_integration")
        ).scalar_one()
    assert recorded == expand

    # And the documented remedy works: repair the row, re-run, done.
    with empty_database.begin() as conn:
        conn.execute(
            sa.text("UPDATE auth_user SET is_superuser = false WHERE email = :email"),
            {"email": "enforce-blocker@example.com"},
        )
    command.upgrade(alembic_config, "head")
    assert has_check_constraint(empty_database, User.__tablename__, _CHECK_NAME)


# ── cutover ordering: legacy sessions are revoked, never backfilled ───────────


def test_legacy_sessions_are_revoked_not_backfilled_before_enforce(
    empty_database: sa.Engine, alembic_config: Config
) -> None:
    """4.1 step 5 at the schema level (``MIG-LEGACY-01``).

    At Expand, ``ClientSession.auth_generation`` is still nullable and every
    pre-cutover row carries ``NULL``. The cutover sweep **deletes** those rows —
    backfilling a generation would bless the stale role a still-wire-valid old
    token carries — and only then can Enforce make the column ``NOT NULL``.
    Proven end to end on a real engine: rows with a real generation survive the
    sweep, ``NULL`` rows do not, and Enforce succeeds only afterwards.

    Amendment G3 of the Phase 3A review: this proof previously existed only as
    a service-level test, never as a migration test.
    """
    from sqlmodel import Session

    expand = _expand_revision(alembic_config)
    command.upgrade(alembic_config, expand)

    owner_id = uuid.uuid4()
    id_sql = (
        ":owner_id" if empty_database.dialect.name == "postgresql" else ":owner_hex"
    )
    with empty_database.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO auth_user (created_at, updated_at, provider, email, "
                "is_active, email_verified, is_superuser, role, auth_generation, id) "
                "VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'PASSWORD', "
                f"'legacy-owner@example.com', true, true, false, 'READER', 3, {id_sql})"  # nosec B608
            ),
            {"owner_id": owner_id, "owner_hex": owner_id.hex},
        )
        for jti, generation in (("legacy-null-jti", None), ("modern-jti", 3)):
            conn.execute(
                sa.text(
                    "INSERT INTO auth_client_session (created_at, updated_at, "
                    "provider, jwt_jti, refresh_token_hash, jwt_expires_at, "
                    "refresh_expires_at, revoked, id, user_id, auth_generation) "
                    "VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'PASSWORD', :jti, "
                    "'h', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, false, :sid, "
                    f"{id_sql}, :generation)"  # nosec B608
                ),
                {
                    "jti": jti,
                    "sid": jti,
                    "owner_id": owner_id,
                    "owner_hex": owner_id.hex,
                    "generation": generation,
                },
            )

    # Enforce cannot be applied while a NULL generation is still present.
    with pytest.raises(Exception):  # noqa: B017 — dialect-specific DDL failure
        command.upgrade(alembic_config, "head")

    with Session(empty_database) as session:
        result = GlobalLegacySessionRevocationController.revoke_legacy_sessions(session)
    assert result.revoked_count == 1

    with empty_database.connect() as conn:
        surviving = [
            row[0]
            for row in conn.execute(sa.text("SELECT jwt_jti FROM auth_client_session"))
        ]
    assert surviving == ["modern-jti"], (
        "the legacy row must be revoked by deletion and the generation-carrying "
        "row must survive — never a backfill"
    )

    command.upgrade(alembic_config, "head")
    session_columns = {
        c["name"]: c
        for c in sa.inspect(empty_database).get_columns(ClientSession.__tablename__)
    }
    assert session_columns["auth_generation"]["nullable"] is False


# ── downgrade round trip (4.5) ────────────────────────────────────────────────


@pytest.mark.destructive
def test_downgrade_to_baseline_then_upgrade_round_trip(
    empty_database: sa.Engine, alembic_config: Config
) -> None:
    """Every revision this plan owns downgrades cleanly and re-applies (4.5).

    Walks back exactly as far as the plan's own revisions reach (audit-table
    Expand, Enforce, generation Expand) and no further: the pre-plan baseline
    migration's own ``downgrade()`` is out of scope and is not certified here.
    """
    command.upgrade(alembic_config, "head")

    command.downgrade(alembic_config, "-1")
    assert PrivilegedActionAudit.__tablename__ not in table_names(empty_database)

    command.downgrade(alembic_config, "-1")
    assert not has_check_constraint(empty_database, User.__tablename__, _CHECK_NAME)
    session_columns = {
        c["name"]: c
        for c in sa.inspect(empty_database).get_columns(ClientSession.__tablename__)
    }
    assert session_columns["auth_generation"]["nullable"] is True

    command.downgrade(alembic_config, "-1")
    remaining = table_names(empty_database)
    for dropped in (
        "auth_revocation_outbox",
        "auth_tombstone",
        SecurityPolicy.__tablename__,
        "auth_api_key_audiences",
    ):
        assert dropped not in remaining
    assert "auth_generation" not in column_names(empty_database, User.__tablename__)
    assert "access_mode" not in column_names(empty_database, "auth_api_key")

    command.upgrade(alembic_config, "head")
    assert has_check_constraint(empty_database, User.__tablename__, _CHECK_NAME)
    assert PrivilegedActionAudit.__tablename__ in table_names(empty_database)
    with empty_database.connect() as conn:
        seeded = conn.execute(
            sa.text(
                "SELECT revision FROM auth_security_policy "
                "WHERE policy_key = 'superuser_set'"
            )
        ).scalar_one()
    assert seeded == 0
