"""Live certification of the split Expand/Enforce Alembic migrations.

Owner: ``MIG-CUTOVER-01``/``MIG-DIALECT-01`` (40-migration-release.md §4.1,
§4.6). Runs the real migration files against a real target engine — never
SQLite, which is a unit-test surrogate only and is never used to certify
migrations, constraints, or locking (§4.6).

Alembic's ``auth_user_service/alembic/env.py`` always resolves its connection
from ``auth_user_service.core.config.settings`` (``get_url()`` ignores
whatever ``sqlalchemy.url`` a Config object carries), so this module targets a
database the same way the app itself does: via ``DB_HOST``/``DB_PORT``/
``DB_DATABASE``/``DB_USER``/``DB_PASSWORD``/``SELECTED_DB``. Point those at a
**disposable** database on the engine you want to certify (never an example
stack's working ``auth_db`` — ``test_downgrade_then_upgrade_round_trip`` drops
and recreates schema objects and would corrupt a database a running
``auth_user_service`` depends on), then opt in explicitly:

    # PostgreSQL (matches examples/docker_compose/postgres_m8)
    export DB_HOST=localhost DB_PORT=5432 DB_DATABASE=auth_db_migtest \\
           DB_USER=auth_user DB_PASSWORD=<pw> SELECTED_DB=Postgres
    export MIGRATION_VERSION_LOCATIONS=examples/docker_compose/postgres_m8/shared_migrations/auth_user/versions
    RUN_MIGRATION_LIVE_TESTS=1 pytest tests/live/test_migration_split.py -m live

    # MariaDB (matches examples/docker_compose/quickstart_m8)
    export DB_HOST=localhost DB_PORT=3306 DB_DATABASE=auth_db_migtest \\
           DB_USER=auth_user DB_PASSWORD=<pw> SELECTED_DB=Mysql
    export MIGRATION_VERSION_LOCATIONS=examples/docker_compose/quickstart_m8/shared_migrations/auth_user/versions
    RUN_MIGRATION_LIVE_TESTS=1 pytest tests/live/test_migration_split.py -m live

    # MySQL (matches examples/docker_compose/rs256_m8 after its 4.6 reassignment)
    export DB_HOST=localhost DB_PORT=3307 DB_DATABASE=auth_db_migtest \\
           DB_USER=auth_user DB_PASSWORD=<pw> SELECTED_DB=Mysql
    export MIGRATION_VERSION_LOCATIONS=examples/docker_compose/rs256_m8/shared_migrations/auth_user/versions
    RUN_MIGRATION_LIVE_TESTS=1 pytest tests/live/test_migration_split.py -m live

The whole module is skipped unless ``RUN_MIGRATION_LIVE_TESTS=1`` is set —
this is a stricter, dedicated opt-in rather than gating on the ``DB_*``
variables directly, because ``tests/conftest.py`` always seeds hermetic
``DB_*`` defaults (``setdefault``) for the unit suite, so their mere presence
never implies a real, disposable target is available. It uses a private
``version_table`` (``alembic_version_auth_migtest``) so it never collides with
an app instance's own migration state even if pointed at the same physical
database by mistake, but the row/table content it creates and drops
(``auth_user``, ``auth_client_session``, ``auth_api_key``, ...) is still
shared, so isolation is by database, not by table prefix.
"""

import os
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError

RUN_LIVE = os.environ.get("RUN_MIGRATION_LIVE_TESTS") == "1"

# PostgreSQL raises IntegrityError for a CHECK violation; MySQL/MariaDB raise
# OperationalError (errno 3819) for the same condition via pymysql. Both are
# DBAPIError subclasses, so tests assert on that shared base rather than
# picking one dialect's exception type.
_CONSTRAINT_VIOLATION = DBAPIError

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_LOCATION = REPO_ROOT / "auth_user_service" / "alembic"
_DEFAULT_VERSION_LOCATIONS = (
    REPO_ROOT
    / "examples"
    / "docker_compose"
    / "postgres_m8"
    / "shared_migrations"
    / "auth_user"
    / "versions"
)
VERSION_LOCATIONS = Path(
    os.environ.get("MIGRATION_VERSION_LOCATIONS", str(_DEFAULT_VERSION_LOCATIONS))
)
VERSION_TABLE = "alembic_version_auth_migtest"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not RUN_LIVE, reason="RUN_MIGRATION_LIVE_TESTS not set — see module docstring"
    ),
]


def _alembic_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(SCRIPT_LOCATION))
    cfg.set_main_option("version_locations", str(VERSION_LOCATIONS))
    cfg.set_main_option("version_table", VERSION_TABLE)
    return cfg


def _engine() -> sa.Engine:
    # Same resolution path env.py itself uses (get_url() ignores the Alembic
    # Config's sqlalchemy.url) — see module docstring.
    from auth_user_service.core.config import settings

    return sa.create_engine(str(settings.SQLALCHEMY_DATABASE_URI), future=True)


@pytest.fixture(scope="module")
def alembic_config() -> Config:
    return _alembic_config()


@pytest.fixture(scope="module")
def migrated_engine(alembic_config):
    """Upgrade the disposable database to head once for the whole module."""
    command.upgrade(alembic_config, "head")
    engine = _engine()
    yield engine
    engine.dispose()


# ---------------------------------------------------------------------------
# TEST-DB-01 (partial): raw-insert CHECK vs. NOT NULL, proven separately so
# neither constraint's test can pass for the wrong reason (40 §4.1).
# ---------------------------------------------------------------------------


def test_enforce_check_rejects_role_flag_mismatch(migrated_engine):
    """A raw INSERT with a mismatched role/is_superuser pair violates the
    named equivalence CHECK (``ck_user_superuser_role_consistency``), proven
    independent of NOT NULL by supplying every NOT NULL column a valid value.
    """
    with migrated_engine.connect() as conn:
        trans = conn.begin()
        try:
            with pytest.raises(
                _CONSTRAINT_VIOLATION, match="ck_user_superuser_role_consistency"
            ):
                conn.execute(
                    sa.text(
                        "INSERT INTO auth_user "
                        "(created_at, updated_at, provider, email, is_active, "
                        "email_verified, is_superuser, role, id) "
                        "VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'PASSWORD', "
                        "'mismatch@example.com', true, true, true, 'READER', "
                        "gen_random_uuid())"
                    )
                    if migrated_engine.dialect.name == "postgresql"
                    else sa.text(
                        "INSERT INTO auth_user "
                        "(created_at, updated_at, provider, email, is_active, "
                        "email_verified, is_superuser, role, id) "
                        "VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'PASSWORD', "
                        "'mismatch@example.com', true, true, true, 'READER', "
                        # MySQL/MariaDB store the UUID as CHAR(32) (no
                        # hyphens); bare UUID() is 36 chars and would fail on
                        # "Data too long for column 'id'" before ever
                        # reaching the CHECK constraint this test targets.
                        "REPLACE(UUID(), '-', ''))"
                    )
                )
        finally:
            trans.rollback()


def test_privileged_action_audit_table_shape(migrated_engine):
    """The Phase 7 Expand migration creates the audit table with the exact
    columns the model declares, indexed on ``actor_user_id`` (schema-level
    proof the migration matches ``PrivilegedActionAudit``, independent of the
    guard-trigger tests below).
    """
    inspector = sa.inspect(migrated_engine)
    columns = {
        c["name"]: c for c in inspector.get_columns("auth_privileged_action_audit")
    }
    assert set(columns) == {
        "id",
        "created_at",
        "actor_user_id",
        "actor_role",
        "action",
        "table_name",
        "row_pk",
        "target_owner_id",
    }
    assert columns["target_owner_id"]["nullable"] is True
    for name in (
        "id",
        "created_at",
        "actor_user_id",
        "actor_role",
        "action",
        "table_name",
        "row_pk",
    ):
        assert columns[name]["nullable"] is False
    indexed_columns = {
        col
        for index in inspector.get_indexes("auth_privileged_action_audit")
        for col in index["column_names"]
    }
    assert "actor_user_id" in indexed_columns


def _insert_audit_row(conn: sa.Connection, *, row_id: str) -> None:
    conn.execute(
        sa.text(
            "INSERT INTO auth_privileged_action_audit "
            "(id, created_at, actor_user_id, actor_role, action, table_name, row_pk) "
            "VALUES (:id, CURRENT_TIMESTAMP, :id, 'SUPERADMIN', 'edit', 'auth_user', 'x')"
        ),
        {"id": row_id},
    )


def test_privileged_action_audit_rejects_update(migrated_engine):
    """The guard trigger unconditionally rejects any ``UPDATE`` — schema-level
    enforcement of the write-once contract (Phase 7 Expand migration).
    """
    row_id = "11111111-1111-1111-1111-111111111111"
    with migrated_engine.connect() as conn:
        trans = conn.begin()
        try:
            _insert_audit_row(conn, row_id=row_id)
            with pytest.raises(_CONSTRAINT_VIOLATION):
                conn.execute(
                    sa.text(
                        "UPDATE auth_privileged_action_audit SET row_pk = 'y' WHERE id = :id"
                    ),
                    {"id": row_id},
                )
        finally:
            trans.rollback()


def test_privileged_action_audit_rejects_unauthorized_targeted_delete(migrated_engine):
    """A raw, targeted single-row ``DELETE`` is rejected: the guard trigger
    only admits a ``DELETE`` when the purge-authorization flag is set, which
    only :func:`purge_expired_audit_rows` ever sets (Phase 7 Expand migration).
    """
    row_id = "22222222-2222-2222-2222-222222222222"
    with migrated_engine.connect() as conn:
        trans = conn.begin()
        try:
            _insert_audit_row(conn, row_id=row_id)
            with pytest.raises(_CONSTRAINT_VIOLATION):
                conn.execute(
                    sa.text("DELETE FROM auth_privileged_action_audit WHERE id = :id"),
                    {"id": row_id},
                )
        finally:
            trans.rollback()


def test_privileged_action_audit_allows_delete_when_purge_authorized(migrated_engine):
    """The exact authorization dance :func:`purge_expired_audit_rows` performs
    (dialect-specific flag set immediately before the ``DELETE``) succeeds —
    proving the trigger's exemption is real, not merely a rejection-only stub.
    """
    row_id = "33333333-3333-3333-3333-333333333333"
    with migrated_engine.connect() as conn:
        trans = conn.begin()
        try:
            _insert_audit_row(conn, row_id=row_id)
            if migrated_engine.dialect.name == "postgresql":
                conn.execute(
                    sa.text("SELECT set_config('audit.purge_active', 'true', true)")
                )
            else:
                conn.execute(sa.text("SET @audit_purge_active = 1"))
            conn.execute(
                sa.text("DELETE FROM auth_privileged_action_audit WHERE id = :id"),
                {"id": row_id},
            )
        finally:
            trans.rollback()


def test_enforce_not_null_rejects_missing_session_generation(migrated_engine):
    """A raw INSERT with ``auth_generation IS NULL`` on ``auth_client_session``
    fails NOT NULL, proven independent of the CHECK constraint (which lives on
    ``auth_user`` only, not this table).
    """
    with migrated_engine.connect() as conn:
        trans = conn.begin()
        try:
            owner_id = conn.execute(
                sa.text(
                    "INSERT INTO auth_user "  # nosec B608 — fully static SQL, no interpolated input
                    "(created_at, updated_at, provider, email, is_active, "
                    "email_verified, is_superuser, role, id, auth_generation) "
                    "VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'PASSWORD', "
                    "'session-owner@example.com', true, true, false, 'READER', "
                    + (
                        "gen_random_uuid(), 1) RETURNING id"
                        if migrated_engine.dialect.name == "postgresql"
                        else "REPLACE(UUID(), '-', ''), 1)"
                    )
                )
            )
            if migrated_engine.dialect.name == "postgresql":
                owner_uuid = owner_id.scalar_one()
            else:
                owner_uuid = conn.execute(
                    sa.text(
                        "SELECT id FROM auth_user WHERE email = 'session-owner@example.com'"
                    )
                ).scalar_one()

            with pytest.raises(_CONSTRAINT_VIOLATION):
                conn.execute(
                    sa.text(
                        "INSERT INTO auth_client_session "
                        "(created_at, updated_at, provider, jwt_jti, refresh_token_hash, "
                        "jwt_expires_at, refresh_expires_at, revoked, id, user_id, "
                        "auth_generation) "
                        "VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'PASSWORD', "
                        "'jti-null-generation', 'hash', CURRENT_TIMESTAMP, "
                        "CURRENT_TIMESTAMP, false, 'sess-null-gen', :owner_id, NULL)"
                    ),
                    {"owner_id": owner_uuid},
                )
        finally:
            trans.rollback()


# ---------------------------------------------------------------------------
# Downgrade round trip (MIG-CUTOVER-01, §4.5) — destructive, disposable DB only.
# ---------------------------------------------------------------------------


@pytest.mark.destructive
def test_downgrade_then_upgrade_round_trip(alembic_config, migrated_engine):
    """Enforce -> Expand -> the pre-existing baseline -> head leaves a clean,
    re-appliable schema: the CHECK constraint, the NOT NULL tightening, and
    every table Expand added are gone at baseline, and reappear correctly on
    re-upgrade (§4.5 — downgrade drops only the constraint, never data;
    re-upgrade is always safe afterward).

    Stops exactly at the baseline revision (three relative ``-1`` steps: the
    Phase 7 audit-table Expand, then Enforce, then the generation Expand)
    rather than downgrading past it to ``base`` — reaching the baseline
    revision runs only *this pair's plus the audit revision's*
    ``downgrade()`` functions, the ones owned by this TODO. Downgrading past
    baseline would additionally invoke the pre-existing (pre-plan) baseline
    migration's own downgrade(), which is out of scope here and not
    certified by this test.
    """
    inspector = sa.inspect(migrated_engine)

    # head -> audit-table Expand.downgrade() -> Enforce revision.
    command.downgrade(alembic_config, "-1")
    inspector = sa.inspect(migrated_engine)
    assert "auth_privileged_action_audit" not in inspector.get_table_names()

    # Enforce revision -> Enforce.downgrade() -> Expand revision.
    command.downgrade(alembic_config, "-1")
    inspector = sa.inspect(migrated_engine)
    checks = inspector.get_check_constraints("auth_user")
    assert not any(c["name"] == "ck_user_superuser_role_consistency" for c in checks)
    session_cols = {c["name"]: c for c in inspector.get_columns("auth_client_session")}
    assert session_cols["auth_generation"]["nullable"] is True

    # Expand revision -> Expand.downgrade() -> baseline revision.
    command.downgrade(alembic_config, "-1")
    inspector = sa.inspect(migrated_engine)
    assert "auth_revocation_outbox" not in inspector.get_table_names()
    assert "auth_tombstone" not in inspector.get_table_names()
    assert "auth_security_policy" not in inspector.get_table_names()
    assert "auth_api_key_audiences" not in inspector.get_table_names()
    assert "auth_generation" not in {
        c["name"] for c in inspector.get_columns("auth_user")
    }
    assert "access_mode" not in {
        c["name"] for c in inspector.get_columns("auth_api_key")
    }

    command.upgrade(alembic_config, "head")
    inspector = sa.inspect(migrated_engine)
    checks = inspector.get_check_constraints("auth_user")
    assert any(c["name"] == "ck_user_superuser_role_consistency" for c in checks)
    session_cols = {c["name"]: c for c in inspector.get_columns("auth_client_session")}
    assert session_cols["auth_generation"]["nullable"] is False
    assert "auth_privileged_action_audit" in inspector.get_table_names()
    with migrated_engine.connect() as conn:
        seeded = conn.execute(
            sa.text(
                "SELECT revision FROM auth_security_policy WHERE policy_key = 'superuser_set'"
            )
        ).scalar_one()
        assert seeded == 0
