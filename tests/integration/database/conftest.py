"""Layer B database integration fixtures (``TEST-DB-01``, ``TEST-LAYER-01``, 4.6).

White-box validation of ORM mappings, repositories, SQL transactions, Alembic
migrations, constraints, locking, concurrency, and dialect compatibility against
**ephemeral real database containers** — never the SQLite unit-test surrogate,
which by contract may never certify migrations, isolation, locking, or
engine-enforced constraint semantics (4.6).

Selecting the engine under test::

    pytest -m database_integration tests/integration/database --database=postgresql
    pytest -m database_integration tests/integration/database --database=mysql
    pytest -m database_integration tests/integration/database --database=mariadb

``--database`` is registered in ``tests/conftest.py`` (the always-initial
conftest); ``FA_AUTH_IT_DIALECT`` is the equivalent environment selector for
runners that cannot pass options. ``FA_AUTH_IT_MODE=external`` consumes an
already-running instance (the CI service-container shape) instead of starting a
container here.

The suite is excluded from the default run by ``pytest.ini``'s
``-m "not database_integration"``, so the unit gate stays Docker-free and its
100% coverage threshold keeps measuring exactly what it measured before
(``TEST-LAYER-01``: Layer B may contribute coverage but is never required to
reach the unit threshold).
"""

from __future__ import annotations

import os
from typing import Iterator

import pytest
import sqlalchemy as sa
from alembic.config import Config
from sqlmodel import Session

from tests.integration.database._engines import (
    CONNECT_TIMEOUT_SECONDS,
    DIALECTS,
    ENGINE_SPECS,
    REPO_ROOT,
    DockerUnavailable,
    Endpoint,
    EngineSpec,
    EphemeralDatabase,
    apply_deployment_prerequisites,
    docker_is_available,
    external_endpoint,
    wait_until_ready,
)
from tests.integration.database._schema import reset_database

#: Alembic version table for this suite — private, so a mistakenly shared
#: database can never have its application migration state rewritten by a run.
VERSION_TABLE = "alembic_version_auth_integration"

#: Rows every test starts without, in foreign-key-safe deletion order. The
#: seeded ``security_policy`` singleton is deliberately absent: it is schema,
#: not test data, and the lock protocol depends on it existing.
_TRUNCATION_ORDER = (
    "auth_revocation_outbox",
    "auth_tombstone",
    "auth_api_key_audiences",
    "auth_rate_limit",
    "auth_api_key",
    "auth_client_session",
    "auth_user",
)


def pytest_collection_modifyitems(config: pytest.Config, items: list) -> None:
    """Mark everything in this package as Layer B, so one selector covers it."""
    for item in items:
        if "integration/database" in str(item.fspath).replace(os.sep, "/"):
            item.add_marker(pytest.mark.database_integration)


def selected_engine_spec(config: pytest.Config) -> EngineSpec:
    """Resolve the certified engine under test from ``--database``/env (4.6).

    Exposed as a plain function as well as a fixture because parametrization
    (``pytest_generate_tests``) needs the answer at collection time, before any
    fixture has run.
    """
    selected = config.getoption("--database", default=None) or os.environ.get(
        "FA_AUTH_IT_DIALECT", "postgresql"
    )
    if selected not in ENGINE_SPECS:
        raise pytest.UsageError(
            f"--database={selected!r} is not a certified dialect; "
            f"choose one of {', '.join(DIALECTS)} (4.6)"
        )
    return ENGINE_SPECS[selected]


@pytest.fixture(scope="session")
def engine_spec(request: pytest.FixtureRequest) -> EngineSpec:
    """The certified engine under test, chosen by ``--database``/env (4.6)."""
    return selected_engine_spec(request.config)


@pytest.fixture(scope="session")
def db_endpoint(engine_spec: EngineSpec) -> Iterator[Endpoint]:
    """A disposable instance of the selected engine: container or external."""
    mode = os.environ.get("FA_AUTH_IT_MODE", "container")
    if mode == "external":
        endpoint = external_endpoint(engine_spec)
        wait_until_ready(engine_spec, endpoint)
        apply_deployment_prerequisites(engine_spec, endpoint)
        yield endpoint
        return

    if not docker_is_available():
        pytest.skip(
            "Layer B needs an ephemeral database container: no Docker daemon is "
            "reachable and FA_AUTH_IT_MODE is not 'external' (TEST-DB-01)."
        )
    container = EphemeralDatabase(engine_spec)
    try:
        endpoint = container.start()
    except DockerUnavailable as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"Could not start the {engine_spec.key} container: {exc}")
    try:
        apply_deployment_prerequisites(engine_spec, endpoint)
        yield endpoint
    finally:
        container.stop()


@pytest.fixture(scope="session", autouse=True)
def configured_settings(
    engine_spec: EngineSpec, db_endpoint: Endpoint
) -> Iterator[None]:
    """Point the issuer settings at the ephemeral target for the whole session.

    ``auth_user_service/alembic/env.py`` resolves its connection from
    ``settings`` (``get_url()`` ignores whatever ``sqlalchemy.url`` an Alembic
    ``Config`` carries), and the service code under test builds its own engines
    the same way, so redirecting the singleton is what makes both talk to this
    container. Original values are restored at teardown so a combined run can
    never leak the real target into another suite.
    """
    from pydantic import SecretStr

    from auth_user_service.core.config import settings

    fields = {
        "SELECTED_DB": engine_spec.selected_db,
        "DB_HOST": db_endpoint.host,
        "DB_PORT": db_endpoint.port,
        "DB_DATABASE": db_endpoint.database,
        "DB_USER": db_endpoint.user,
        # ``SQLALCHEMY_DATABASE_URI`` calls ``get_secret_value()`` on this field,
        # so the redirect must preserve its ``SecretStr`` type, not just its value.
        "DB_PASSWORD": SecretStr(db_endpoint.password),
    }
    previous = {name: getattr(settings, name) for name in fields}
    for name, value in fields.items():
        setattr(settings, name, value)
    try:
        yield
    finally:
        for name, value in previous.items():
            setattr(settings, name, value)


@pytest.fixture(scope="session")
def it_engine(
    engine_spec: EngineSpec, db_endpoint: Endpoint, configured_settings: None
) -> Iterator[sa.Engine]:
    """Primary engine for the suite (``pool_size`` leaves room for races)."""
    engine = sa.create_engine(
        db_endpoint.uri(engine_spec),
        future=True,
        pool_size=5,
        max_overflow=10,
        connect_args={"connect_timeout": CONNECT_TIMEOUT_SECONDS},
    )
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def second_engine(
    engine_spec: EngineSpec, db_endpoint: Endpoint, configured_settings: None
) -> Iterator[sa.Engine]:
    """A **separate** engine, so concurrency tests use genuinely distinct
    connections rather than two sessions sharing one pooled connection."""
    engine = sa.create_engine(
        db_endpoint.uri(engine_spec),
        future=True,
        pool_size=5,
        connect_args={"connect_timeout": CONNECT_TIMEOUT_SECONDS},
    )
    yield engine
    engine.dispose()


def build_alembic_config(engine_spec: EngineSpec) -> Config:
    """Alembic config bound to this dialect's certified example chain (4.6)."""
    cfg = Config()
    cfg.set_main_option(
        "script_location", str(REPO_ROOT / "auth_user_service" / "alembic")
    )
    cfg.set_main_option("version_locations", str(engine_spec.version_locations))
    cfg.set_main_option("version_table", VERSION_TABLE)
    return cfg


@pytest.fixture(scope="session")
def alembic_config(engine_spec: EngineSpec) -> Config:
    return build_alembic_config(engine_spec)


@pytest.fixture(scope="session")
def migrated_database(
    it_engine: sa.Engine, alembic_config: Config
) -> Iterator[sa.Engine]:
    """Bring the disposable target to ``head`` once for the whole session.

    Every non-migration module consumes this; the migration module owns its own
    reset/rebuild cycle and restores ``head`` when it finishes, so module order
    never matters.
    """
    from alembic import command

    reset_database(it_engine)
    command.upgrade(alembic_config, "head")
    yield it_engine


def clear_audit_rows(connection: sa.Connection, dialect: str) -> None:
    """Delete audit rows through the purge authorization the guard trigger requires.

    The Expand migration installs a ``BEFORE DELETE`` guard that rejects any
    delete unless the purge flag is set, so even fixture cleanup must perform
    the same dance ``purge_expired_audit_rows`` performs — which is itself
    evidence the guard is real.
    """
    if dialect == "postgresql":
        connection.execute(
            sa.text("SELECT set_config('audit.purge_active', 'true', true)")
        )
    else:
        connection.execute(sa.text("SET @audit_purge_active = 1"))
    connection.execute(sa.text("DELETE FROM auth_privileged_action_audit"))
    if dialect != "postgresql":
        connection.execute(sa.text("SET @audit_purge_active = NULL"))


@pytest.fixture
def clean_database(migrated_database: sa.Engine) -> Iterator[sa.Engine]:
    """Empty every plan-owned table before each test (FK-safe order)."""
    engine = migrated_database
    with engine.begin() as conn:
        for table in _TRUNCATION_ORDER:
            conn.execute(sa.text(f"DELETE FROM {table}"))  # nosec B608 — fixed names
        clear_audit_rows(conn, engine.dialect.name)
        conn.execute(sa.text("UPDATE auth_security_policy SET revision = 0"))
    yield engine


@pytest.fixture
def it_session(clean_database: sa.Engine) -> Iterator[Session]:
    """A SQLModel session on the ephemeral target, on a clean schema."""
    with Session(clean_database) as session:
        yield session
        session.rollback()
