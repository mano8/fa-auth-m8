"""The bundled example's ``m8_app`` chain, applied to the Layer B target (P9-4).

Layer B certifies the **issuer's** schema on real engines. The consumer example
in ``examples/fastapi_full`` ships a second, structurally identical guarantee —
``app_privileged_action_audit`` is write-once and removable only by the
horizon-bounded retention purge, enforced by a trigger its Expand migration
installs — and that guarantee had no gate anywhere: the example's own unit suite
runs on SQLite, where by the example's own ``_PURGE_GUARDED_DIALECTS`` design no
trigger exists at all, and the smoke workflow proves only that the migration
*applies*, never that an ``UPDATE`` or a targeted ``DELETE`` is *rejected*.

This module is what closes that gap. It supplies three things to
``test_example_audit_triggers.py``:

* the example's ``m8_app`` chain for the dialect under test, selected from the
  same certifying compose stack that already supplies the issuer chain
  (:attr:`~tests.integration.database._engines.EngineSpec.app_version_locations`);
* the example's **own** Alembic configuration — its ``alembic/env.py``, not the
  issuer's — which is precisely what the Phase 7 record said was missing, so
  applying the chain also proves that env resolves and runs against a real
  engine; and
* the example package itself, imported against the ephemeral target, so the
  purge under test is the one ``fastapi_full`` actually ships rather than a
  re-implementation of it in a test.

The example is a *consumer service* with its own settings object and package
root: ``fastapi_full.core.config`` validates at import time and its
``find_dotenv()`` lookup raises when no ``.env`` exists, so a complete throwaway
environment has to be in place before the first import — the same bootstrap
``examples/fastapi_full/tests/conftest.py`` performs, with the database block
pointed at this suite's disposable container instead of a placeholder.
"""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from types import ModuleType
from typing import Iterator, Optional

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from tests.integration.database._engines import REPO_ROOT, Endpoint, EngineSpec
from tests.integration.database._schema import table_names

#: Import root of the bundled example: ``examples/fastapi_full`` is the package
#: ``fastapi_full``, exactly as ``examples/fastapi_full/pytest.ini`` declares.
EXAMPLES_ROOT = REPO_ROOT / "examples"

#: The example's own Alembic environment — the config the deployed consumer
#: runs, reused here rather than approximated with the issuer's.
EXAMPLE_SCRIPT_LOCATION = EXAMPLES_ROOT / "fastapi_full" / "alembic"

#: Private version table for the example chain under test, for the same reason
#: the issuer chain has one: a mistakenly shared database can never have its
#: real application migration state (``alembic_version_m8``) rewritten by a run.
APP_VERSION_TABLE = "alembic_version_m8_app_integration"

#: Tables the example's ``m8_app`` chain owns.
AUDIT_TABLE = "app_privileged_action_audit"
CATEGORY_TABLE = "app_category"

#: Everything the example's settings require that is not database connection
#: detail. Mirrors ``examples/fastapi_full/tests/conftest.py``'s bootstrap:
#: throwaway local-profile placeholders, no socket is ever opened with them.
_STATIC_ENVIRONMENT = {
    "DOMAIN": "localhost",
    "ENVIRONMENT": "local",
    "PROJECT_NAME": "fastapi-full-layer-b",
    "STACK_NAME": "fastapi-full-layer-b",
    "API_PREFIX": "/fastapi",
    "BACKEND_HOST": "http://127.0.0.1:9000",
    "FRONTEND_HOST": "http://localhost:5173",
    "BACKEND_CORS_ORIGINS": "http://localhost:9000",
    "AUTH_SERVICE_ROLE": "consumer",
    "AUTH_PREFIX": "/user",
    # 32+ characters with mixed case and digits: the SDK's secret-strength
    # validator refuses anything weaker, and these are throwaways.
    "SECRET_KEY": "LayerB-SessionSecret-fastapi-full-Ab1",  # nosec B105
    "ACCESS_SECRET_KEY": "LayerB-AccessKey-fastapi-full-Ab12Cd",  # nosec B105
    "REFRESH_SECRET_KEY": "LayerB-RefreshKey-fastapi-full-Ab12Cd",  # nosec B105
    "ACCESS_TOKEN_ALGORITHM": "HS256",
    "REFRESH_TOKEN_ALGORITHM": "HS256",
    "TOKEN_MODE": "stateless",
    "TOKEN_STRICT_VALIDATION": "false",
    "EVENT_SIGNING_ENABLED": "false",
    "METRICS_ENABLED": "false",
}


@dataclass(frozen=True)
class ExampleAudit:
    """The bundled example's audit surface, bound to the Layer B target.

    Every attribute is the object ``fastapi_full`` itself exports, so a test
    written against this dataclass exercises shipped code rather than a copy.
    """

    #: ``fastapi_full.app.audit`` — the recorder and the retention purge.
    module: ModuleType
    #: ``PrivilegedActionAudit``: the mapped, write-once audit row.
    model: type
    #: ``AuditAction``: ``add`` / ``edit`` / ``delete``.
    action: type
    #: ``RetentionWindow``: the fixed windows the purge accepts.
    window: type


def _database_environment(spec: EngineSpec, endpoint: Endpoint) -> dict[str, str]:
    """The example settings' database block, pointed at the disposable target.

    ``SELECTED_DB`` carries the dialect declaration of the certifying stack
    (4.6), so the example resolves the same driver the issuer chain runs on.
    """
    return {
        "SELECTED_DB": spec.selected_db,
        "DB_HOST": endpoint.host,
        "DB_PORT": str(endpoint.port),
        "DB_DATABASE": endpoint.database,
        "DB_USER": endpoint.user,
        "DB_PASSWORD": endpoint.password,
    }


@contextmanager
def loaded_example(spec: EngineSpec, endpoint: Endpoint) -> Iterator[ExampleAudit]:
    """Import the example's audit surface configured against *endpoint*.

    The environment is seeded and ``find_dotenv`` stubbed **before** the first
    ``fastapi_full`` import, then both are restored, so neither a developer's
    ``.env`` nor this bootstrap can leak into the rest of the session. The
    example's settings singleton is built during that window and keeps pointing
    at *endpoint* afterwards — which is why this is entered once per session,
    with the session-scoped endpoint.
    """
    environment = {**_STATIC_ENVIRONMENT, **_database_environment(spec, endpoint)}
    previous: dict[str, Optional[str]] = {
        name: os.environ.get(name) for name in environment
    }
    os.environ.update(environment)

    examples_root = str(EXAMPLES_ROOT)
    added_to_path = examples_root not in sys.path
    if added_to_path:
        sys.path.insert(0, examples_root)

    import auth_sdk_m8.utils.paths as paths_module

    real_find_dotenv = paths_module.find_dotenv
    paths_module.find_dotenv = lambda *_args, **_kwargs: ""
    try:
        import fastapi_full.app.audit as example_audit
        from fastapi_full.db_models.privileged_action_audit import (
            AuditAction,
            PrivilegedActionAudit,
        )

        yield ExampleAudit(
            module=example_audit,
            model=PrivilegedActionAudit,
            action=AuditAction,
            window=example_audit.RetentionWindow,
        )
    finally:
        paths_module.find_dotenv = real_find_dotenv
        if added_to_path:
            sys.path.remove(examples_root)
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def build_example_alembic_config(spec: EngineSpec) -> Config:
    """The example's own Alembic config, bound to this dialect's chain (4.6).

    ``script_location`` is the example's ``alembic/`` directory, so its
    ``env.py`` resolves the URL from ``fastapi_full``'s settings — which
    :func:`loaded_example` has already pointed at the disposable target.
    """
    config = Config()
    config.set_main_option("script_location", str(EXAMPLE_SCRIPT_LOCATION))
    config.set_main_option("version_locations", str(spec.app_version_locations))
    # Declared rather than inherited: without it Alembic falls back to splitting
    # ``version_locations`` on spaces and commas, which a checkout path is free
    # to contain.
    config.set_main_option("path_separator", "os")
    config.set_main_option("version_table", APP_VERSION_TABLE)
    return config


def apply_example_chain(engine: sa.Engine, spec: EngineSpec) -> None:
    """Bring the example's ``m8_app`` chain to ``head`` on the Layer B target.

    Idempotent in any module order: ``test_migrations.py`` drops and recreates
    the whole schema, which takes the example's tables with it while a private
    version table could survive on another dialect's reset path, so a claimed
    head with no tables behind it is forgotten before re-applying.
    """
    config = build_example_alembic_config(spec)
    if AUDIT_TABLE not in table_names(engine):
        command.stamp(config, "base")
    command.upgrade(config, "head")


@contextmanager
def purge_authorized(connection: sa.Connection, dialect: str) -> Iterator[None]:
    """Hold the flag the Expand migration's ``BEFORE DELETE`` guard requires.

    The example's ``_set_purge_delete_authorized`` performs this dance inside
    its own session; fixture cleanup needs it on a raw connection, and the flag
    is cleared on the way out because MySQL/MariaDB session variables outlive
    the transaction on a pooled connection while PostgreSQL's transaction-local
    ``set_config`` resets itself.
    """
    if dialect == "postgresql":
        connection.execute(
            sa.text("SELECT set_config('audit.purge_active', 'true', true)")
        )
    else:
        connection.execute(sa.text("SET @audit_purge_active = 1"))
    try:
        yield
    finally:
        if dialect != "postgresql":
            connection.execute(sa.text("SET @audit_purge_active = NULL"))


def clear_example_audit_rows(engine: sa.Engine) -> None:
    """Empty the example's audit table through the authorization its guard demands."""
    with engine.begin() as connection:
        with purge_authorized(connection, engine.dialect.name):
            connection.execute(sa.text(f"DELETE FROM {AUDIT_TABLE}"))  # nosec B608
        connection.execute(sa.text(f"DELETE FROM {CATEGORY_TABLE}"))  # nosec B608
