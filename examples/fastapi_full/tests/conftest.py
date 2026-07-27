"""Test bootstrap for the bundled ``fastapi_full`` consumer example.

``fastapi_full.core.config`` validates its settings at import time and fails
fast when the configuration is incomplete, so a deterministic environment has
to exist before the first ``fastapi_full`` import. Environment variables
outrank any developer ``.env`` sitting next to the example, which keeps this
suite identical locally and in CI (where no ``.env`` is checked in).

Every value here is a throwaway local-profile placeholder: no test in this
suite opens a socket, and the only database is an in-memory SQLite surrogate
built from the package's own SQLModel metadata.
"""

from __future__ import annotations

import os
from typing import Iterator

_TEST_ENV = {
    "DOMAIN": "localhost",
    "ENVIRONMENT": "local",
    "PROJECT_NAME": "fastapi-full-tests",
    "STACK_NAME": "fastapi-full-tests",
    "API_PREFIX": "/fastapi",
    "BACKEND_HOST": "http://127.0.0.1:9000",
    "FRONTEND_HOST": "http://localhost:5173",
    "BACKEND_CORS_ORIGINS": "http://localhost:9000",
    "AUTH_SERVICE_ROLE": "consumer",
    "AUTH_PREFIX": "/user",
    "SELECTED_DB": "Postgres",
    "DB_HOST": "127.0.0.1",
    "DB_PORT": "5432",
    "DB_DATABASE": "api_db",
    "DB_USER": "example_tests_user",
    "DB_PASSWORD": "ExampleTests_Passw0rd",
    "SECRET_KEY": "ExampleTests-SessionSecret-fa8full-Ab1",
    "ACCESS_SECRET_KEY": "ExampleTests-AccessKey-fa8full-Ab12Cd",
    "REFRESH_SECRET_KEY": "ExampleTests-RefreshKey-fa8full-Ab12Cd",
    "ACCESS_TOKEN_ALGORITHM": "HS256",
    "REFRESH_TOKEN_ALGORITHM": "HS256",
    "TOKEN_MODE": "stateless",
    "TOKEN_STRICT_VALIDATION": "false",
    "EVENT_SIGNING_ENABLED": "false",
    "METRICS_ENABLED": "false",
}

for _key, _value in _TEST_ENV.items():
    os.environ[_key] = _value


# The environment must be complete before ``fastapi_full`` is imported, so
# every package import below this line, not above it.
import sqlite3  # noqa: E402
import uuid  # noqa: E402

import pytest  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

import fastapi_full.db_models  # noqa: E402,F401  (registers the tables)

# ``Category.owner_id`` is a raw ``CHAR(36)``: the real drivers adapt a
# ``uuid.UUID`` to its text form, the SQLite surrogate does not. Teaching the
# test driver the same adaptation keeps the model untouched (changing the column
# type would be a migration, not a test concern).
sqlite3.register_adapter(uuid.UUID, str)


@pytest.fixture
def db_session() -> Iterator[Session]:
    """A throwaway in-memory database session built from the package metadata.

    One fresh engine per test, so a purge — which is deliberately table-wide —
    can never reach another test's rows. ``StaticPool`` keeps every caller on
    the one connection that holds the in-memory database, including the thread
    ``TestClient`` runs the app in. SQLite is a unit-test surrogate only: the
    real dialects are certified by the compose examples' migrations.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()
