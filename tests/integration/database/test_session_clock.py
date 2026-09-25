"""Layer B: an API key expires when it says it does, whatever the server clock.

Workspace finding ``G23`` (``B30-pre-publish-hardening`` leg 1). sqlmodel
``0.0.46`` binds every ``datetime`` field as an *aware* UTC value, and every
deployed PostgreSQL database holds ``timestamp without time zone`` columns from
the previous mapping. PostgreSQL casts that value into such a column **in the
session** ``TimeZone``: on a server running ``Europe/Madrid`` a key issued to
expire at ``E`` was stored as ``E`` + the offset, and because
``ApiKeyService.get_active_key`` compares ``expires_at`` in Python it went on
validating for that long after its expiry.

The service now pins every PostgreSQL session to UTC (``core/utc_session.py``),
and the tracked PostgreSQL chains gain a ``timestamptz`` revision. This module
proves both on a real engine:

* at **head** on every certified dialect, and
* on PostgreSQL, also at the revision **before** ``timestamptz`` — the naive
  columns every existing deployment has until it migrates, where only the pin
  keeps the clock right — and across that revision, which must convert an
  existing row exactly.

The matrix's ``postgresql-europe-madrid`` leg runs it against a server
initialised in ``Europe/Madrid`` and sets ``FA_AUTH_IT_EXPECT_SERVER_TZ`` so the
leg cannot pass on a UTC server by accident.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterator

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlmodel import Session

from auth_user_service.core.security import SecurityHelper
from auth_user_service.db_models.api_keys import ApiKey
from auth_user_service.services.api_keys import ApiKeyService
from tests.integration.database._engines import Endpoint, EngineSpec
from tests.integration.database._factories import make_user
from tests.integration.database.conftest import VERSION_TABLE

pytestmark = pytest.mark.database_integration

_TIMESTAMPTZ_SLUG = "timestamptz_columns"


def _as_utc(value: datetime) -> datetime:
    """Normalise a read-back value: naive columns hold UTC wall clock."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _pre_timestamptz_revision(config: Config) -> str | None:
    """The revision the chain's ``timestamptz`` revision revises, if it has one."""
    for script in ScriptDirectory.from_config(config).walk_revisions():
        if script.path.endswith(f"_{_TIMESTAMPTZ_SLUG}.py"):
            down = script.down_revision
            assert isinstance(down, str)
            return down
    return None


@pytest.fixture(scope="module", autouse=True)
def restore_head(it_engine: sa.Engine, alembic_config: Config) -> Iterator[None]:
    """Leave the target at ``head`` however this module ends."""
    yield
    command.upgrade(alembic_config, "head")


@pytest.fixture(params=["head", "before_timestamptz"])
def schema_at(
    request: pytest.FixtureRequest,
    clean_database: sa.Engine,
    alembic_config: Config,
) -> Iterator[sa.Engine]:
    """The clean target at ``head``, or at the naive revision before timestamptz."""
    if request.param == "before_timestamptz":
        target = _pre_timestamptz_revision(alembic_config)
        if target is None:
            pytest.skip("this dialect's chain has no timestamptz revision")
        command.downgrade(alembic_config, target)
    try:
        yield clean_database
    finally:
        command.upgrade(alembic_config, "head")


def _issue(session: Session, expires_at: datetime) -> str:
    """Persist an API key with a known plaintext and return that plaintext."""
    plaintext = f"layerb-clock-{uuid.uuid4().hex}"
    user = make_user(session)
    session.add(
        ApiKey(
            id=uuid.uuid4(),
            name=f"clock-{uuid.uuid4().hex[:8]}",
            key_hash=SecurityHelper.hash_token(plaintext),
            user_id=user.id,
            expires_at=expires_at,
        )
    )
    session.commit()
    return plaintext


def test_the_leg_runs_on_the_server_clock_it_claims(
    engine_spec: EngineSpec, db_endpoint: Endpoint
) -> None:
    """On the non-UTC leg, the server's own default really is not UTC."""
    expected = os.environ.get("FA_AUTH_IT_EXPECT_SERVER_TZ")
    if not expected:
        pytest.skip("no server zone is asserted for this leg")
    assert engine_spec.dialect == "postgresql"
    unpinned = sa.create_engine(db_endpoint.uri(engine_spec))
    try:
        with unpinned.connect() as conn:
            assert conn.execute(sa.text("SHOW TIME ZONE")).scalar_one() == expected
    finally:
        unpinned.dispose()


def test_an_api_key_expires_exactly_when_issued_to(schema_at: sa.Engine) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    expired_at = now - timedelta(seconds=1)
    live_until = now + timedelta(minutes=5)

    with Session(schema_at) as session:
        expired = _issue(session, expired_at)
        live = _issue(session, live_until)

    with Session(schema_at) as session:
        stored = sorted(
            _as_utc(key.expires_at)
            for key in session.query(ApiKey).all()
            if key.expires_at is not None
        )
        assert stored == [expired_at, live_until]
        # Refused one second after its expiry, not an offset later ...
        assert ApiKeyService.get_active_key(session, expired) is None
        # ... and not refused early either.
        assert ApiKeyService.get_active_key(session, live) is not None


def test_the_timestamptz_revision_converts_existing_rows_exactly(
    clean_database: sa.Engine, alembic_config: Config, engine_spec: EngineSpec
) -> None:
    """A row written before the revision reads back as the same instant after it."""
    target = _pre_timestamptz_revision(alembic_config)
    if target is None:
        pytest.skip("this dialect's chain has no timestamptz revision")
    command.downgrade(alembic_config, target)
    try:
        issued_at = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
        with Session(clean_database) as session:
            _issue(session, issued_at)
        command.upgrade(alembic_config, "head")
        with clean_database.connect() as conn:
            applied = conn.execute(
                sa.text(f"SELECT version_num FROM {VERSION_TABLE}")  # nosec B608
            ).scalar_one()
            column_type = conn.execute(
                sa.text(
                    "SELECT data_type FROM information_schema.columns "
                    "WHERE table_name = 'auth_api_key' AND column_name = 'expires_at'"
                )
            ).scalar_one()
        assert applied == ScriptDirectory.from_config(alembic_config).get_current_head()
        assert column_type == "timestamp with time zone"
        with Session(clean_database) as session:
            (key,) = session.query(ApiKey).all()
            assert key.expires_at is not None
            assert _as_utc(key.expires_at) == issued_at
    finally:
        command.upgrade(alembic_config, "head")
