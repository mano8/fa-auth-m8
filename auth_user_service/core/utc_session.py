"""Pin every PostgreSQL session this service opens to UTC.

sqlmodel ``0.0.46`` maps a plain ``datetime`` field to ``UTCDateTime``, which
binds an *aware* UTC value. Databases created under the previous mapping hold
``timestamp without time zone`` columns, and PostgreSQL casts an aware value
into such a column **in the session ``TimeZone``** — so on a server whose zone
is not UTC every new timestamp would be stored shifted by the offset, while
rows written before the upgrade were not (workspace finding ``G23``).

With the session pinned to UTC that cast is a no-op on every server, and the
one-time ``timestamp`` → ``timestamptz`` ALTER a later autogenerate emits reads
existing rows as the UTC they are. Other dialects bind the UTC wall clock
unchanged, so they are left alone. Applied to the service engine in
``core/engine_sync.py`` and to Alembic's engine in ``alembic/env.py``.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import Engine

UTC_SESSION_SQL = "SET TIME ZONE 'UTC'"


def set_session_utc(dbapi_connection: Any, _connection_record: Any) -> None:
    """Set a new DBAPI connection's session zone to UTC, outside any transaction."""
    autocommit = dbapi_connection.autocommit
    dbapi_connection.autocommit = True
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(UTC_SESSION_SQL)
    finally:
        cursor.close()
        dbapi_connection.autocommit = autocommit


def pin_utc_session(engine: Engine) -> Engine:
    """Register :func:`set_session_utc` on *engine* when it speaks PostgreSQL."""
    if engine.dialect.name == "postgresql" and not event.contains(
        engine, "connect", set_session_utc
    ):
        event.listen(engine, "connect", set_session_utc, insert=True)
    return engine
