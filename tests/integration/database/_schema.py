"""Schema reset and inspection helpers for the Layer B matrix (``TEST-DB-01``).

The migration tests need a genuinely empty database — ``alembic upgrade head``
from empty, and from every supported prior revision, is only meaningful if no
object survives from the previous test. Dropping tables alone is not enough:
PostgreSQL keeps the native enum types the migrations create, and MySQL/MariaDB
keep the audit-guard triggers if their table drop is ordered badly. Both are
handled here so a reset always yields the same empty state a fresh production
database would present.
"""

from __future__ import annotations

import sqlalchemy as sa


def reset_database(engine: sa.Engine) -> None:
    """Drop every object in the target schema, leaving it genuinely empty."""
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            # Drops tables, sequences, native enum types, and triggers in one
            # statement — the only reliable way to clear PostgreSQL's type
            # namespace, which a table drop leaves behind.
            conn.execute(sa.text("DROP SCHEMA public CASCADE"))
            conn.execute(sa.text("CREATE SCHEMA public"))
        return

    with engine.begin() as conn:
        conn.execute(sa.text("SET FOREIGN_KEY_CHECKS = 0"))
        try:
            tables = [
                row[0]
                for row in conn.execute(
                    sa.text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'"
                    )
                )
            ]
            for table in tables:
                # Identifiers come from information_schema for the database we
                # are connected to; they cannot carry caller input.
                conn.execute(sa.text(f"DROP TABLE IF EXISTS `{table}`"))  # nosec B608
        finally:
            conn.execute(sa.text("SET FOREIGN_KEY_CHECKS = 1"))


def table_names(engine: sa.Engine) -> set[str]:
    """Reflected base-table names currently present in the target schema."""
    return set(sa.inspect(engine).get_table_names())


def column_names(engine: sa.Engine, table: str) -> set[str]:
    """Reflected column names of *table*."""
    return {c["name"] for c in sa.inspect(engine).get_columns(table)}


def has_check_constraint(engine: sa.Engine, table: str, name: str) -> bool:
    """Whether *table* carries a named CHECK constraint.

    MySQL/MariaDB and PostgreSQL all report named CHECK constraints through
    the SQLAlchemy inspector, so this needs no per-dialect branch.
    """
    return any(
        c["name"] == name for c in sa.inspect(engine).get_check_constraints(table)
    )
