"""
dm_model's helpers
"""

from typing import Any

from sqlalchemy.engine import Connection
from sqlalchemy.ext.declarative import declared_attr
from sqlmodel import SQLModel

from auth_user_service.core.config import settings

#: "Mariadb" and "Mysql" share the mysql+pymysql driver family but are distinct
#: declared/verified server dialects (supported database contract, 4.6).
_MYSQL_FAMILY = ("Mysql", "Mariadb")


def get_table_args() -> dict[str, Any]:
    """Return engine-specific table args for the selected database."""
    if settings.SELECTED_DB in _MYSQL_FAMILY:
        return {
            "mysql_engine": settings.DB_ENGINE,
            "mysql_charset": settings.DB_CHARSET,
        }
    return {}


class DialectMismatchError(RuntimeError):
    """Raised when SELECTED_DB does not match the connected database server (4.6).

    Any mismatch — including MariaDB declared as Mysql, or the reverse — must
    fail startup cleanly rather than run half-configured.
    """


def detect_connected_dialect(connection: Connection) -> str:
    """Return which certified ``SELECTED_DB`` value *connection* actually is.

    MySQL and MariaDB report the same SQLAlchemy dialect name (``"mysql"``) on
    their shared wire protocol, so the server version string is what
    distinguishes them (4.6).
    """
    dialect_name = connection.dialect.name
    if dialect_name == "postgresql":
        return "Postgres"
    if dialect_name == "mysql":
        version_string = str(
            connection.exec_driver_sql("SELECT VERSION()").scalar() or ""
        )
        return "Mariadb" if "mariadb" in version_string.lower() else "Mysql"
    raise DialectMismatchError(
        f"Connected database reports unsupported SQLAlchemy dialect "
        f"{dialect_name!r}; only PostgreSQL and the MySQL/MariaDB family are "
        "certified (4.6)."
    )


def verify_selected_db_dialect(connection: Connection, selected_db: str) -> None:
    """Fail closed if *selected_db* does not match the connected server (4.6).

    Called at startup so a deployment declaring the wrong engine — including
    ``"Mysql"`` against a real MariaDB server, or the reverse — never runs
    half-configured.
    """
    detected = detect_connected_dialect(connection)
    if detected != selected_db:
        raise DialectMismatchError(
            f"SELECTED_DB={selected_db!r} but the connected database server is "
            f"{detected!r}. Update SELECTED_DB to match the deployed engine "
            "(4.6) — existing MariaDB deployments declaring SELECTED_DB=Mysql "
            "must migrate to SELECTED_DB=Mariadb."
        )


class PrefixedBase(SQLModel):
    """
    Automatiquelly prefix table names.
    """

    @declared_attr  # type: ignore[arg-type]
    @classmethod
    def __tablename__(cls) -> str:
        return f"{settings.TABLES_PREFIX}_{cls.__name__.lower()}"


def prefixed_fk(model: str, column: str) -> str:
    """
    Build a ForeignKey string like "prefix_model.column" dynamically,
    so it always matches model.__tablename__.
    """
    return f"{settings.TABLES_PREFIX}_{model}.{column}"


def prefixed_tables(name: str) -> str:
    """
    Build a ForeignKey string like "prefix_model.column" dynamically,
    so it always matches model.__tablename__.
    """
    return f"{settings.TABLES_PREFIX}_{name}"
