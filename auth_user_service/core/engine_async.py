"""Initialise the async database connection."""

from sqlalchemy.ext.asyncio import create_async_engine

from auth_user_service.core.config import settings


def _async_uri() -> str:
    uri = settings.SQLALCHEMY_DATABASE_URI
    if settings.SELECTED_DB == "Postgres":
        return uri.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
    # "Mysql" and "Mariadb" both build a mysql+pymysql URI (CommonSettings) and
    # fall through unchanged here — already identical for the whole mysql
    # family, so no per-value branch is needed (dialect-declaration contract, 4.6).
    return uri


async_engine = create_async_engine(_async_uri(), echo=True, future=True)
