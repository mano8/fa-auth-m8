"""Initialise the database connection."""

from collections.abc import Generator
from typing import Annotated
from fastapi import Depends
from sqlmodel import Session, create_engine
from auth_user_service.core.config import settings
from auth_user_service.core.utc_session import pin_utc_session

# Every PostgreSQL session this engine opens runs in UTC (G23).
engine = pin_utc_session(create_engine(str(settings.SQLALCHEMY_DATABASE_URI)))


def get_db() -> Generator[Session, None, None]:
    """
    Provide a database session.

    Yields:
        Session:
            A SQLAlchemy session connected to the database.
    """
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_db)]
