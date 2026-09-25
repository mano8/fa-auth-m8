"""Timestamp columns carry their zone: ``timestamp`` -> ``timestamptz``

sqlmodel ``0.0.46`` (fa-auth-m8 ``2.2.3``) maps every ``datetime`` field to
``UTCDateTime`` - ``timestamp with time zone`` on PostgreSQL - while this chain
was generated under the previous, naive mapping. The columns below are exactly
what Alembic's own comparison reports against this chain's previous head.

Each ALTER reads the stored value explicitly as UTC
(``USING <column> AT TIME ZONE 'UTC'``), so the conversion is exact whatever
the server's or the session's ``TimeZone``; an implicit cast would use the
session zone and move every existing row by its offset. The downgrade converts
back the same way. ``B30-pre-publish-hardening``, finding ``G23``.

Revision ID: bbe56251ef5a
Revises: b1c4f7a92d38
Create Date: 2026-09-25 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "bbe56251ef5a"
down_revision: Union[str, None] = "b1c4f7a92d38"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

#: (table, column, nullable) for every naive timestamp column of this chain.
_COLUMNS = (
    ("app_category", "created_at", False),
    ("app_category", "updated_at", False),
    ("app_privileged_action_audit", "created_at", False),
)


def _using(column: str) -> str:
    return f"\"{column}\" AT TIME ZONE 'UTC'"


def upgrade() -> None:
    for table, column, nullable in _COLUMNS:
        op.alter_column(
            table,
            column,
            existing_type=postgresql.TIMESTAMP(),
            type_=sa.DateTime(timezone=True),
            existing_nullable=nullable,
            postgresql_using=_using(column),
        )


def downgrade() -> None:
    for table, column, nullable in reversed(_COLUMNS):
        op.alter_column(
            table,
            column,
            existing_type=sa.DateTime(timezone=True),
            type_=postgresql.TIMESTAMP(),
            existing_nullable=nullable,
            postgresql_using=_using(column),
        )
