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

Revision ID: d93c98c350b7
Revises: 26e421434bed
Create Date: 2026-09-25 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "d93c98c350b7"
down_revision: Union[str, None] = "26e421434bed"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

#: (table, column, nullable) for every naive timestamp column of this chain.
_COLUMNS = (
    ("auth_api_key", "created_at", False),
    ("auth_api_key", "expires_at", True),
    ("auth_api_key", "last_used_at", True),
    ("auth_api_key", "updated_at", False),
    ("auth_client_session", "created_at", False),
    ("auth_client_session", "external_token_expires_at", True),
    ("auth_client_session", "jwt_expires_at", False),
    ("auth_client_session", "refresh_expires_at", False),
    ("auth_client_session", "updated_at", False),
    ("auth_privileged_action_audit", "created_at", False),
    ("auth_revocation_outbox", "created_at", False),
    ("auth_revocation_outbox", "updated_at", False),
    ("auth_tombstone", "created_at", False),
    ("auth_tombstone", "updated_at", False),
    ("auth_user", "created_at", False),
    ("auth_user", "updated_at", False),
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
