"""Blocked external identity model (``D-j``).

An administrator's deletion of a GOOGLE account is an operator decision to ban
that Google identity, so it records a block marker here; a user deleting their
own account records none and may come back. Deletion removes the ``User`` row
and the durable tombstone is keyed by the old ``user_id``, so without this
marker the next Google login would provision a fresh account for the same
Google ``sub`` (``N18``).

Design constraints:

- keyed by ``identity_digest``, the SHA-256 of ``"<provider>:<subject>"`` —
  the raw provider subject is never stored;
- ``user_id`` is the deleted account the block came from, with **no foreign
  key** (the row it names is gone). It is a non-secret handle the audited
  unblock command takes, since an operator never knows the subject itself;
- one row per identity: blocking an already blocked identity is a no-op.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Uuid, text
from sqlmodel import Field, SQLModel

from auth_user_service.core.db_utils import get_table_args, prefixed_tables


class IdentityBlock(SQLModel, table=True):
    """One blocked external identity, known only by its digest."""

    __tablename__ = prefixed_tables("identity_block")
    __table_args__ = (get_table_args(),)

    identity_digest: str = Field(
        sa_column=Column("identity_digest", String(64), primary_key=True),
        description="SHA-256 hex of '<provider>:<subject>' (never the raw subject).",
    )
    user_id: uuid.UUID = Field(
        sa_column=Column("user_id", Uuid(as_uuid=True), nullable=False, index=True),
        description="Id of the deleted account the block came from (no FK).",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column_kwargs={
            "nullable": False,
            "server_default": text("CURRENT_TIMESTAMP"),
        },
        description="When the identity was blocked.",
    )
