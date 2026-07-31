"""Durable authorization tombstone model.

A tombstone durably records a *terminal* authorization generation for a user
that has been hard-deleted. Because deletion removes the ``User`` row (and
cascades its sessions/api-keys), the incremented generation cannot live on the
user; the tombstone survives instead so the introspection path can still treat
every token minted for that subject as revoked (3.5.1 ``REV-GEN-01``).

Design constraints (all normative, 3.5.1):

- keyed by ``user_id`` with **no foreign key** to ``User`` — it must outlive the
  row it describes, so it is never subject to ``ON DELETE CASCADE``;
- user ids are never reused (random UUID primary keys elsewhere), so a tombstone
  can never deny a legitimately new account;
- writes are an idempotent max-generation upsert (a replayed delete can only
  raise the terminal generation, never lower it) — see
  :class:`auth_user_service.services.generation.GenerationController`.
"""

import uuid

from sqlalchemy import BigInteger, Column, Uuid
from sqlmodel import Field, SQLModel

from auth_sdk_m8.models.shared import TimestampMixin
from auth_user_service.core.db_utils import get_table_args, prefixed_tables


class AuthTombstone(TimestampMixin, SQLModel, table=True):
    """Terminal authorization generation for a deleted subject.

    Deliberately carries no relationship to :class:`User`: the row exists
    precisely because the user row is gone, so a foreign key would defeat its
    purpose.
    """

    __tablename__ = prefixed_tables("tombstone")
    __table_args__ = (get_table_args(),)

    user_id: uuid.UUID = Field(
        sa_column=Column(
            "user_id",
            Uuid(as_uuid=True),
            primary_key=True,
            index=True,
        ),
        description="Deleted user's id (no FK — the tombstone outlives the user).",
    )
    terminal_generation: int = Field(
        sa_column=Column(
            "terminal_generation",
            BigInteger,
            nullable=False,
        ),
        description=(
            "Terminal authorization generation; any session stamped below this "
            "is revoked. Idempotent max upsert — never lowered."
        ),
    )
