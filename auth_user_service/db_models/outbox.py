"""Transactional revocation-outbox model (3.5.2 ``REV-OUTBOX-01``).

``events.emit()`` is best-effort/in-memory and the Redis blacklist write happens
after commit, so a crash or Redis/stream failure after a role-change commit would
otherwise strand revocation side effects and leave positive authorization cached.
The outbox closes that gap: the Redis blacklist writes and the user-wide
session-revoked publication are recorded as durable rows committed **atomically**
with the role change, then drained by a post-commit worker with at-least-once
delivery (:mod:`auth_user_service.services.outbox`).

**One data model (decided, 3.5.2):** separate effect rows, each with its own
``status``. A blacklist effect is *one row per captured ``(jti, expires_at)``
target* (the payload carries both, so no row ever aggregates multiple JTIs and
loses an individual expiry); the user-wide publication is a single row whose
``target_digest`` is a deterministic user-wide key. The unique constraint on
``(user_id, auth_generation, effect_type, target_digest)`` makes duplicate
enqueue and duplicate drain harmless, and each row's own ``status`` means a crash
after the blacklist write but before publication re-drains only the rows still
``pending``.
"""

import uuid
from datetime import datetime
from typing import Final, Optional

from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    DateTime,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlmodel import Field, SQLModel

from auth_sdk_m8.models.shared import TimestampMixin
from auth_user_service.core.db_utils import get_table_args, prefixed_tables

# Effect kinds — the two revocation side effects the worker applies (3.5.2).
EFFECT_BLACKLIST: Final[str] = "blacklist"
EFFECT_PUBLISH: Final[str] = "publish"

# Row lifecycle states. ``pending`` → claimable; ``leased`` → held by a worker
# until ``lease_until`` (abandoned-lease recovery re-claims a stale lease);
# ``completed`` → applied (retained briefly then reaped); ``dead`` → retries
# exhausted (dead-letter, operator replay).
STATUS_PENDING: Final[str] = "pending"
STATUS_LEASED: Final[str] = "leased"
STATUS_COMPLETED: Final[str] = "completed"
STATUS_DEAD: Final[str] = "dead"

#: Deterministic ``target_digest`` for the single user-wide publish effect of a
#: generation — exactly one publish row per ``(user_id, auth_generation)``.
USER_WIDE_TARGET: Final[str] = "user-wide"


class RevocationOutbox(TimestampMixin, SQLModel, table=True):
    """A durable revocation side effect awaiting at-least-once delivery (3.5.2).

    Committed in the same transaction as the authorization change that produced
    it; a post-commit worker claims it (``FOR UPDATE SKIP LOCKED`` + lease),
    applies the effect, and marks the row ``completed`` or, on exhausted retries,
    ``dead``. ``payload`` is self-contained so the worker never needs the
    (possibly since-mutated or deleted) source rows.
    """

    __tablename__ = prefixed_tables("revocation_outbox")
    __table_args__ = (
        # Duplicate enqueue / duplicate drain are harmless: the same effect
        # target within a generation collapses to one row (3.5.2).
        UniqueConstraint(
            "user_id",
            "auth_generation",
            "effect_type",
            "target_digest",
            name="uq_revocation_outbox_effect_target",
        ),
        get_table_args(),
    )

    id: uuid.UUID = Field(
        sa_column=Column(
            "id",
            Uuid(as_uuid=True),
            default=uuid.uuid4,
            primary_key=True,
        ),
        description="Outbox row identifier (UUID).",
    )
    user_id: uuid.UUID = Field(
        sa_column=Column(
            "user_id",
            Uuid(as_uuid=True),
            nullable=False,
            index=True,
        ),
        description="Subject whose authorization changed (no FK — the effect "
        "must survive a subsequent hard delete of the user).",
    )
    auth_generation: int = Field(
        sa_column=Column("auth_generation", BigInteger, nullable=False),
        description="Owner's authorization generation backing this revocation.",
    )
    effect_type: str = Field(
        sa_column=Column("effect_type", String(16), nullable=False),
        description="'blacklist' (one captured JTI) or 'publish' (user-wide event).",
    )
    target_digest: str = Field(
        sa_column=Column("target_digest", String(128), nullable=False),
        description="Opaque per-target key: a JTI digest for blacklist effects, "
        "the deterministic user-wide key for the publish effect. Never a JTI in "
        "clear (JTIs stay in the payload only, 3.5.2).",
    )
    payload: dict = Field(
        sa_column=Column("payload", JSON, nullable=False),
        description="Self-contained effect payload (blacklist: jti + expiry; "
        "publish: the durable v2 session-revoked event dict).",
    )
    status: str = Field(
        sa_column=Column(
            "status",
            String(16),
            nullable=False,
            default=STATUS_PENDING,
            server_default=text("'pending'"),
            index=True,
        ),
        description="pending | leased | completed | dead.",
    )
    attempts: int = Field(
        sa_column=Column(
            "attempts",
            Integer,
            nullable=False,
            default=0,
            server_default=text("0"),
        ),
        description="Delivery attempts so far; drives backoff and dead-lettering.",
    )
    lease_until: Optional[datetime] = Field(
        default=None,
        sa_column=Column("lease_until", DateTime, nullable=True),
        description="When a worker's lease on this row expires (abandoned-lease "
        "recovery re-claims a leased row past this instant).",
    )
    next_attempt_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column("next_attempt_at", DateTime, nullable=True),
        description="Earliest instant this row may be re-claimed after a "
        "retryable failure (backoff). NULL means immediately eligible.",
    )
    completed_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column("completed_at", DateTime, nullable=True),
        description="When the effect was successfully applied (retention clock).",
    )
