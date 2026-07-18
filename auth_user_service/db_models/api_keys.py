"""
Api key and rate limit models for the database.
These models are used to manage API keys and their associated rate limits.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlmodel import Column, Field, ForeignKey, Relationship, SQLModel

from auth_sdk_m8.schemas.base import ApiKeyAccessMode, Period
from auth_sdk_m8.models.shared import TimestampMixin
from auth_user_service.core.db_utils import (
    get_table_args,
    prefixed_fk,
    prefixed_tables,
)

if TYPE_CHECKING:
    from auth_user_service.db_models.users import User


# ---------------------------------------------------------------
# ---------------------- API KEY MODELS ------------------------
# ---------------------------------------------------------------
class ApiKeyBase(TimestampMixin, SQLModel):
    """Shared fields for API key schemas."""

    name: str = Field(
        default=None,
        min_length=3,
        max_length=100,
        description="Developer-defined key name",
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        sa_column_kwargs={"nullable": True},
        description="When the key expires (UTC)",
    )
    revoked: bool = Field(
        default=False,
        description="Whether the key is revoked",
    )


class ApiKeyCreate(SQLModel):
    """Schema for creating a new API key.

    ``access_mode`` and ``audiences`` are the two additive, explicit-only fields
    of §3.12 — both fixed at issuance. Omitting them yields the security-first
    default: a ``READ_ONLY`` key bound to no audience (issuer-local use only).
    """

    name: Optional[str] = Field(
        default=None,
        min_length=3,
        max_length=100,
        description="Developer-friendly key name",
    )
    ttl_hours: int = Field(
        default=24,
        gt=0,
        description="Time to live for the key in hours",
    )
    access_mode: ApiKeyAccessMode = Field(
        default=ApiKeyAccessMode.READ_ONLY,
        description="Immutable operation-category cap for the new key "
        "(``APIKEY-MODE-01``). Defaults to the most restrictive ``READ_ONLY``; "
        "``READ_WRITE`` is an explicit choice and cannot be changed afterwards — "
        "issue a replacement key instead.",
    )
    audiences: Optional[list[str]] = Field(
        default=None,
        description="Registered consumer ids permitted to introspect this key "
        "remotely (``APIKEY-AUD-01``, §3.12). Omitted/empty ⇒ issuer-local use "
        "only (remote introspection answers ``active: false``). Each must be an "
        "enabled consumer explicitly granted the ``api-key-introspection`` scope. "
        "The set is immutable after issuance.",
    )


class ApiKey(ApiKeyBase, SQLModel, table=True):
    """Database model for storing API keys."""

    __tablename__ = prefixed_tables("api_key")
    __table_args__ = (get_table_args(),)

    id: uuid.UUID = Field(
        sa_column=Column(
            "id",
            Uuid(as_uuid=True),
            default=uuid.uuid4,
            primary_key=True,
            index=True,
        ),
        description="Unique API key ID",
    )
    key_hash: str = Field(
        sa_column_kwargs={"unique": True, "nullable": False},
        min_length=64,
        max_length=128,
        description="Secure hash of the API key",
    )
    user_id: uuid.UUID = Field(
        sa_column=Column(
            "user_id",
            Uuid(as_uuid=True),
            ForeignKey(prefixed_fk("user", "id"), ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        description="Owner user ID",
    )
    last_used_at: Optional[datetime] = Field(
        default=None,
        description="Last time the key was used (UTC)",
    )
    access_mode: ApiKeyAccessMode = Field(
        default=ApiKeyAccessMode.READ_ONLY,
        sa_column_kwargs={
            "nullable": False,
            # Every existing key migrates to the most restrictive mode in Expand
            # (server default), and READ_ONLY is the creation-time default. The
            # enum persists its member name (READ_ONLY), matching the RoleType
            # column convention. The mode is immutable after issuance
            # (APIKEY-MODE-01) — there is deliberately no update path.
            "server_default": ApiKeyAccessMode.READ_ONLY.name,
        },
        description="Immutable operation-category cap chosen at issuance "
        "(APIKEY-MODE-01); never a role — the owner's live role stays the ceiling.",
    )

    user: "User" = Relationship(back_populates="api_keys")
    rate_limits: List["RateLimit"] = Relationship(
        back_populates="api_key",
        cascade_delete=True,
    )
    # Normalized audience bindings (APIKEY-AUD-01, §3.12). No rows ⇒ the key is
    # issuer-local only, so remote introspection answers active:false — the
    # fail-closed cutover that stops any legacy key silently becoming a
    # cross-service credential.
    audiences: List["ApiKeyAudience"] = Relationship(
        back_populates="api_key",
        cascade_delete=True,
    )


class ApiKeyPublic(ApiKeyBase, SQLModel):
    """Public representation of an API key (no key hash)."""

    id: uuid.UUID = Field(description="Unique API key ID")
    last_used_at: Optional[datetime] = Field(
        default=None,
        description="Last time the key was used (UTC)",
    )
    access_mode: ApiKeyAccessMode = Field(
        default=ApiKeyAccessMode.READ_ONLY,
        description="The key's immutable operation-category cap (APIKEY-MODE-01).",
    )


class ApiKeyAudience(SQLModel, table=True):
    """One audience binding of an API key (normalized ``api_key_audiences``).

    An audience is the immutable technical id of a registered consumer explicitly
    permitted to introspect user API keys (``APIKEY-AUD-01``, §3.12). The set is
    stored as its own relation — not a PostgreSQL-native array, JSON blob, or a
    nullable plural column — because the supported engines include MySQL/MariaDB
    (§4.6) and authorization data needs an exact physical contract. The complete
    set is immutable after issuance; adding/replacing it requires key rotation.
    """

    __tablename__ = prefixed_tables("api_key_audiences")
    __table_args__ = (get_table_args(),)

    api_key_id: uuid.UUID = Field(
        sa_column=Column(
            "api_key_id",
            Uuid(as_uuid=True),
            ForeignKey(prefixed_fk("api_key", "id"), ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        description="Owning API key (composite PK; cascades on key delete).",
    )
    audience_id: str = Field(
        sa_column=Column(
            "audience_id",
            sa.String(255),
            primary_key=True,
            nullable=False,
        ),
        description="Immutable technical id of a registered consumer permitted to "
        "introspect this key. Exact-match after canonical normalization; no "
        "wildcards; display names are never used for authorization.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column("created_at", sa.DateTime, nullable=False),
        description="When the binding was recorded (UTC).",
    )

    api_key: "ApiKey" = Relationship(back_populates="audiences")


# ---------------------------------------------------------------
# ---------------------- RATE LIMIT MODELS ---------------------
# ---------------------------------------------------------------
class RateLimit(SQLModel, table=True):
    """
    Rate limit configuration.

    Enforcement priority: api_key_id row > user_id row > settings defaults.
    Invariant: at least one of api_key_id or user_id must be set (DB CHECK).
    """

    __tablename__ = prefixed_tables("rate_limit")
    __table_args__ = (
        sa.CheckConstraint(
            "api_key_id IS NOT NULL OR user_id IS NOT NULL",
            name="ck_ratelimit_has_owner",
        ),
        sa.UniqueConstraint("api_key_id", "period", name="uq_ratelimit_api_key_period"),
        sa.UniqueConstraint("user_id", "period", name="uq_ratelimit_user_period"),
        get_table_args(),
    )

    id: Optional[int] = Field(
        default=None,
        primary_key=True,
        description="Rate limit record ID",
    )
    api_key_id: Optional[uuid.UUID] = Field(
        default=None,
        sa_column=Column(
            "api_key_id",
            Uuid(as_uuid=True),
            ForeignKey(prefixed_fk("api_key", "id"), ondelete="CASCADE"),
            nullable=True,
            index=True,
        ),
        description="API key this limit applies to (primary enforcement axis)",
    )
    user_id: Optional[uuid.UUID] = Field(
        default=None,
        sa_column=Column(
            "user_id",
            Uuid(as_uuid=True),
            ForeignKey(prefixed_fk("user", "id"), ondelete="CASCADE"),
            nullable=True,
            index=True,
        ),
        description="User default limit (fallback when no per-key override exists)",
    )
    period: Period = Field(
        sa_column_kwargs={"nullable": False},
        description="Rate limit interval",
    )
    limit: int = Field(
        nullable=False,
        gt=0,
        description="Maximum requests allowed in the interval",
    )

    api_key: Optional["ApiKey"] = Relationship(back_populates="rate_limits")
    user: Optional["User"] = Relationship(back_populates="rate_limits")
