"""Read-only privileged-action audit model for the consumer example (Phase 7).

Mirrors the issuer's ``auth_privileged_action_audit`` contract for the data this
example owns: a :class:`PrivilegedActionAudit` row durably records a single
superadmin mutation of a **non-owned** category — an ``add``, ``edit``, or
``delete`` of a row the actor does not own. It is an **append-only** forensic
record: exactly one row is written, in the same transaction as the audited
mutation (see ``app.audit.record_privileged_action``), and the row is thereafter
never updated and never individually deleted. The only deletion path is the
superadmin retention purge — a horizon-bounded *bulk* removal — so no single
(e.g. self-incriminating) row can ever be surgically erased.

Design constraints (all normative, Phase 7, and identical to the issuer's):

- **No foreign key** to the actor or the target row: the audit must outlive the
  users/rows it describes, so it is never subject to ``ON DELETE CASCADE`` and
  survives a later hard delete of the actor or the target owner. The actor is a
  user of the *auth service*, which this consumer never joins against anyway
  (``ARCH-NO-CROSS-SERVICE-DATA``).
- ``row_pk`` and ``target_owner_id`` are stored as **text** so one table records
  both this example's integer category PKs and the issuer's UUID owner ids.
- ``table_name`` is the canonical **prefixed** table name of the mutated row.
- Every column is NULL-safe: the required columns are ``NOT NULL`` and only
  ``target_owner_id`` is nullable (a target row may legitimately have no owner).
- ``actor_role`` is stored as the role's **text** value — a snapshot of the
  actor's role at action time, taken from the authenticated principal — never a
  native enum, so this append-only table couples to no role-enum lifecycle.
- Write-once: this model exposes no update and no targeted-delete path, and the
  Expand migration installs the matching database triggers, so the contract is
  schema-level rather than a code-discipline convention alone.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from sqlalchemy import Column, String, Uuid, text
from sqlalchemy import Enum as SAEnum
from sqlmodel import Field, SQLModel

from fastapi_full.core.config import settings
from fastapi_full.core.db_models import prefixed_tables


class AuditAction(str, Enum):
    """The three privileged mutation kinds recorded in the audit trail."""

    ADD = "add"
    EDIT = "edit"
    DELETE = "delete"


class PrivilegedActionAudit(SQLModel, table=True):
    """One durable, write-once record of a privileged mutation of non-owned data.

    Deliberately carries no relationship to the mutated row: the record exists
    precisely so it can outlive the actor and the target it describes, so a
    foreign key (and its cascade) would defeat its purpose.
    """

    __tablename__ = prefixed_tables("privileged_action_audit")
    __table_args__ = (
        {"mysql_engine": settings.DB_ENGINE, "mysql_charset": settings.DB_CHARSET},
    )

    id: uuid.UUID = Field(
        sa_column=Column(
            "id",
            Uuid(as_uuid=True),
            default=uuid.uuid4,
            primary_key=True,
        ),
        description="Audit row identifier (UUID).",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column_kwargs={
            "nullable": False,
            "server_default": text("CURRENT_TIMESTAMP"),
        },
        description="When the audited action was recorded (write-once).",
    )
    actor_user_id: uuid.UUID = Field(
        sa_column=Column(
            "actor_user_id",
            Uuid(as_uuid=True),
            nullable=False,
            index=True,
        ),
        description="Id of the privileged actor who performed the action (no FK — "
        "the audit outlives the actor, who lives in the auth service anyway).",
    )
    actor_role: str = Field(
        sa_column=Column("actor_role", String(32), nullable=False),
        description="Snapshot of the actor's role at action time, taken from the "
        "authenticated principal, never from client input.",
    )
    action: AuditAction = Field(
        sa_column=Column(
            "action",
            SAEnum(
                AuditAction,
                name=prefixed_tables("privileged_action"),
                values_callable=lambda enum: [member.value for member in enum],
            ),
            nullable=False,
        ),
        description="Privileged mutation kind: 'add', 'edit', or 'delete'.",
    )
    table_name: str = Field(
        sa_column=Column("table_name", String(128), nullable=False),
        description="Canonical prefixed table name of the mutated row.",
    )
    row_pk: str = Field(
        sa_column=Column("row_pk", String(128), nullable=False),
        description="Primary key of the mutated row as text (this example's int "
        "category PKs and the issuer's UUID ids share this one column).",
    )
    target_owner_id: Optional[str] = Field(
        default=None,
        sa_column=Column("target_owner_id", String(128), nullable=True),
        description="Owner id of the mutated row as text; NULL when the target has "
        "no owner (no FK — the audit outlives the owner).",
    )


class PrivilegedActionAuditPublic(SQLModel):
    """Read-only response shape for one audit row (Phase 7 audit read route).

    Carries only the recorded ids and classification fields — no PII beyond the
    actor/target ids already stored on the row, and nothing this consumer would
    have to fetch from the auth service to render.
    """

    id: uuid.UUID
    created_at: datetime
    actor_user_id: uuid.UUID
    actor_role: str
    action: AuditAction
    table_name: str
    row_pk: str
    target_owner_id: Optional[str] = None


class PrivilegedActionAuditsPublic(SQLModel):
    """Wrapper for a paginated privileged-action-audit listing."""

    data: List[PrivilegedActionAuditPublic] = Field(
        description="List of public privileged-action-audit rows",
    )
    count: int = Field(
        description="Total number of audit rows visible to the caller",
    )
