"""Read-only privileged-action audit model (Phase 7 audit trail).

A :class:`PrivilegedActionAudit` row durably records a single privileged
mutation of *non-owned* data — a superadmin/admin ``add``, ``edit``, or
``delete`` of a row the actor does not own. It is an **append-only** forensic
record: exactly one row is written, in the same transaction as the audited
mutation (see the transaction-bound recorder), and the row is thereafter never
updated and never individually deleted. The only deletion path is the superadmin
retention purge — a horizon-bounded *bulk* removal — so no single (e.g.
self-incriminating) row can ever be surgically erased.

Design constraints (all normative, Phase 7; tombstone-consistent, 3.5.1):

- **No foreign key** to the actor or the target row: the audit must outlive the
  users/rows it describes, so it is never subject to ``ON DELETE CASCADE`` and
  survives a subsequent hard delete of the actor or the target owner.
- ``row_pk`` and ``target_owner_id`` are stored as **text** so one table records
  both integer PKs (e.g. category rows) and UUID PKs (e.g. user/session rows).
- ``table_name`` is the canonical **prefixed** table name of the mutated row.
- Every column is NULL-safe: the required columns are ``NOT NULL`` and only
  ``target_owner_id`` is nullable (a target row may legitimately have no owner).
- ``actor_role`` is stored as the role's **text** value (a snapshot of the
  actor's role at action time), deliberately *not* the shared native role enum,
  so this append-only table never couples to the user table's enum-type
  lifecycle.
- Write-once: this model exposes no update or targeted-delete path; the schema
  enforcement (no ``UPDATE``, no single-row ``DELETE``) lands with the Expand
  migration.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from sqlalchemy import Column, String, Uuid, text
from sqlalchemy import Enum as SAEnum
from sqlmodel import Field, SQLModel

from auth_sdk_m8.schemas.base import RoleType
from auth_user_service.core.db_utils import get_table_args, prefixed_tables


class AuditAction(str, Enum):
    """The three privileged mutation kinds recorded in the audit trail."""

    ADD = "add"
    EDIT = "edit"
    DELETE = "delete"


class PrivilegedActionAudit(SQLModel, table=True):
    """One durable, write-once record of a privileged mutation of non-owned data.

    Deliberately carries no relationship to :class:`User` or any target row: the
    record exists precisely so it can outlive the actor and the target it
    describes, so a foreign key (and its cascade) would defeat its purpose.
    """

    __tablename__ = prefixed_tables("privileged_action_audit")
    __table_args__ = (get_table_args(),)

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
        "the audit outlives the actor).",
    )
    actor_role: RoleType = Field(
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
        description="Primary key of the mutated row as text (int PKs and UUID PKs "
        "share this one column).",
    )
    target_owner_id: Optional[str] = Field(
        default=None,
        sa_column=Column("target_owner_id", String(128), nullable=True),
        description="Owner id of the mutated row as text; NULL when the target has "
        "no owner (no FK — the audit outlives the owner).",
    )


class PrivilegedActionAuditPublic(SQLModel):
    """Read-only response shape for one audit row (Phase 7 audit read route).

    Carries only the recorded ids and classification fields — no PII beyond
    the actor/target ids already stored on the row (secret non-exposure
    invariant: this surface never touches user profile/secret columns).
    """

    id: uuid.UUID
    created_at: datetime
    actor_user_id: uuid.UUID
    actor_role: RoleType
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
