"""Expand: app privileged_action_audit table (Phase 7 consumer audit trail)

Additive-only, chained onto the consumer example's existing m8_app head. Creates
the read-only, append-only ``app_privileged_action_audit`` table and installs
``BEFORE UPDATE``/``BEFORE DELETE`` guard triggers that make the write-once/
no-targeted-delete contract schema-level rather than a code-discipline
convention alone:

- Any ``UPDATE`` is unconditionally rejected — no code path may ever modify a
  written row.
- Any ``DELETE`` is rejected unless the current session variable
  ``@audit_purge_active`` is set to ``1`` (set before, and cleared after, each
  batch of deletes, since MySQL/MariaDB session variables persist on the pooled
  connection past the transaction boundary) — which only
  ``fastapi_full.app.audit.purge_expired_audit_rows`` (the horizon-bounded
  retention purge) ever does, so an ad-hoc/targeted single-row delete is
  rejected by the database itself, not merely absent from the application's API
  surface.

Safe to apply while the previous consumer version is still running: the new
table is unreferenced by old code and no existing table/column is touched.

Revision ID: d47a2e8c1b95
Revises: 24a7de285ea5
Create Date: 2026-07-27 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd47a2e8c1b95'
down_revision: Union[str, None] = '24a7de285ea5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_action_enum = sa.Enum('add', 'edit', 'delete', name='app_privileged_action')

_NO_UPDATE_TRIGGER_SQL = """
CREATE TRIGGER trg_app_privileged_action_audit_no_update
BEFORE UPDATE ON app_privileged_action_audit
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'app_privileged_action_audit rows are write-once and cannot be updated';
END;
"""

_NO_TARGETED_DELETE_TRIGGER_SQL = """
CREATE TRIGGER trg_app_privileged_action_audit_no_delete
BEFORE DELETE ON app_privileged_action_audit
FOR EACH ROW
BEGIN
    IF @audit_purge_active IS NULL OR @audit_purge_active <> 1 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'app_privileged_action_audit rows can only be removed by the horizon-bounded retention purge';
    END IF;
END;
"""


def upgrade() -> None:
    op.create_table(
        'app_privileged_action_audit',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('actor_user_id', sa.Uuid(), nullable=False),
        sa.Column('actor_role', sa.String(length=32), nullable=False),
        sa.Column('action', _action_enum, nullable=False),
        sa.Column('table_name', sa.String(length=128), nullable=False),
        sa.Column('row_pk', sa.String(length=128), nullable=False),
        sa.Column('target_owner_id', sa.String(length=128), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        mysql_charset='utf8mb4',
        mysql_engine='InnoDB',
    )
    op.create_index(
        op.f('ix_app_privileged_action_audit_actor_user_id'),
        'app_privileged_action_audit',
        ['actor_user_id'],
        unique=False,
    )
    op.execute(sa.text(_NO_UPDATE_TRIGGER_SQL))
    op.execute(sa.text(_NO_TARGETED_DELETE_TRIGGER_SQL))


def downgrade() -> None:
    op.execute(sa.text('DROP TRIGGER IF EXISTS trg_app_privileged_action_audit_no_delete'))
    op.execute(sa.text('DROP TRIGGER IF EXISTS trg_app_privileged_action_audit_no_update'))
    op.drop_index(
        op.f('ix_app_privileged_action_audit_actor_user_id'),
        table_name='app_privileged_action_audit',
    )
    op.drop_table('app_privileged_action_audit')
    _action_enum.drop(op.get_bind(), checkfirst=True)
