"""Expand: app privileged_action_audit table (Phase 7 consumer audit trail)

Additive-only, chained onto the consumer example's existing m8_app head. Creates
the read-only, append-only ``app_privileged_action_audit`` table and installs
a ``BEFORE UPDATE OR DELETE`` guard trigger that makes the write-once/
no-targeted-delete contract schema-level rather than a code-discipline
convention alone:

- Any ``UPDATE`` is unconditionally rejected — no code path may ever modify a
  written row.
- Any ``DELETE`` is rejected unless the current transaction has set
  ``audit.purge_active`` to ``'true'`` via ``set_config(..., true)``
  (transaction-local, auto-resets at commit/rollback) — which only
  ``fastapi_full.app.audit.purge_expired_audit_rows`` (the horizon-bounded
  retention purge) ever does, so an ad-hoc/targeted single-row delete is
  rejected by the database itself, not merely absent from the application's API
  surface.

Safe to apply while the previous consumer version is still running: the new
table is unreferenced by old code and no existing table/column is touched.

Revision ID: b1c4f7a92d38
Revises: 019a32a3ca8c
Create Date: 2026-07-27 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b1c4f7a92d38'
down_revision: Union[str, None] = '019a32a3ca8c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_action_enum = sa.Enum('add', 'edit', 'delete', name='app_privileged_action')

_GUARD_FUNCTION_SQL = """
CREATE FUNCTION app_privileged_action_audit_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'app_privileged_action_audit rows are write-once and cannot be updated';
    ELSIF TG_OP = 'DELETE' THEN
        IF current_setting('audit.purge_active', true) IS DISTINCT FROM 'true' THEN
            RAISE EXCEPTION 'app_privileged_action_audit rows can only be removed by the horizon-bounded retention purge';
        END IF;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
"""

_GUARD_TRIGGER_SQL = """
CREATE TRIGGER trg_app_privileged_action_audit_guard
BEFORE UPDATE OR DELETE ON app_privileged_action_audit
FOR EACH ROW EXECUTE FUNCTION app_privileged_action_audit_guard();
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
    )
    op.create_index(
        op.f('ix_app_privileged_action_audit_actor_user_id'),
        'app_privileged_action_audit',
        ['actor_user_id'],
        unique=False,
    )
    op.execute(sa.text(_GUARD_FUNCTION_SQL))
    op.execute(sa.text(_GUARD_TRIGGER_SQL))


def downgrade() -> None:
    op.execute(sa.text('DROP TRIGGER IF EXISTS trg_app_privileged_action_audit_guard ON app_privileged_action_audit'))
    op.execute(sa.text('DROP FUNCTION IF EXISTS app_privileged_action_audit_guard()'))
    op.drop_index(
        op.f('ix_app_privileged_action_audit_actor_user_id'),
        table_name='app_privileged_action_audit',
    )
    op.drop_table('app_privileged_action_audit')
    _action_enum.drop(op.get_bind(), checkfirst=True)
