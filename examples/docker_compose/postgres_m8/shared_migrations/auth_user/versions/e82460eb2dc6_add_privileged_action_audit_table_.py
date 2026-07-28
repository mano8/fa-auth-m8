"""Expand: privileged_action_audit table (Phase 7 audit trail)

Additive-only, chained onto the issuer's existing 2.0.0 head. Creates the
read-only, append-only ``auth_privileged_action_audit`` table and installs a
``BEFORE UPDATE OR DELETE`` guard trigger that makes the write-once/
no-targeted-delete contract schema-level rather than a code-discipline
convention alone:

- Any ``UPDATE`` is unconditionally rejected — no code path may ever modify a
  written row.
- Any ``DELETE`` is rejected unless the current transaction has set
  ``audit.purge_active`` to ``'true'`` via ``set_config(..., true)``
  (transaction-local, auto-resets at commit/rollback) — which only
  ``purge_expired_audit_rows`` (the horizon-bounded retention purge) ever
  does, so an ad-hoc/targeted single-row delete is rejected by the database
  itself, not merely absent from the application's API surface.

Safe to apply while the previous issuer version is still running: the new
table is unreferenced by old code and no existing table/column is touched.

Revision ID: e82460eb2dc6
Revises: c386b90a1455
Create Date: 2026-07-27 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e82460eb2dc6'
down_revision: Union[str, None] = 'c386b90a1455'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_action_enum = sa.Enum('add', 'edit', 'delete', name='auth_privileged_action')

_GUARD_FUNCTION_SQL = """
CREATE FUNCTION auth_privileged_action_audit_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'auth_privileged_action_audit rows are write-once and cannot be updated';
    ELSIF TG_OP = 'DELETE' THEN
        IF current_setting('audit.purge_active', true) IS DISTINCT FROM 'true' THEN
            RAISE EXCEPTION 'auth_privileged_action_audit rows can only be removed by the horizon-bounded retention purge';
        END IF;
    END IF;
    -- A BEFORE ... FOR EACH ROW trigger that returns NULL *silently suppresses*
    -- the row operation. The UPDATE branch above always raises, so reaching
    -- here means an authorized DELETE, which must return OLD so the horizon
    -- purge's delete actually happens instead of being discarded.
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
"""

_GUARD_TRIGGER_SQL = """
CREATE TRIGGER trg_auth_privileged_action_audit_guard
BEFORE UPDATE OR DELETE ON auth_privileged_action_audit
FOR EACH ROW EXECUTE FUNCTION auth_privileged_action_audit_guard();
"""


def upgrade() -> None:
    op.create_table(
        'auth_privileged_action_audit',
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
        op.f('ix_auth_privileged_action_audit_actor_user_id'),
        'auth_privileged_action_audit',
        ['actor_user_id'],
        unique=False,
    )
    op.execute(sa.text(_GUARD_FUNCTION_SQL))
    op.execute(sa.text(_GUARD_TRIGGER_SQL))


def downgrade() -> None:
    op.execute(sa.text('DROP TRIGGER IF EXISTS trg_auth_privileged_action_audit_guard ON auth_privileged_action_audit'))
    op.execute(sa.text('DROP FUNCTION IF EXISTS auth_privileged_action_audit_guard()'))
    op.drop_index(
        op.f('ix_auth_privileged_action_audit_actor_user_id'),
        table_name='auth_privileged_action_audit',
    )
    op.drop_table('auth_privileged_action_audit')
    _action_enum.drop(op.get_bind(), checkfirst=True)
