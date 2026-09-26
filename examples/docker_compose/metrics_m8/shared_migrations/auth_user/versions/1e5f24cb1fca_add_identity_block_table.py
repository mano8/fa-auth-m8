"""Add auth_identity_block: Google identities an administrator deleted (S1A)

Additive-only. An administrator's deletion of a GOOGLE account records one row
keyed by the SHA-256 of ``"<provider>:<subject>"`` (the raw Google subject is
never stored), so the same Google identity cannot provision a new account
until an audited unblock (``google_identity_unblock``). ``user_id`` names the
deleted account with no foreign key: the row it names is gone. Safe to apply
while the previous issuer version is still running; it never reads the table.

Downgrade drops the table, which lifts every block.

Revision ID: 1e5f24cb1fca
Revises: d93c98c350b7
Create Date: 2026-09-26 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1e5f24cb1fca'
down_revision: Union[str, None] = 'd93c98c350b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'auth_identity_block',
        sa.Column('identity_digest', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('identity_digest'),
    )
    op.create_index(op.f('ix_auth_identity_block_user_id'), 'auth_identity_block', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_auth_identity_block_user_id'), table_name='auth_identity_block')
    op.drop_table('auth_identity_block')
