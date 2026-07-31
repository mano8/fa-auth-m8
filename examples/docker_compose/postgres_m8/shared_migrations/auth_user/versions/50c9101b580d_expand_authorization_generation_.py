"""Expand: authorization generation, revocation outbox, tombstone, security
policy lock, and API-key access mode/audiences (4.1 step 3)

Additive-only. No equivalence CHECK and no final ``NOT NULL`` on
``auth_client_session.auth_generation`` here — those land in Enforce, after the
preflight/repair CLI and the global legacy-session revocation have run against
this schema (4.1 steps 4-6). Safe to apply while the previous issuer version is
still running: every new column is nullable or carries a server default that
backfills existing rows in place, and every new table is unreferenced by old
code.

Revision ID: 50c9101b580d
Revises: 8b85fd49afb9
Create Date: 2026-07-21 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '50c9101b580d'
down_revision: Union[str, None] = '8b85fd49afb9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Enum type backing ``auth_api_key.access_mode`` (APIKEY-MODE-01). Declared
# once so upgrade/downgrade reference the identical type object.
_access_mode_enum = sa.Enum('READ_ONLY', 'READ_WRITE', name='apikeyaccessmode')


def upgrade() -> None:
    op.create_table(
        'auth_security_policy',
        sa.Column('policy_key', sa.String(length=64), nullable=False),
        sa.Column('revision', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('policy_key'),
    )
    op.create_table(
        'auth_tombstone',
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('terminal_generation', sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint('user_id'),
    )
    op.create_index(op.f('ix_auth_tombstone_user_id'), 'auth_tombstone', ['user_id'], unique=False)
    op.create_table(
        'auth_revocation_outbox',
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('auth_generation', sa.BigInteger(), nullable=False),
        sa.Column('effect_type', sa.String(length=16), nullable=False),
        sa.Column('target_digest', sa.String(length=128), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=16), server_default=sa.text("'pending'"), nullable=False),
        sa.Column('attempts', sa.Integer(), server_default=sa.text('0'), nullable=False),
        sa.Column('lease_until', sa.DateTime(), nullable=True),
        sa.Column('next_attempt_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'user_id', 'auth_generation', 'effect_type', 'target_digest',
            name='uq_revocation_outbox_effect_target',
        ),
    )
    op.create_index(op.f('ix_auth_revocation_outbox_status'), 'auth_revocation_outbox', ['status'], unique=False)
    op.create_index(op.f('ix_auth_revocation_outbox_user_id'), 'auth_revocation_outbox', ['user_id'], unique=False)

    # ``auth_user.auth_generation`` — NOT NULL is safe here because the server
    # default backfills every existing row to the first generation (3.5.1); no
    # equivalence CHECK yet (Enforce).
    op.add_column(
        'auth_user',
        sa.Column('auth_generation', sa.BigInteger(), server_default=sa.text('1'), nullable=False),
    )

    # ``auth_client_session.auth_generation`` — nullable through Expand; legacy
    # sessions carry NULL and are treated as revoked at runtime, never
    # backfilled (3.5.1). NOT NULL lands in Enforce once the global
    # legacy-session revocation (4.1 step 5) has removed every NULL row.
    op.add_column(
        'auth_client_session',
        sa.Column('auth_generation', sa.BigInteger(), nullable=True),
    )

    # ``auth_api_key.access_mode`` — NOT NULL from Expand: the server default
    # migrates every existing key to the most restrictive mode (APIKEY-MODE-01).
    _access_mode_enum.create(op.get_bind(), checkfirst=True)
    op.add_column(
        'auth_api_key',
        sa.Column('access_mode', _access_mode_enum, server_default='READ_ONLY', nullable=False),
    )

    op.create_table(
        'auth_api_key_audiences',
        sa.Column('api_key_id', sa.Uuid(), nullable=False),
        sa.Column('audience_id', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['api_key_id'], ['auth_api_key.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('api_key_id', 'audience_id'),
    )

    # Seed the singleton superuser-set lock row (3.5.3, REV-LOCK-01). The
    # runtime lock acquisition path (``role_admin.acquire_superuser_set_lock``)
    # defensively re-seeds it if absent (first run / unit-test metadata
    # schema), but production relies on this migration-time seed.
    op.execute(
        sa.text(
            "INSERT INTO auth_security_policy (policy_key, revision, updated_at) "
            "VALUES ('superuser_set', 0, CURRENT_TIMESTAMP)"
        )
    )


def downgrade() -> None:
    op.execute(sa.text("DELETE FROM auth_security_policy WHERE policy_key = 'superuser_set'"))

    op.drop_table('auth_api_key_audiences')

    op.drop_column('auth_api_key', 'access_mode')
    _access_mode_enum.drop(op.get_bind(), checkfirst=True)

    op.drop_column('auth_client_session', 'auth_generation')
    op.drop_column('auth_user', 'auth_generation')

    op.drop_index(op.f('ix_auth_revocation_outbox_user_id'), table_name='auth_revocation_outbox')
    op.drop_index(op.f('ix_auth_revocation_outbox_status'), table_name='auth_revocation_outbox')
    op.drop_table('auth_revocation_outbox')

    op.drop_index(op.f('ix_auth_tombstone_user_id'), table_name='auth_tombstone')
    op.drop_table('auth_tombstone')

    op.drop_table('auth_security_policy')
