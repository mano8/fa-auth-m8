"""Enforce: role/flag equivalence CHECK and final auth_generation NOT NULL
(4.1 step 6)

Applied only after the preflight/repair CLI (4.1 step 4) has resolved every
``is_superuser``/``role`` mismatch and the global legacy-session revocation
(4.1 step 5, ``legacy_session_revocation``) has deleted every
``auth_client_session`` row still carrying a NULL ``auth_generation``. Both
preconditions are operator actions that run between Expand and this migration,
not something this migration performs itself: if either was skipped, the
``ALTER COLUMN ... SET NOT NULL`` or the CHECK backfill validation below fails
loudly instead of silently repairing or discarding rows (4.1 policy — no
automatic promotion/demotion, no silent resurrection of revoked sessions).

Downgrade only drops the CHECK constraint and reverts the NOT NULL constraint
on ``auth_client_session.auth_generation``, per the decided rollback policy
(4.5): it does not restore invalid rows or un-revoke sessions.

Revision ID: eaa7c094c234
Revises: c65504277d36
Create Date: 2026-07-21 00:00:01.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'eaa7c094c234'
down_revision: Union[str, None] = 'c65504277d36'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        'auth_client_session',
        'auth_generation',
        existing_type=sa.BigInteger(),
        nullable=False,
    )
    op.create_check_constraint(
        'ck_user_superuser_role_consistency',
        'auth_user',
        "is_superuser = (role = 'SUPERADMIN')",
    )


def downgrade() -> None:
    op.drop_constraint('ck_user_superuser_role_consistency', 'auth_user', type_='check')
    op.alter_column(
        'auth_client_session',
        'auth_generation',
        existing_type=sa.BigInteger(),
        nullable=True,
    )
