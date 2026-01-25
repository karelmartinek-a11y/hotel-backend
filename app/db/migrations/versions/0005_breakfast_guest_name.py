"""Add guest_name to breakfast_entries.

Revision ID: 0005_breakfast_guest_name
Revises: 0004_breakfast_admin_config
Create Date: 2026-01-25 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0005_breakfast_guest_name"
down_revision: Union[str, None] = "0004_breakfast_admin_config"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("breakfast_entries", sa.Column("guest_name", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("breakfast_entries", "guest_name")
