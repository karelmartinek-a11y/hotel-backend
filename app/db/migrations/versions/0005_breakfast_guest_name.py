"""Add guest_name to breakfast entries.

Revision ID: 0005_breakfast_guest_name
Revises: 0004_breakfast_admin_config
Create Date: 2026-01-25 08:50:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_breakfast_guest_name"
down_revision: str | None = "0004_breakfast_admin_config"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "breakfast_entries",
        sa.Column("guest_name", sa.String(length=255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("breakfast_entries", "guest_name")
