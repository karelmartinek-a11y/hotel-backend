"""Add checked fields to breakfast entries.

Revision ID: 0003_breakfast_checks
Revises: 0002_breakfast_tables
Create Date: 2026-01-22 18:10:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_breakfast_checks"
down_revision: Union[str, None] = "0002_breakfast_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "breakfast_entries",
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "breakfast_entries",
        sa.Column("checked_by_device_id", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("breakfast_entries", "checked_by_device_id")
    op.drop_column("breakfast_entries", "checked_at")
