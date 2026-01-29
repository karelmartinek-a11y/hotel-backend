"""Add note to breakfast entries.

Revision ID: 0006_breakfast_note
Revises: 0005_breakfast_guest_name
Create Date: 2026-01-26 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_breakfast_note"
down_revision: str | None = "0005_breakfast_guest_name"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("breakfast_entries", sa.Column("note", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("breakfast_entries", "note")
