"""Add roles column to devices table.

Revision ID: 0001_device_roles
Revises:
Create Date: 2026-01-20 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001_device_roles"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "devices",
        sa.Column("roles", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("devices", "roles")
