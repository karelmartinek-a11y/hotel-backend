"""Add admin-config fields for breakfast + diagnostics table.

Revision ID: 0004_breakfast_admin_config
Revises: 0003_breakfast_checks
Create Date: 2026-01-22 20:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_breakfast_admin_config"
down_revision: str | None = "0003_breakfast_checks"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "breakfast_mail_config",
        sa.Column("imap_security", sa.String(length=16), nullable=False, server_default="SSL"),
    )
    op.add_column(
        "breakfast_mail_config",
        sa.Column("password_enc", sa.String(length=1024), nullable=True),
    )
    op.add_column(
        "breakfast_mail_config",
        sa.Column("filter_from", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "breakfast_mail_config",
        sa.Column("filter_subject", sa.String(length=255), nullable=True),
    )

    op.create_table(
        "breakfast_fetch_status",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
    )
    op.execute("INSERT INTO breakfast_fetch_status (id) VALUES (1)")


def downgrade() -> None:
    op.drop_table("breakfast_fetch_status")
    op.drop_column("breakfast_mail_config", "filter_subject")
    op.drop_column("breakfast_mail_config", "filter_from")
    op.drop_column("breakfast_mail_config", "password_enc")
    op.drop_column("breakfast_mail_config", "imap_security")
