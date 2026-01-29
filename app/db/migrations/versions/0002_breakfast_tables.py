"""Add breakfast mail config + normalized breakfast tables.

Revision ID: 0002_breakfast_tables
Revises: 0001_device_roles
Create Date: 2026-01-22 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_breakfast_tables"
down_revision: str | None = "0001_device_roles"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "breakfast_mail_config",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("imap_host", sa.String(length=255), nullable=False, server_default="mail.webglobe.cz"),
        sa.Column("imap_port", sa.Integer(), nullable=False, server_default=sa.text("993")),
        sa.Column("imap_use_ssl", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("imap_mailbox", sa.String(length=120), nullable=False, server_default="INBOX"),
        sa.Column("username", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("password", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("from_contains", sa.String(length=255), nullable=True),
        sa.Column("subject_contains", sa.String(length=255), nullable=True),
        sa.Column("window_start", sa.Time(), nullable=False, server_default=sa.text("'02:00:00'")),
        sa.Column("window_end", sa.Time(), nullable=False, server_default=sa.text("'03:00:00'")),
        sa.Column("retry_minutes", sa.Integer(), nullable=False, server_default=sa.text("5")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_table(
        "breakfast_days",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("pdf_path", sa.String(length=512), nullable=False),
        sa.Column("pdf_archive_path", sa.String(length=512), nullable=False),
        sa.Column("source_uid", sa.String(length=64), nullable=True),
        sa.Column("source_message_id", sa.String(length=255), nullable=True),
        sa.Column("source_subject", sa.String(length=255), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("text_summary", sa.Text(), nullable=False, server_default=""),
        sa.UniqueConstraint("day", name="uq_breakfast_days_day"),
    )
    op.create_index("ix_breakfast_days_day", "breakfast_days", ["day"])

    op.create_table(
        "breakfast_entries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "breakfast_day_id",
            sa.Integer(),
            sa.ForeignKey("breakfast_days.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("room", sa.String(length=8), nullable=False),
        sa.Column("breakfast_count", sa.Integer(), nullable=False),
    )
    op.create_index("ix_breakfast_entries_day", "breakfast_entries", ["breakfast_day_id"])
    op.create_index("ix_breakfast_entries_room", "breakfast_entries", ["room"])
    op.create_index(
        "ix_breakfast_entries_day_room",
        "breakfast_entries",
        ["breakfast_day_id", "room"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_breakfast_entries_day_room", table_name="breakfast_entries")
    op.drop_index("ix_breakfast_entries_room", table_name="breakfast_entries")
    op.drop_index("ix_breakfast_entries_day", table_name="breakfast_entries")
    op.drop_table("breakfast_entries")

    op.drop_index("ix_breakfast_days_day", table_name="breakfast_days")
    op.drop_table("breakfast_days")

    op.drop_table("breakfast_mail_config")
