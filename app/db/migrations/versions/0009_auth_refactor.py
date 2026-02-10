"""Auth refactor: remove devices, extend portal users."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0009_auth_refactor"
down_revision = "0008_portal_users_smtp"
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = inspect(conn)
    has_devices = inspector.has_table("devices")

    # portal_users
    op.add_column("portal_users", sa.Column("first_name", sa.String(length=80), nullable=False, server_default=""))
    op.add_column("portal_users", sa.Column("last_name", sa.String(length=80), nullable=False, server_default=""))
    op.add_column("portal_users", sa.Column("phone", sa.String(length=20), nullable=True))
    op.add_column(
        "portal_users",
        sa.Column(
            "roles",
            postgresql.JSON(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::json"),
        ),
    )
    op.add_column("portal_users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("portal_users", sa.Column("last_password_change_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("portal_users", sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("portal_users", sa.Column("failed_window_started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("portal_users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))

    # backfill names from legacy "name" if exists
    op.execute(
        """
        UPDATE portal_users
        SET first_name = COALESCE(NULLIF(split_part(name, ' ', 1), ''), ''),
            last_name  = COALESCE(NULLIF(ltrim(substr(name, length(split_part(name, ' ', 1)) + 1)), ''), '')
        WHERE first_name = '' AND last_name = ''
        """
    )

    # reports: link to users
    op.add_column("reports", sa.Column("created_by_user_id", sa.Integer(), nullable=True))
    op.add_column("reports", sa.Column("done_by_user_id", sa.Integer(), nullable=True))
    op.create_foreign_key(None, "reports", "portal_users", ["created_by_user_id"], ["id"], ondelete="SET NULL")
    op.create_foreign_key(None, "reports", "portal_users", ["done_by_user_id"], ["id"], ondelete="SET NULL")
    # drop old device cols if present
    with op.batch_alter_table("reports") as batch:
        if has_devices:
            try:
                batch.drop_constraint("reports_created_by_device_id_fkey", type_="foreignkey")
            except Exception:
                pass
        for col in ("created_by_device_id", "done_by_device_id"):
            try:
                batch.drop_column(col)
            except Exception:
                pass
        try:
            batch.add_column(sa.Column("actor_user_id", sa.Integer(), nullable=True))
        except Exception:
            pass
        try:
            batch.create_foreign_key(None, "portal_users", ["actor_user_id"], ["id"], ondelete="SET NULL")
        except Exception:
            pass

    # admin lockout columns
    op.add_column("admin_singleton", sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("admin_singleton", sa.Column("failed_window_started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("admin_singleton", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))

    # drop devices table if exists
    if has_devices:
        try:
            op.drop_table("devices")
        except Exception:
            pass

    # report_history actor_user_id + drop actor_device_id
    with op.batch_alter_table("report_history") as batch:
        try:
            batch.add_column(sa.Column("actor_user_id", sa.Integer(), nullable=True))
            batch.create_foreign_key(None, "portal_users", ["actor_user_id"], ["id"], ondelete="SET NULL")
        except Exception:
            pass
        try:
            batch.drop_column("actor_device_id")
        except Exception:
            pass

    # breakfast_entries checked_by_user_id
    with op.batch_alter_table("breakfast_entries") as batch:
        try:
            batch.add_column(sa.Column("checked_by_user_id", sa.Integer(), nullable=True))
            batch.create_foreign_key(None, "portal_users", ["checked_by_user_id"], ["id"], ondelete="SET NULL")
        except Exception:
            pass
        try:
            batch.drop_column("checked_by_device_id")
        except Exception:
            pass


def downgrade():
    # best-effort: remove new columns, restore device columns
    with op.batch_alter_table("admin_singleton") as batch:
        for col in ("locked_until", "failed_window_started_at", "failed_attempts"):
            try:
                batch.drop_column(col)
            except Exception:
                pass

    # revert report_history
    with op.batch_alter_table("report_history") as batch:
        try:
            batch.add_column(sa.Column("actor_device_id", sa.String(length=64), nullable=True))
        except Exception:
            pass
        for fk in ("report_history_actor_user_id_fkey",):
            try:
                batch.drop_constraint(fk, type_="foreignkey")
            except Exception:
                pass
        try:
            batch.drop_column("actor_user_id")
        except Exception:
            pass

    # revert breakfast_entries
    with op.batch_alter_table("breakfast_entries") as batch:
        for fk in ("breakfast_entries_checked_by_user_id_fkey",):
            try:
                batch.drop_constraint(fk, type_="foreignkey")
            except Exception:
                pass
        try:
            batch.add_column(sa.Column("checked_by_device_id", sa.String(length=64), nullable=True))
        except Exception:
            pass
        try:
            batch.drop_column("checked_by_user_id")
        except Exception:
            pass

    with op.batch_alter_table("reports") as batch:
        for fk in ("reports_created_by_user_id_fkey", "reports_done_by_user_id_fkey"):
            try:
                batch.drop_constraint(fk, type_="foreignkey")
            except Exception:
                pass
        for col in ("done_by_user_id", "created_by_user_id"):
            try:
                batch.drop_column(col)
            except Exception:
                pass
        batch.add_column(sa.Column("done_by_device_id", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("created_by_device_id", sa.Integer(), nullable=True))

    with op.batch_alter_table("portal_users") as batch:
        for col in (
            "locked_until",
            "failed_window_started_at",
            "failed_attempts",
            "last_password_change_at",
            "last_login_at",
            "roles",
            "phone",
            "last_name",
            "first_name",
        ):
            try:
                batch.drop_column(col)
            except Exception:
                pass

    # recreate devices table (minimal)
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.String(length=64), unique=True, nullable=False),
    )
