"""Add qty_pieces to inventory stock card lines.

Revision ID: 0007_inventory_qty_pieces
Revises: 0006_breakfast_note
Create Date: 2026-02-05 00:00:00.000000
"""

from collections.abc import Sequence
from decimal import Decimal, ROUND_HALF_UP

import sqlalchemy as sa
from alembic import op

revision: str = "0007_inventory_qty_pieces"
down_revision: str | None = "0006_breakfast_note"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "inventory_stock_card_lines",
        sa.Column("qty_pieces", sa.Integer(), nullable=True, server_default="0"),
    )

    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            """
            SELECT l.id, l.qty_delta_base, i.amount_per_piece_base
            FROM inventory_stock_card_lines l
            JOIN inventory_ingredients i ON i.id = l.ingredient_id
            """
        )
    ).fetchall()
    for row in rows:
        per_piece = int(row.amount_per_piece_base or 0)
        qty_delta = int(row.qty_delta_base or 0)
        if per_piece > 0:
            qty_pieces = int(
                (Decimal(qty_delta) / Decimal(per_piece)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
            )
        else:
            qty_pieces = qty_delta
        bind.execute(
            sa.text("UPDATE inventory_stock_card_lines SET qty_pieces = :qty_pieces WHERE id = :id"),
            {"id": row.id, "qty_pieces": qty_pieces},
        )

    op.alter_column("inventory_stock_card_lines", "qty_pieces", nullable=False)


def downgrade() -> None:
    op.drop_column("inventory_stock_card_lines", "qty_pieces")
