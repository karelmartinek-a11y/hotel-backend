from __future__ import annotations

import enum
from datetime import date, datetime, time

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    Time,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class DeviceStatus(str, enum.Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class ReportType(str, enum.Enum):
    FIND = "FIND"  # Nalez
    ISSUE = "ISSUE"  # Zavada


class ReportStatus(str, enum.Enum):
    OPEN = "OPEN"
    DONE = "DONE"


class AdminSingleton(Base):
    """Single-row table holding the single admin password hash.

    Requirement: web admin is protected by a single password (no accounts).
    """

    __tablename__ = "admin_singleton"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # e.g. argon2/bcrypt hash (never store plaintext)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    device_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    status: Mapped[DeviceStatus] = mapped_column(
        Enum(DeviceStatus, name="device_status"), nullable=False, default=DeviceStatus.PENDING
    )

    # When admin activates, we store display name/label for admin UI.
    display_name: Mapped[str | None] = mapped_column(String(120), nullable=True)

    # Comma-separated list of role keys ("frontdesk", "housekeeping", "maintenance").
    # Public API používá property `roles`, tato kolona je jen interní úložiště.
    roles_raw: Mapped[str | None] = mapped_column("roles", String(64), nullable=True, default=None)

    # Public key bytes (raw). Algorithm chosen in API layer; for now store bytes and metadata.
    public_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    public_key_alg: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Device token is an app authentication token (random), stored hashed.
    token_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Challenge-response nonce storage (last issued nonce + time) to mitigate replay.
    last_challenge_nonce: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_challenge_issued_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    reports: Mapped[list[Report]] = relationship(
        back_populates="created_by_device", cascade="all,delete", passive_deletes=True
    )

    @property
    def roles(self) -> set[str]:
        """Vrátí normalizované role přiřazené k zařízení.

        Prázdná množina = zařízení zatím nemá žádné role (zpětná kompatibilita).
        """
        raw = (self.roles_raw or "").strip()
        if not raw:
            return set()
        return {part for part in (item.strip() for item in raw.split(",")) if part}

    @roles.setter
    def roles(self, value: set[str] | list[str]) -> None:
        if not value:
            self.roles_raw = None
            return
        normalized = sorted({str(v).strip().lower() for v in value if str(v).strip()})
        self.roles_raw = ",".join(normalized)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    report_type: Mapped[ReportType] = mapped_column(
        Enum(ReportType, name="report_type"), nullable=False
    )

    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, name="report_status"), nullable=False, default=ReportStatus.OPEN
    )

    room: Mapped[str] = mapped_column(String(8), nullable=False)  # 101..109, 201..210, 301..310

    description: Mapped[str | None] = mapped_column(String(50), nullable=True)

    created_by_device_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("devices.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    done_by_device_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    created_by_device: Mapped[Device] = relationship(back_populates="reports")

    photos: Mapped[list[ReportPhoto]] = relationship(
        back_populates="report",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ReportPhoto.sort_order.asc()",
    )

    history: Mapped[list[ReportHistory]] = relationship(
        back_populates="report",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ReportHistory.id.asc()",
    )

    @property
    def category(self) -> str:
        # Legacy alias used by templates/routes
        return self.report_type.value if isinstance(self.report_type, enum.Enum) else str(self.report_type)


class ReportPhoto(Base):
    __tablename__ = "report_photos"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    report_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("reports.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Stored filenames are relative to MEDIA_ROOT; never store absolute paths.
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    thumb_path: Mapped[str] = mapped_column(String(512), nullable=False)

    mime_type: Mapped[str] = mapped_column(String(80), nullable=False)

    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    report: Mapped[Report] = relationship(back_populates="photos")


class HistoryActorType(str, enum.Enum):
    ADMIN = "ADMIN"
    DEVICE = "DEVICE"


class ReportHistoryAction(str, enum.Enum):
    CREATED = "CREATED"
    MARK_DONE = "MARK_DONE"
    REOPEN = "REOPEN"
    DELETE = "DELETE"


class ReportHistory(Base):
    __tablename__ = "report_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    report_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("reports.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    action: Mapped[ReportHistoryAction] = mapped_column(
        Enum(ReportHistoryAction, name="report_history_action"), nullable=False
    )

    actor_type: Mapped[HistoryActorType] = mapped_column(
        Enum(HistoryActorType, name="history_actor_type"), nullable=False
    )

    actor_device_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    actor_admin_session: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )  # optional session id / marker

    # Snapshot fields for audit (minimal)
    from_status: Mapped[ReportStatus | None] = mapped_column(
        Enum(ReportStatus, name="report_status"), nullable=True
    )
    to_status: Mapped[ReportStatus | None] = mapped_column(
        Enum(ReportStatus, name="report_status"), nullable=True
    )

    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    report: Mapped[Report] = relationship(back_populates="history")


# --- Breakfast ingestion ---

class BreakfastMailConfig(Base):
    """Single-row-ish config table for breakfast mail fetcher.

    In step 2 (admin UI), this will be editable in /admin.
    For now, the backend uses this table if present; otherwise it falls back to env defaults.
    """

    __tablename__ = "breakfast_mail_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    imap_host: Mapped[str] = mapped_column(String(255), nullable=False, default="mail.webglobe.cz")
    imap_port: Mapped[int] = mapped_column(Integer, nullable=False, default=993)
    imap_security: Mapped[str] = mapped_column(String(16), nullable=False, default="SSL")
    imap_use_ssl: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    imap_mailbox: Mapped[str] = mapped_column(String(120), nullable=False, default="INBOX")

    username: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    password: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    password_enc: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    from_contains: Mapped[str | None] = mapped_column(String(255), nullable=True, default="better-hotel.com")
    subject_contains: Mapped[str | None] = mapped_column(String(255), nullable=True, default="přehled stravy")
    filter_from: Mapped[str | None] = mapped_column(String(255), nullable=True)
    filter_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)

    window_start: Mapped[time] = mapped_column(Time, nullable=False, default=time(2, 0))
    window_end: Mapped[time] = mapped_column(Time, nullable=False, default=time(3, 0))
    retry_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=5)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class BreakfastDay(Base):
    """Normalized breakfast data for a single day (D)."""

    __tablename__ = "breakfast_days"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    day: Mapped[date] = mapped_column(Date, nullable=False, unique=True, index=True)

    # Relative paths under MEDIA_ROOT (never absolute paths in DB)
    pdf_path: Mapped[str] = mapped_column(String(512), nullable=False)
    pdf_archive_path: Mapped[str] = mapped_column(String(512), nullable=False)

    # Mail provenance (best-effort)
    source_uid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_message_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)

    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Human-readable output required by spec
    text_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")

    entries: Mapped[list[BreakfastEntry]] = relationship(
        back_populates="breakfast_day",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="BreakfastEntry.room.asc()",
    )


class BreakfastEntry(Base):
    """One row per room for a given day; only rooms with breakfast > 0 are stored."""

    __tablename__ = "breakfast_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    breakfast_day_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("breakfast_days.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    room: Mapped[str] = mapped_column(String(8), nullable=False, index=True)  # e.g. "101"
    breakfast_count: Mapped[int] = mapped_column(Integer, nullable=False)
    guest_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    checked_by_device_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    breakfast_day: Mapped[BreakfastDay] = relationship(back_populates="entries")


Index("ix_breakfast_entries_day_room", BreakfastEntry.breakfast_day_id, BreakfastEntry.room, unique=True)

# Diagnostics for fetcher (admin)
class BreakfastFetchStatus(Base):
    __tablename__ = "breakfast_fetch_status"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


# ---------------------------------------------------------------------------
# Inventory / breakfast ingredients stock
# ---------------------------------------------------------------------------


class InventoryUnit(str, enum.Enum):
    # NOTE: We store the enum value as the label shown to users.
    # For kg/l we still keep stock quantities in base units (g/ml) internally.
    KG = "kg"
    G = "g"
    L = "l"
    ML = "ml"
    KS = "ks"


class StockCardType(str, enum.Enum):
    IN = "IN"   # příjem
    OUT = "OUT"  # výdej


class InventoryIngredient(Base):
    __tablename__ = "inventory_ingredients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    name: Mapped[str] = mapped_column(String(120), nullable=False)

    unit: Mapped[InventoryUnit] = mapped_column(
        Enum(InventoryUnit, name="inventory_unit"), nullable=False, default=InventoryUnit.G
    )

    # Amount in 1 piece, stored in base unit (g/ml/ks).
    amount_per_piece_base: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Current stock, stored in base unit (g/ml/ks).
    stock_qty_base: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    pictogram_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    pictogram_thumb_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    card_lines: Mapped[list[StockCardLine]] = relationship(
        "StockCardLine",
        back_populates="ingredient",
        cascade="all,delete",
        passive_deletes=True,
    )


class StockCard(Base):
    __tablename__ = "inventory_stock_cards"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    card_type: Mapped[StockCardType] = mapped_column(
        Enum(StockCardType, name="stock_card_type"), nullable=False
    )

    number: Mapped[str] = mapped_column(String(40), nullable=False)
    card_date: Mapped[date] = mapped_column(Date, nullable=False, default=date.today)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    lines: Mapped[list[StockCardLine]] = relationship(
        back_populates="card",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="StockCardLine.id.asc()",
    )

    __table_args__ = (
        UniqueConstraint("card_type", "number", name="uq_stock_card_type_number"),
        Index("ix_stock_cards_date", "card_date"),
    )


class StockCardLine(Base):
    __tablename__ = "inventory_stock_card_lines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    card_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("inventory_stock_cards.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    ingredient_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("inventory_ingredients.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # Signed delta in base unit (g/ml/ks). For OUT cards we store negative deltas.
    qty_delta_base: Mapped[int] = mapped_column(Integer, nullable=False)

    card: Mapped[StockCard] = relationship(back_populates="lines")
    ingredient: Mapped[InventoryIngredient] = relationship(back_populates="card_lines")

# Indexy pro filtrování/stránkování
Index("ix_reports_type_status_created_at", Report.report_type, Report.status, Report.created_at)
Index("ix_reports_room_created_at", Report.room, Report.created_at)


# Sanity constraints
UniqueConstraint(Device.device_id, name="uq_devices_device_id")
