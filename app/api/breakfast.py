from __future__ import annotations

import json
from datetime import date, datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_device
from app.db.models import BreakfastDay, BreakfastEntry, Device, DeviceStatus
from app.services.breakfast.mail_fetcher import _store_pdf_bytes, _upsert_breakfast_day
from app.services.breakfast.parser import format_text_summary, parse_breakfast_pdf


router = APIRouter(prefix="/v1/breakfast", tags=["breakfast"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _device_roles(device: Device) -> set[str]:
    try:
        roles = getattr(device, "roles", set()) or set()
    except Exception:
        return set()
    return set(roles)


def _ensure_device_allowed_for_breakfast(device: Device) -> None:
    roles = _device_roles(device)
    if not roles:
        return
    allowed = {"breakfast", "frontdesk"}
    if roles.isdisjoint(allowed):
        raise HTTPException(status_code=403, detail="DEVICE_ROLE_FORBIDDEN")


def _parse_note_map(raw: str) -> dict[str, str]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    out: dict[str, str] = {}
    if isinstance(data, dict):
        for key, val in data.items():
            if val is None:
                continue
            try:
                text = str(val).strip()
            except Exception:
                continue
            if text:
                out[str(key)] = text
    return out


class BreakfastItem(BaseModel):
    room: int
    count: int = Field(..., ge=0)
    guestName: Optional[str] = None
    note: Optional[str] = None
    checkedAt: Optional[str] = None
    checkedBy: Optional[str] = None


class BreakfastDayResponse(BaseModel):
    date: str
    status: str = Field(..., description="FOUND | MISSING")
    items: list[BreakfastItem] = Field(default_factory=list)


class BreakfastCheckRequest(BaseModel):
    date: date
    room: int
    checked: Optional[bool] = True
    note: Optional[str] = None


class BreakfastNoteRequest(BaseModel):
    date: date
    room: int
    note: Optional[str] = None


class BreakfastImportResponse(BreakfastDayResponse):
    saved: bool = False


class GenericOkResponse(BaseModel):
    ok: bool = True


@router.get("/day", response_model=BreakfastDayResponse)
def get_breakfast_day(
    date: date,
    db: Session = Depends(get_db),
    device: Device = Depends(require_device),
):
    if device.status != DeviceStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="DEVICE_NOT_ACTIVE")
    _ensure_device_allowed_for_breakfast(device)

    day_row = (
        db.execute(select(BreakfastDay).where(BreakfastDay.day == date)).scalars().one_or_none()
    )
    if day_row is None or not day_row.entries:
        return BreakfastDayResponse(date=date.isoformat(), status="MISSING", items=[])

    items: list[BreakfastItem] = []
    for entry in day_row.entries:
        checked_at = None
        if entry.checked_at is not None:
            dt = entry.checked_at
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            checked_at = dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        items.append(
            BreakfastItem(
                room=int(entry.room),
                count=int(entry.breakfast_count),
                guestName=entry.guest_name,
                note=entry.note,
                checkedAt=checked_at,
                checkedBy=entry.checked_by_device_id,
            )
        )

    return BreakfastDayResponse(date=date.isoformat(), status="FOUND", items=items)


@router.post("/check", response_model=GenericOkResponse)
def check_breakfast(
    payload: BreakfastCheckRequest,
    db: Session = Depends(get_db),
    device: Device = Depends(require_device),
):
    if device.status != DeviceStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="DEVICE_NOT_ACTIVE")
    _ensure_device_allowed_for_breakfast(device)

    entry = (
        db.execute(
            select(BreakfastEntry)
            .join(BreakfastDay, BreakfastEntry.breakfast_day_id == BreakfastDay.id)
            .where(BreakfastDay.day == payload.date)
            .where(BreakfastEntry.room == str(payload.room))
        )
        .scalars()
        .one_or_none()
    )
    if entry is None:
        raise HTTPException(status_code=404, detail="NOT_FOUND")

    target_checked = True if payload.checked is None else bool(payload.checked)
    if target_checked:
        entry.checked_at = _now()
        entry.checked_by_device_id = device.device_id
    else:
        entry.checked_at = None
        entry.checked_by_device_id = None
    if payload.note is not None:
        note = payload.note.strip() if isinstance(payload.note, str) else None
        entry.note = note or None
    db.add(entry)
    db.commit()

    return GenericOkResponse(ok=True)


@router.post("/import", response_model=BreakfastImportResponse)
def import_breakfast(
    save: bool = Form(False),
    notes: str = Form(""),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    device: Device = Depends(require_device),
):
    if device.status != DeviceStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="DEVICE_NOT_ACTIVE")
    _ensure_device_allowed_for_breakfast(device)

    filename = (file.filename or "").lower()
    if not filename.endswith(".pdf"):
        raise HTTPException(status_code=400, detail="EXPECTED_PDF")

    pdf_bytes = file.file.read()
    if not pdf_bytes:
        raise HTTPException(status_code=400, detail="EMPTY_FILE")

    parsed_day, rows = parse_breakfast_pdf(pdf_bytes)
    note_map = _parse_note_map(notes)

    items: list[BreakfastItem] = []
    for row in rows:
        room = int(row.room)
        room_key = str(room)
        alt_key = str(row.room) if str(row.room) != room_key else None
        note = note_map.get(room_key) or (note_map.get(alt_key) if alt_key else None)
        items.append(BreakfastItem(room=room, count=int(row.breakfast_count), guestName=row.guest_name, note=note))
    items.sort(key=lambda x: x.room)

    base_status = "FOUND" if items else "MISSING"
    response = BreakfastImportResponse(
        date=parsed_day.isoformat(),
        status=base_status,
        items=items,
        saved=False,
    )

    if not save:
        return response

    text_summary = format_text_summary(parsed_day, rows)
    pdf_rel, archive_rel = _store_pdf_bytes(pdf_bytes, parsed_day, source_uid=f"device-{device.device_id}")
    entries = [
        (str(item.room), item.count, item.guestName, item.note)
        for item in items
        if item.count > 0
    ]
    _upsert_breakfast_day(
        db=db,
        day=parsed_day,
        pdf_rel=pdf_rel,
        archive_rel=archive_rel,
        source_uid=f"device-{device.device_id}",
        source_message_id=None,
        source_subject="Ruční upload (device)",
        text_summary=text_summary,
        entries=entries,
    )
    response.saved = True
    return response


@router.post("/note", response_model=GenericOkResponse)
def update_breakfast_note(
    payload: BreakfastNoteRequest,
    db: Session = Depends(get_db),
    device: Device = Depends(require_device),
):
    if device.status != DeviceStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="DEVICE_NOT_ACTIVE")
    _ensure_device_allowed_for_breakfast(device)

    entry = (
        db.execute(
            select(BreakfastEntry)
            .join(BreakfastDay, BreakfastEntry.breakfast_day_id == BreakfastDay.id)
            .where(BreakfastDay.day == payload.date)
            .where(BreakfastEntry.room == str(payload.room))
        )
        .scalars()
        .one_or_none()
    )
    if entry is None:
        raise HTTPException(status_code=404, detail="NOT_FOUND")

    note = payload.note.strip() if isinstance(payload.note, str) else None
    entry.note = note or None
    db.add(entry)
    db.commit()

    return GenericOkResponse(ok=True)
