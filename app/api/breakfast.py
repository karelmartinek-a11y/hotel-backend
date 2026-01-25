from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_device
from app.db.models import BreakfastDay, BreakfastEntry, Device, DeviceStatus


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
    if "breakfast" not in roles:
        raise HTTPException(status_code=403, detail="DEVICE_ROLE_FORBIDDEN")


class BreakfastItem(BaseModel):
    room: int
    count: int = Field(..., ge=0)
    guestName: Optional[str] = None
    checkedAt: Optional[str] = None
    checkedBy: Optional[str] = None


class BreakfastDayResponse(BaseModel):
    date: str
    status: str = Field(..., description="FOUND | MISSING")
    items: list[BreakfastItem] = Field(default_factory=list)


class BreakfastCheckRequest(BaseModel):
    date: date
    room: int


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

    if entry.checked_at is not None or entry.checked_by_device_id is not None:
        raise HTTPException(status_code=409, detail="ALREADY_CHECKED")

    entry.checked_at = _now()
    entry.checked_by_device_id = device.device_id
    db.add(entry)
    db.commit()

    return GenericOkResponse(ok=True)
