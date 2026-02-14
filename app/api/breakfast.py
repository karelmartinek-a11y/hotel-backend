# ruff: noqa: B008
from __future__ import annotations

import json
from datetime import UTC, date, datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db

router = APIRouter(prefix="/v1/breakfast", tags=["breakfast"])


def _now() -> datetime:
    return datetime.now(UTC)


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
    guestName: str | None = None
    note: str | None = None
    checkedAt: str | None = None
    checkedBy: str | None = None


class BreakfastDayResponse(BaseModel):
    date: str
    status: str = Field(..., description="FOUND | MISSING")
    items: list[BreakfastItem] = Field(default_factory=list)


class BreakfastCheckRequest(BaseModel):
    date: date
    room: int
    checked: bool | None = True
    note: str | None = None


class BreakfastNoteRequest(BaseModel):
    date: date
    room: int
    note: str | None = None


class BreakfastImportResponse(BreakfastDayResponse):
    saved: bool = False


class GenericOkResponse(BaseModel):
    ok: bool = True


@router.get("/day", response_model=BreakfastDayResponse)
def get_breakfast_day(
    date: date,
    db: Session = Depends(get_db),
):
    raise HTTPException(status_code=410, detail="LEGACY_DEVICE_API_DISABLED")


@router.post("/check", response_model=GenericOkResponse)
def check_breakfast(
    payload: BreakfastCheckRequest,
    db: Session = Depends(get_db),
):
    raise HTTPException(status_code=410, detail="LEGACY_DEVICE_API_DISABLED")


@router.post("/import", response_model=BreakfastImportResponse)
def import_breakfast(
    save: bool = Form(False),
    notes: str = Form(""),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    raise HTTPException(status_code=410, detail="LEGACY_DEVICE_API_DISABLED")


@router.post("/note", response_model=GenericOkResponse)
def update_breakfast_note(
    payload: BreakfastNoteRequest,
    db: Session = Depends(get_db),
):
    raise HTTPException(status_code=410, detail="LEGACY_DEVICE_API_DISABLED")
