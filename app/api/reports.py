from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_device
from app.config import Settings
from app.db.models import (
    Device,
    DeviceStatus,
    HistoryActorType,
    Report,
    ReportHistory,
    ReportHistoryAction,
    ReportPhoto,
    ReportStatus,
    ReportType,
)
from app.media.storage import MediaStorage, get_media_paths_for_photo
from app.security.device_crypto import compute_device_token_hash

router = APIRouter(tags=["reports"])


ROOMS_ALLOWED = (
    [*range(101, 110)] +
    [*range(201, 211)] +
    [*range(301, 311)]
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validate_room(room: int) -> None:
    if room not in ROOMS_ALLOWED:
        raise HTTPException(status_code=400, detail="Invalid room")


def _sanitize_description(description: str | None) -> str | None:
    if description is None:
        return None
    s = description.strip()
    if not s:
        return None
    if len(s) > 50:
        raise HTTPException(status_code=400, detail="Description too long")
    if any(ord(c) < 32 for c in s):
        raise HTTPException(status_code=400, detail="Invalid description")
    return s


def _device_roles(device: Device) -> set[str]:
    """Bezpečné načtení rolí zařízení jako množiny stringů."""
    try:
        roles = getattr(device, "roles", set()) or set()
    except Exception:
        return set()
    return set(roles)


def _ensure_device_allowed_for_category(device: Device, report_type: ReportType) -> None:
    """Vynucení oprávnění podle rolí zařízení pro danou kategorii reportu.

    Zpětná kompatibilita: pokud zařízení nemá žádné role, neaplikuje se žádné omezení.
    """
    roles = _device_roles(device)
    if not roles:
        return

    if report_type == ReportType.FIND:
        allowed_roles = {"frontdesk", "housekeeping"}
    else:
        allowed_roles = {"maintenance", "housekeeping"}

    if roles.isdisjoint(allowed_roles):
        raise HTTPException(status_code=403, detail="DEVICE_ROLE_FORBIDDEN")


def _resolve_device_for_media(request: Request, db: Session) -> Device:
    """Auth fallback pro obrázky: token, X-Device-Id nebo query ?device_id."""
    headers = request.headers
    token = headers.get("x-device-token")
    auth = headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
    if token:
        hashed = compute_device_token_hash(token.strip())
        device = db.execute(select(Device).where(Device.token_hash == hashed)).scalar_one_or_none()
        if device is None or device.status != DeviceStatus.ACTIVE:
            raise HTTPException(status_code=401, detail="DEVICE_TOKEN_INVALID")
        return device

    device_id = headers.get("x-device-id") or request.query_params.get("device_id")
    if device_id:
        device = db.execute(select(Device).where(Device.device_id == device_id.strip())).scalar_one_or_none()
        if device is None:
            raise HTTPException(status_code=401, detail="DEVICE_NOT_REGISTERED")
        if device.status != DeviceStatus.ACTIVE:
            raise HTTPException(status_code=403, detail="DEVICE_NOT_ACTIVE")
        return device

    raise HTTPException(status_code=401, detail="DEVICE_AUTH_MISSING")


class CreateReportResponse(BaseModel):
    ok: bool = True
    reportId: str


class ReportSummary(BaseModel):
    id: str
    room: int
    description: Optional[str] = None
    createdAt: str
    type: str
    photos: list[str] = Field(default_factory=list)
    thumbnailUrls: list[str] = Field(default_factory=list)


class ReportListResponse(BaseModel):
    items: list[ReportSummary] = Field(default_factory=list)


class GenericOkResponse(BaseModel):
    ok: bool = True


class NewSinceResponse(BaseModel):
    lastSeenOpenFindsId: int | None = None
    lastSeenOpenIssuesId: int | None = None
    newOpenFindsCount: int = 0
    newOpenIssuesCount: int = 0


@router.post("/reports", response_model=CreateReportResponse)
async def create_report(
    request: Request,
    db: Session = Depends(get_db),
    device: Device = Depends(require_device),
    settings: Settings = Depends(Settings.from_env),
    type: Annotated[str, Form(...)] = "FIND",
    room: Annotated[int, Form(...)] = 101,
    description: Annotated[Optional[str], Form(...)] = None,
    createdAtEpochMs: Annotated[int, Form(...)] = 0,
    photos: Annotated[list[UploadFile], File(...)] = [],
):
    if device.status != DeviceStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="Device not active")

    try:
        report_type = ReportType(type)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid type") from e

    _ensure_device_allowed_for_category(device, report_type)

    _validate_room(room)
    desc = _sanitize_description(description)

    if len(photos) > 5:
        raise HTTPException(status_code=400, detail="Photos must be 0-5")

    for f in photos:
        if f.content_type not in {"image/jpeg", "image/jpg", "image/png"}:
            raise HTTPException(status_code=400, detail="Unsupported image type")

    report = Report(
        report_type=report_type,
        status=ReportStatus.OPEN,
        room=str(room),
        description=desc,
        created_by_device_id=device.id,
    )
    db.add(report)
    db.flush()

    storage = MediaStorage(settings.media_root)

    try:
        for idx, up in enumerate(photos, start=1):
            stored = storage.store_photo(
                report_id=report.id,
                photo_id=idx,
                src_file=up.file,
                src_filename=up.filename or f"photo_{idx}",
            )
            db.add(
                ReportPhoto(
                    report_id=report.id,
                    sort_order=idx - 1,
                    file_path=stored.original_relpath,
                    thumb_path=stored.thumb_relpath,
                    mime_type="image/jpeg",
                    size_bytes=stored.bytes,
                )
            )

        db.add(
            ReportHistory(
                report_id=report.id,
                action=ReportHistoryAction.CREATED,
                actor_type=HistoryActorType.DEVICE,
                actor_device_id=device.device_id,
                actor_admin_session=None,
                from_status=None,
                to_status=ReportStatus.OPEN,
                note=json.dumps({"photos": len(photos)}),
            )
        )

        db.commit()
    except Exception:
        db.rollback()
        try:
            storage.delete_report(report.id)
        except Exception:
            pass
        raise

    return CreateReportResponse(reportId=str(report.id), ok=True)


@router.get("/reports/open", response_model=ReportListResponse)
def list_open_reports(
    request: Request,
    category: str,
    db: Session = Depends(get_db),
    device: Device = Depends(require_device),
):
    try:
        report_type = ReportType(category.strip().upper())
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid category") from e

    _ensure_device_allowed_for_category(device, report_type)

    q = (
        select(Report)
        .where(
            and_(
                Report.status == ReportStatus.OPEN,
                Report.report_type == report_type,
                Report.done_at.is_(None),
            )
        )
        .order_by(Report.created_at.desc(), Report.id.desc())
    )
    reports = db.execute(q).scalars().all()

    items: list[ReportSummary] = []
    for r in reports:
        thumb_urls = []
        if r.photos:
            for p in r.photos:
                if p.thumb_path:
                    thumb_urls.append(f"/api/reports/photos/{p.id}/thumb")
        items.append(
            ReportSummary(
                id=str(r.id),
                room=int(r.room),
                description=r.description,
                createdAt=_iso(r.created_at),
                type=r.report_type.value,
                photos=[],
                thumbnailUrls=thumb_urls,
            )
        )

    return ReportListResponse(items=items)


@router.post("/reports/mark-done", response_model=GenericOkResponse)
def mark_done(
    request: Request,
    id: str,
    db: Session = Depends(get_db),
    device: Device = Depends(require_device),
):
    try:
        rid = int(id)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid id") from e

    r = db.get(Report, rid)
    if not r:
        raise HTTPException(status_code=404, detail="Not found")

    # Pokud má zařízení role, nesmí měnit reporty mimo své kategorie.
    report_type = r.report_type
    _ensure_device_allowed_for_category(device, report_type)

    if r.status != ReportStatus.DONE:
        from_status = r.status
        r.status = ReportStatus.DONE
        r.done_at = _now()
        r.done_by_device_id = device.device_id
        db.add(
            ReportHistory(
                report_id=r.id,
                action=ReportHistoryAction.MARK_DONE,
                actor_type=HistoryActorType.DEVICE,
                actor_device_id=device.device_id,
                actor_admin_session=None,
                from_status=from_status,
                to_status=r.status,
                note=None,
            )
        )
        db.commit()

    return GenericOkResponse(ok=True)


@router.get("/reports/photos/{photo_id}/thumb")
def report_photo_thumb(
    request: Request,
    photo_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    _resolve_device_for_media(request, db)
    photo = db.get(ReportPhoto, photo_id)
    if not photo:
        raise HTTPException(status_code=404, detail="Not found")

    orig, thumb = get_media_paths_for_photo(settings=settings, photo=photo)
    if not thumb.exists():
        raise HTTPException(status_code=404, detail="File missing")

    return FileResponse(path=thumb)


@router.get("/poll/new-since", response_model=NewSinceResponse)
def poll_new_since(
    request: Request,
    db: Session = Depends(get_db),
    device: Device = Depends(require_device),
):
    qp = request.query_params

    def _parse_int(name: str) -> int | None:
        raw = qp.get(name)
        if raw is None or raw == "":
            return None
        try:
            return int(raw)
        except Exception:
            raise HTTPException(status_code=400, detail=f"Invalid {name}")

    last_find = _parse_int("last_seen_find_id") or _parse_int("lastSeenOpenFindsId")
    last_issue = _parse_int("last_seen_issue_id") or _parse_int("lastSeenOpenIssuesId")

    roles = _device_roles(device)
    enforce = bool(roles)
    allow_find = (not enforce) or (not roles.isdisjoint({"frontdesk", "housekeeping"}))
    allow_issue = (not enforce) or (not roles.isdisjoint({"maintenance", "housekeeping"}))

    newest_find = (
        db.scalar(
            select(func.max(Report.id)).where(
                and_(Report.status == ReportStatus.OPEN, Report.report_type == ReportType.FIND)
            )
        )
        if allow_find
        else None
    )
    newest_issue = (
        db.scalar(
            select(func.max(Report.id)).where(
                and_(Report.status == ReportStatus.OPEN, Report.report_type == ReportType.ISSUE)
            )
        )
        if allow_issue
        else None
    )

    if not allow_find:
        new_finds = 0
        next_find = None
    elif last_find is None:
        new_finds = 0
        next_find = int(newest_find) if newest_find is not None else None
    else:
        new_finds = int(
            db.scalar(
                select(func.count()).select_from(Report).where(
                    and_(
                        Report.status == ReportStatus.OPEN,
                        Report.report_type == ReportType.FIND,
                        Report.id > last_find,
                    )
                )
            )
            or 0
        )
        next_find = int(newest_find) if newest_find is not None else last_find

    if not allow_issue:
        new_issues = 0
        next_issue = None
    elif last_issue is None:
        new_issues = 0
        next_issue = int(newest_issue) if newest_issue is not None else None
    else:
        new_issues = int(
            db.scalar(
                select(func.count()).select_from(Report).where(
                    and_(
                        Report.status == ReportStatus.OPEN,
                        Report.report_type == ReportType.ISSUE,
                        Report.id > last_issue,
                    )
                )
            )
            or 0
        )
        next_issue = int(newest_issue) if newest_issue is not None else last_issue

    return NewSinceResponse(
        lastSeenOpenFindsId=next_find,
        lastSeenOpenIssuesId=next_issue,
        newOpenFindsCount=new_finds,
        newOpenIssuesCount=new_issues,
    )
