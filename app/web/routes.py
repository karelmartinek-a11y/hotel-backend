from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from PIL import Image
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.models import (
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
from ..db.session import get_db
from ..media.storage import MediaStorage, get_media_paths_for_photo
from ..security.admin_auth import (
    admin_change_password,
    admin_login_check,
    admin_logout,
    admin_require,
    admin_session_is_authenticated,
    set_admin_session,
)
from ..security.csrf import csrf_protect, csrf_token_ensure
from ..security.rate_limit import rate_limit
from .ua_detect import detect_client_kind

router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")

TZ_LOCAL = ZoneInfo("Europe/Prague")

ROOMS_ALLOWED = (
    [*range(101, 110)] +
    [*range(201, 211)] +
    [*range(301, 311)]
)

WEB_APP_ROLES = {
    "housekeeping": "Pokojská",
    "frontdesk": "Recepce",
    "maintenance": "Údržba",
    "breakfast": "Snídaně",
}


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _fmt_dt(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(TZ_LOCAL).strftime("%d.%m.%Y %H:%M")


def _csrf_token(request: Request) -> str:
    return csrf_token_ensure(request) or ""


def _base_ctx(
    request: Request,
    *,
    settings: Settings | None = None,
    active_nav: str | None = None,
    flash: dict | None = None,
    hide_shell: bool = False,
    show_splash: bool = False,
) -> dict[str, Any]:
    settings = settings or Settings.from_env()
    flash_success = flash.get("message") if flash and flash.get("type") == "success" else None
    flash_error = flash.get("message") if flash and flash.get("type") == "error" else None
    return {
        "request": request,
        "year": _now().year,
        "app_version": settings.app_version,
        "admin_logged_in": admin_session_is_authenticated(request),
        "csrf_token": _csrf_token(request),
        "active_nav": active_nav,
        "flash": flash,
        "flash_success": flash_success,
        "flash_error": flash_error,
        "hide_shell": hide_shell,
        "show_splash": show_splash,
    }


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url=url, status_code=303)


def _query_url(request: Request, base_path: str, **updates: Any) -> str:
    params = dict(request.query_params)
    for key, value in updates.items():
        if value is None:
            params.pop(key, None)
        else:
            params[key] = str(value)
    q = urlencode(params)
    return f"{base_path}?{q}" if q else base_path


def _parse_date_filter(raw: str) -> date:
    try:
        return date.fromisoformat(raw)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid date") from e


@router.get("/", response_class=HTMLResponse)
def public_landing(request: Request, settings: Settings = Depends(Settings.from_env)):
    device_class = detect_client_kind(request)
    return templates.TemplateResponse(
        "public_landing.html",
        {
            **_base_ctx(request, settings=settings),
            "device_class": device_class,
            "apk_version": settings.app_version,
        },
    )


@router.get("/app", response_class=HTMLResponse)
def web_app_landing(request: Request, settings: Settings = Depends(Settings.from_env)):
    return templates.TemplateResponse(
        "web_app_landing.html",
        {
            **_base_ctx(request, settings=settings, hide_shell=True),
        },
    )


@router.get("/app/{role}", response_class=HTMLResponse)
def web_app_role(
    request: Request,
    role: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    role_key = (role or "").strip().lower()
    role_title = WEB_APP_ROLES.get(role_key)
    if not role_title:
        raise HTTPException(status_code=404, detail="Not found")

    # Autorizace podle zařízení a přiřazených rolí (pokud nějaké existují).
    device_id = request.headers.get("x-device-id") or request.cookies.get("hotel_device_id")
    device: Device | None = None
    if device_id:
        device = db.scalar(select(Device).where(Device.device_id == device_id.strip()))
    # Zpětná kompatibilita: pokud zařízení nemá žádné role, necháváme přístup otevřený.
    if device and device.roles and role_key not in device.roles:
        raise HTTPException(status_code=403, detail="ROLE_NOT_ALLOWED_FOR_DEVICE")

    device_class = detect_client_kind(request)
    return templates.TemplateResponse(
        "web_app.html",
        {
            **_base_ctx(request, settings=settings, hide_shell=True),
            "role_key": role_key,
            "role_title": role_title,
            "device_class": device_class,
            "rooms": ROOMS_ALLOWED,
        },
    )


@router.get("/app/maintanance")
def web_app_role_typo(_: Request):
    # Alias pro častý překlep, aby uživatelé skončili na správné stránce.
    return _redirect("/app/maintenance")


@router.get("/app/mantenance")
def web_app_role_typo2(_: Request):
    # Další alias překlepu; sjednoceno na /app/maintenance.
    return _redirect("/app/maintenance")


@router.get("/device/pending", response_class=HTMLResponse)
def device_pending(request: Request, settings: Settings = Depends(Settings.from_env)):
    # Public page for pending device activation (web fallback)
    return templates.TemplateResponse(
        "device_pending.html",
        {
            **_base_ctx(request, settings=settings, hide_shell=True, show_splash=True),
            "pending_logo": "asc_logo.png",
            "pending_brand": "ASC Hotel Chodov",
            "pending_app": "Hotel App",
        },
    )


@router.get("/download/app.apk")
def download_apk(_: Request, settings: Settings = Depends(Settings.from_env)):
    if not settings.public_apk_path:
        raise HTTPException(status_code=404, detail="APK not configured")
    return FileResponse(
        path=settings.public_apk_path,
        media_type="application/vnd.android.package-archive",
        filename="app.apk",
    )


@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    if not admin_session_is_authenticated(request):
        return _redirect("/admin/login")

    pending_devices = db.scalar(select(func.count()).select_from(Device).where(Device.status == DeviceStatus.PENDING))

    open_finds = db.scalar(
        select(func.count())
        .select_from(Report)
        .where(Report.status == ReportStatus.OPEN)
        .where(Report.report_type == ReportType.FIND)
    )
    open_issues = db.scalar(
        select(func.count())
        .select_from(Report)
        .where(Report.status == ReportStatus.OPEN)
        .where(Report.report_type == ReportType.ISSUE)
    )

    stats = {
        "pending_devices": int(pending_devices or 0),
        "open_finds": int(open_finds or 0),
        "open_issues": int(open_issues or 0),
        "generated_at_human": _fmt_dt(_now()) or "",
        "api_base": "/api",
        "db_ok": True,
        "media_ok": True,
    }

    return templates.TemplateResponse(
        "admin_dashboard.html",
        {
            **_base_ctx(request, settings=settings, active_nav="dashboard", hide_shell=True, show_splash=True),
            "stats": stats,
        },
    )


@router.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request):
    if admin_session_is_authenticated(request):
        return _redirect("/admin")
    return templates.TemplateResponse(
        "admin_login.html",
        {
            **_base_ctx(request, hide_shell=True, show_splash=True),
        },
    )


@router.post("/admin/login")
@rate_limit("admin_login")
def admin_login_action(
    request: Request,
    password: str = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    csrf_protect(request)
    if not admin_login_check(password=password, db=db, settings=settings):
        return templates.TemplateResponse(
            "admin_login.html",
            {
                **_base_ctx(request, settings=settings, hide_shell=True, show_splash=True),
                "error": "Neplatné heslo",
            },
            status_code=401,
        )
    resp = _redirect("/admin")
    set_admin_session(resp, settings=settings, ttl_minutes=settings.admin_session_ttl_minutes)
    return resp


@router.post("/admin/logout")
def admin_logout_action(request: Request):
    csrf_protect(request)
    resp = _redirect("/")
    admin_logout(request, response=resp)
    return resp


@router.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard_alias(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    return admin_dashboard(request=request, db=db, settings=settings)


@router.get("/admin/reports/findings", response_class=HTMLResponse)
def admin_reports_findings(request: Request):
    if not admin_session_is_authenticated(request):
        return _redirect("/admin/login")
    return _redirect("/admin/reports?category=FIND")


@router.get("/admin/reports/issues", response_class=HTMLResponse)
def admin_reports_issues(request: Request):
    if not admin_session_is_authenticated(request):
        return _redirect("/admin/login")
    return _redirect("/admin/reports?category=ISSUE")


@router.get("/admin/reports", response_class=HTMLResponse)
def admin_reports_list(
    request: Request,
    db: Session = Depends(get_db),
    category: Optional[str] = None,
    status: Optional[str] = None,
    room: Optional[int] = None,
    date: Optional[str] = None,
    sort: str = "created_desc",
    page: int = 1,
    per_page: int = 25,
    type: Optional[str] = None,
):
    admin_require(request)

    if not category and type:
        category = type

    page = max(1, min(page, 10_000))
    per_page = max(10, min(per_page, 100))

    stmt = select(Report)

    if category:
        try:
            stmt = stmt.where(Report.report_type == ReportType(category))
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid category") from e

    if status:
        try:
            stmt = stmt.where(Report.status == ReportStatus(status))
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid status") from e

    if room is not None:
        if room not in ROOMS_ALLOWED:
            raise HTTPException(status_code=400, detail="Invalid room")
        stmt = stmt.where(Report.room == str(room))

    if date:
        day = _parse_date_filter(date)
        start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        stmt = stmt.where(Report.created_at >= start).where(Report.created_at < end)

    if sort == "created_desc":
        stmt = stmt.order_by(Report.created_at.desc())
    elif sort == "created_asc":
        stmt = stmt.order_by(Report.created_at.asc())
    elif sort == "room_asc":
        stmt = stmt.order_by(Report.room.asc(), Report.created_at.desc())
    elif sort == "room_desc":
        stmt = stmt.order_by(Report.room.desc(), Report.created_at.desc())
    elif sort == "status_asc":
        stmt = stmt.order_by(Report.status.asc(), Report.created_at.desc())
    elif sort == "status_desc":
        stmt = stmt.order_by(Report.status.desc(), Report.created_at.desc())
    else:
        raise HTTPException(status_code=400, detail="Invalid sort")

    total = int(db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
    pages_total = max(1, ((total - 1) // per_page) + 1) if total > 0 else 1

    rows = db.scalars(stmt.offset((page - 1) * per_page).limit(per_page)).all()

    report_ids = [r.id for r in rows]
    photos_by_report: dict[int, list[ReportPhoto]] = {}
    if report_ids:
        photos = db.scalars(
            select(ReportPhoto)
            .where(ReportPhoto.report_id.in_(report_ids))
            .order_by(ReportPhoto.report_id.asc(), ReportPhoto.sort_order.asc())
        ).all()
        for p in photos:
            photos_by_report.setdefault(p.report_id, []).append(p)

    reports = []
    for r in rows:
        photos = photos_by_report.get(r.id, [])
        resolved_at_local = _fmt_dt(r.done_at) or ""
        duration_hours = None
        if r.done_at and r.created_at:
            delta = r.done_at - r.created_at
            duration_hours = round(delta.total_seconds() / 3600, 1)
        reports.append(
            {
                "id": r.id,
                "category": r.report_type.value,
                "status": r.status.value,
                "room": int(r.room),
                "description": r.description,
                "created_at_local": _fmt_dt(r.created_at) or "",
                "done_at_local": resolved_at_local,
                "duration_hours": duration_hours,
                "photos": [{"id": p.id, "thumb_url": f"/admin/media/{p.id}/thumb"} for p in photos],
            }
        )

    base_path = "/admin/reports"
    active_nav = "dashboard"
    if category == "FIND":
        active_nav = "findings"
    elif category == "ISSUE":
        active_nav = "issues"

    return templates.TemplateResponse(
        "admin_reports_list.html",
        {
            **_base_ctx(request, active_nav=active_nav, hide_shell=True, show_splash=True),
            "base_path": base_path,
            "query_url": lambda **kw: _query_url(request, base_path, **kw),
            "rooms": ROOMS_ALLOWED,
            "page": page,
            "pages_total": pages_total,
            "total": total,
            "reports": reports,
            "filters": {
                "category": category,
                "status": status,
                "room": room,
                "date": date,
                "sort": sort,
                "per_page": per_page,
            },
        },
    )


@router.get("/admin/reports/{report_id}", response_class=HTMLResponse)
def admin_report_detail(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
):
    admin_require(request)

    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Not found")

    photos = db.scalars(
        select(ReportPhoto).where(ReportPhoto.report_id == report_id).order_by(ReportPhoto.sort_order.asc())
    ).all()

    history = db.scalars(
        select(ReportHistory).where(ReportHistory.report_id == report_id).order_by(ReportHistory.created_at.desc())
    ).all()

    created_by = (
        report.created_by_device.device_id  # type: ignore[union-attr]
        if getattr(report, "created_by_device", None) is not None
        else str(report.created_by_device_id)
    )

    report_vm = {
        "id": report.id,
        "type": report.report_type.value,
        "status": report.status.value,
        "room": int(report.room),
        "description": report.description,
        "created_at_human": _fmt_dt(report.created_at) or "",
        "created_by_device_id": created_by,
        "photo_count": len(photos),
        "done_at_human": _fmt_dt(report.done_at),
        "done_by_device_id": report.done_by_device_id,
        "duration_hours": round(((report.done_at - report.created_at).total_seconds() / 3600), 1)
        if report.done_at and report.created_at
        else None,
    }

    photo_vms = [{"id": p.id, "size_kb": int((p.size_bytes or 0) // 1024)} for p in photos]

    action_labels = {
        ReportHistoryAction.CREATED: "Vytvořeno",
        ReportHistoryAction.MARK_DONE: "Vyřízeno",
        ReportHistoryAction.REOPEN: "Reopen",
        ReportHistoryAction.DELETE: "Smazáno",
    }

    history_vms = []
    for h in history:
        history_vms.append(
            {
                "action_label": action_labels.get(h.action, str(h.action)),
                "at_human": _fmt_dt(h.created_at) or "",
                "by_admin": h.actor_type == HistoryActorType.ADMIN,
                "by_device_id": h.actor_device_id,
                "note": h.note,
            }
        )

    return templates.TemplateResponse(
        "admin_report_detail.html",
        {
            **_base_ctx(request, active_nav="dashboard", hide_shell=True, show_splash=True),
            "report": report_vm,
            "photos": photo_vms,
            "history": history_vms,
        },
    )


@router.post("/admin/reports/{report_id}/done")
def admin_report_done(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
):
    admin_require(request)
    csrf_protect(request)

    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Not found")

    if report.status != ReportStatus.DONE:
        from_status = report.status
        report.status = ReportStatus.DONE
        report.done_at = _now()
        report.done_by_device_id = None
        db.add(
            ReportHistory(
                report_id=report.id,
                action=ReportHistoryAction.MARK_DONE,
                actor_type=HistoryActorType.ADMIN,
                actor_device_id=None,
                actor_admin_session=None,
                from_status=from_status,
                to_status=report.status,
                note=None,
            )
        )
        db.commit()

    return _redirect(f"/admin/reports/{report_id}")


@router.post("/admin/reports/{report_id}/reopen")
def admin_report_reopen(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
):
    admin_require(request)
    csrf_protect(request)

    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Not found")

    if report.status != ReportStatus.OPEN:
        from_status = report.status
        report.status = ReportStatus.OPEN
        report.done_at = None
        report.done_by_device_id = None
        db.add(
            ReportHistory(
                report_id=report.id,
                action=ReportHistoryAction.REOPEN,
                actor_type=HistoryActorType.ADMIN,
                actor_device_id=None,
                actor_admin_session=None,
                from_status=from_status,
                to_status=report.status,
                note=None,
            )
        )
        db.commit()

    return _redirect(f"/admin/reports/{report_id}")


@router.post("/admin/reports/{report_id}/delete")
def admin_report_delete(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    admin_require(request)
    csrf_protect(request)

    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Not found")

    db.delete(report)
    db.commit()

    try:
        MediaStorage(settings.media_root).delete_report(report_id)
    except Exception:
        pass

    return _redirect("/admin/reports")


@router.get("/admin/devices", response_class=HTMLResponse)
def admin_devices(
    request: Request,
    db: Session = Depends(get_db),
):
    admin_require(request)

    def _serialize_roles(d: Device) -> list[str]:
        try:
            roles = getattr(d, "roles", set()) or set()
        except Exception:
            return []
        return sorted(roles)

    pending_raw = db.scalars(
        select(Device).where(Device.status == DeviceStatus.PENDING).order_by(Device.created_at.desc())
    ).all()
    active_raw = db.scalars(
        select(Device).where(Device.status == DeviceStatus.ACTIVE).order_by(Device.created_at.desc())
    ).all()
    revoked_raw = db.scalars(
        select(Device).where(Device.status == DeviceStatus.REVOKED).order_by(Device.created_at.desc())
    ).all()

    pending_devices = [
        {
            "id": d.id,
            "device_id": d.device_id,
            "created_at_human": _fmt_dt(d.created_at) or "",
            "device_label": d.display_name,
            "device_info_summary": d.public_key_alg or "",
            "status": "PENDING",
            "roles": _serialize_roles(d),
        }
        for d in pending_raw
    ]
    active_devices = [
        {
            "id": d.id,
            "device_id": d.device_id,
            "activated_at_human": _fmt_dt(d.activated_at) or "",
            "last_seen_at_human": _fmt_dt(d.last_seen_at) if d.last_seen_at else None,
            "device_label": d.display_name,
            "device_info_summary": d.public_key_alg or "",
            "status": "ACTIVE",
            "roles": _serialize_roles(d),
        }
        for d in active_raw
    ]
    revoked_devices = [
        {
            "id": d.id,
            "device_id": d.device_id,
            "revoked_at_human": _fmt_dt(d.revoked_at) or _fmt_dt(d.updated_at) or "",
            "last_seen_at_human": _fmt_dt(d.last_seen_at) if d.last_seen_at else None,
            "device_label": d.display_name,
            "device_info_summary": d.public_key_alg or "",
            "status": "REVOKED",
            "roles": _serialize_roles(d),
        }
        for d in revoked_raw
    ]

    all_devices = pending_devices + active_devices + revoked_devices

    return templates.TemplateResponse(
        "admin_devices.html",
        {
            **_base_ctx(request, active_nav="devices", hide_shell=True, show_splash=True),
            "pending_devices": pending_devices,
            "active_devices": active_devices,
            "revoked_devices": revoked_devices,
            "all_devices": all_devices,
            "web_app_roles": WEB_APP_ROLES,
        },
    )


@router.get("/admin/settings/devices")
def admin_devices_alias(request: Request):
    if not admin_session_is_authenticated(request):
        return _redirect("/admin/login")
    return _redirect("/admin/devices")


@router.post("/admin/devices/{device_id}/activate")
@rate_limit("admin_device_activate")
def admin_device_activate(
    request: Request,
    device_id: int,
    roles: list[str] = Form(default=[]),
    db: Session = Depends(get_db),
):
    admin_require(request)
    csrf_protect(request)

    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Not found")

    if device.status == DeviceStatus.PENDING:
        allowed_role_keys = set(WEB_APP_ROLES.keys())
        selected_roles = {r.strip().lower() for r in roles if r.strip().lower() in allowed_role_keys}
        if selected_roles:
            device.roles = selected_roles

        device.status = DeviceStatus.ACTIVE
        device.activated_at = _now()
        db.commit()

    return _redirect("/admin/devices")


@router.post("/admin/devices/{device_id}/roles")
@rate_limit("admin_device_roles")
def admin_device_roles(
    request: Request,
    device_id: int,
    roles: list[str] = Form(default=[]),
    db: Session = Depends(get_db),
):
    """Aktualizace rolí u aktivního zařízení."""
    admin_require(request)
    csrf_protect(request)

    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Not found")

    if device.status != DeviceStatus.ACTIVE:
        return _redirect("/admin/devices")

    allowed_role_keys = set(WEB_APP_ROLES.keys())
    selected_roles = {r.strip().lower() for r in roles if r.strip().lower() in allowed_role_keys}
    device.roles = selected_roles

    db.add(device)
    db.commit()
    return _redirect("/admin/devices")


@router.post("/admin/devices/{device_id}/revoke")
@rate_limit("admin_device_revoke")
def admin_device_revoke(
    request: Request,
    device_id: int,
    db: Session = Depends(get_db),
):
    admin_require(request)
    csrf_protect(request)

    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Not found")

    if device.status != DeviceStatus.REVOKED:
        device.status = DeviceStatus.REVOKED
        device.revoked_at = _now()
        db.commit()

    return _redirect("/admin/devices")


@router.post("/admin/devices/{device_id}/delete")
@rate_limit("admin_device_delete")
def admin_device_delete(
    request: Request,
    device_id: int,
    db: Session = Depends(get_db),
):
    admin_require(request)
    csrf_protect(request)

    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Not found")

    db.delete(device)
    db.commit()
    return _redirect("/admin/devices")


@router.post("/admin/devices/delete-pending")
@rate_limit("admin_device_delete_all_pending")
def admin_devices_delete_pending(
    request: Request,
    db: Session = Depends(get_db),
):
    """Hromadné smazání všech čekajících instancí."""
    admin_require(request)
    csrf_protect(request)

    pending = db.scalars(select(Device).where(Device.status == DeviceStatus.PENDING)).all()
    if pending:
        for d in pending:
            db.delete(d)
        db.commit()

    return _redirect("/admin/devices")


@router.get("/admin/profile", response_class=HTMLResponse)
def admin_profile_page(request: Request):
    admin_require(request)
    return templates.TemplateResponse(
        "admin_profile.html",
        {
            **_base_ctx(request, active_nav="profile", hide_shell=True, show_splash=True),
        },
    )


@router.post("/admin/profile/password")
@rate_limit("admin_change_password")
def admin_profile_change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    admin_require(request)
    csrf_protect(request)

    if new_password != new_password_confirm:
        return templates.TemplateResponse(
            "admin_profile.html",
            {
                **_base_ctx(
                    request,
                    settings=settings,
                    active_nav="profile",
                    show_splash=True,
                    hide_shell=True,
                    flash={"type": "error", "message": "Potvrzení hesla nesouhlasí."},
                ),
            },
            status_code=400,
        )

    try:
        admin_change_password(
            current_password=current_password,
            new_password=new_password,
            db=db,
            settings=settings,
        )
    except HTTPException as e:
        return templates.TemplateResponse(
            "admin_profile.html",
            {
                **_base_ctx(
                    request,
                    settings=settings,
                    active_nav="profile",
                    show_splash=True,
                    hide_shell=True,
                    flash={"type": "error", "message": str(e.detail)},
                ),
            },
            status_code=e.status_code,
        )

    return templates.TemplateResponse(
        "admin_profile.html",
        {
            **_base_ctx(
                request,
                settings=settings,
                active_nav="profile",
                show_splash=True,
                hide_shell=True,
                flash={"type": "success", "message": "Heslo bylo změněno."},
            ),
        },
    )


@router.get("/admin/media/{photo_id}/{kind}")
def admin_media(
    request: Request,
    photo_id: int,
    kind: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    admin_require(request)

    if kind not in {"thumb", "original"}:
        raise HTTPException(status_code=400, detail="Invalid kind")

    photo = db.get(ReportPhoto, photo_id)
    if not photo:
        raise HTTPException(status_code=404, detail="Not found")

    orig, thumb = get_media_paths_for_photo(settings=settings, photo=photo)
    path = thumb if kind == "thumb" else orig
    if not path.exists():
        # Pokud chybí thumbnail, ale originál máme, zkusíme ho vygenerovat na místě
        if kind == "thumb" and orig.exists():
            try:
                thumb.parent.mkdir(parents=True, exist_ok=True)
                with Image.open(orig) as img:
                    img.load()
                    if img.mode not in ("RGB", "L"):
                        img = img.convert("RGB")
                    elif img.mode == "L":
                        img = img.convert("RGB")
                    img.thumbnail((480, 480), Image.Resampling.LANCZOS)
                    img.save(thumb, format="JPEG", quality=75, optimize=True, progressive=True)
                path = thumb
            except Exception:
                # fallback na původní 404 pokud generování selže
                path = thumb
        if not path.exists():
            raise HTTPException(status_code=404, detail="File missing")

    return FileResponse(path=path)
