from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, date, datetime, timedelta
from typing import Any
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from PIL import Image
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.models import (
    HistoryActorType,
    InventoryIngredient,
    InventoryUnit,
    PortalSmtpSettings,
    PortalUser,
    PortalUserResetToken,
    PortalUserRole,
    Report,
    ReportHistory,
    ReportHistoryAction,
    ReportPhoto,
    ReportStatus,
    ReportType,
    StockCard,
    StockCardLine,
    StockCardType,
)
from ..db.session import get_db
from ..media.inventory_storage import get_inventory_media_root
from ..media.storage import MediaStorage, get_media_paths_for_photo
from ..security.admin_auth import (
    ADMIN_USERNAME,
    AdminAuthError,
    admin_change_password,
    admin_login_check,
    admin_logout,
    admin_require,
    admin_session_is_authenticated,
    hash_password,
    set_admin_session,
    verify_password,
)
from ..security.crypto import Crypto
from ..security.csrf import csrf_protect, csrf_token_ensure
from ..security.rate_limit import rate_limit
from ..security.user_auth import clear_user_session, get_user_session, set_user_session

router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")

TZ_LOCAL = ZoneInfo("Europe/Prague")

ROOMS_ALLOWED = (
    [*range(101, 110)] +
    [*range(201, 211)] +
    [*range(301, 311)]
)

PORTAL_ROLE_LABELS: dict[PortalUserRole, str] = {
    PortalUserRole.HOUSEKEEPING: "Pokojská",
    PortalUserRole.FRONTDESK: "Recepce",
    PortalUserRole.MAINTENANCE: "Údržba",
    PortalUserRole.BREAKFAST: "Snídaně",
}


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _fmt_dt(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
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


def _portal_session_user(request: Request, db: Session, settings: Settings) -> PortalUser | None:
    sess = get_user_session(request, settings=settings)
    if not sess.authenticated or not sess.user_id:
        return None
    user = db.get(PortalUser, int(sess.user_id))
    if not user or not user.is_active:
        return None
    return user


def _require_portal_user(request: Request, db: Session, settings: Settings) -> PortalUser:
    user = _portal_session_user(request, db, settings)
    if not user:
        raise HTTPException(status_code=401, detail="Login required")
    return user


def _authenticate_portal_user(email: str, password: str, db: Session) -> PortalUser | None:
    email_norm = (email or "").strip().lower()
    if not email_norm or not password:
        return None
    user = db.scalar(select(PortalUser).where(PortalUser.email == email_norm))
    if not user or not user.is_active or not user.password_hash:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def _ensure_smtp_settings(db: Session) -> PortalSmtpSettings:
    cfg = db.scalar(select(PortalSmtpSettings).order_by(PortalSmtpSettings.id.asc()))
    if cfg is None:
        cfg = PortalSmtpSettings()
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _smtp_password(cfg: PortalSmtpSettings, settings: Settings) -> str | None:
    if not cfg.password_enc:
        return None
    if not settings.crypto_secret:
        return None
    crypto = Crypto.from_secret(settings.crypto_secret)
    try:
        return crypto.decrypt_str(cfg.password_enc)
    except Exception:
        return None


def _send_reset_email(*, settings: Settings, cfg: PortalSmtpSettings, to_email: str, reset_url: str) -> None:
    import smtplib
    from email.message import EmailMessage

    host = (cfg.host or "").strip()
    if not host or not cfg.port:
        raise ValueError("SMTP není nastaveno.")
    username = (cfg.username or "").strip()
    password = _smtp_password(cfg, settings) if cfg.password_enc else None
    security = (cfg.security or "SSL").strip().upper()
    from_email = (cfg.from_email or username or "").strip()
    if not from_email:
        raise ValueError("Chybí odesílací e-mail.")

    msg = EmailMessage()
    msg["Subject"] = "Nastavení nebo změna hesla"
    msg["From"] = f"{cfg.from_name} <{from_email}>" if cfg.from_name else from_email
    msg["To"] = to_email
    msg.set_content(
        
            "Dobrý den,\n\n"
            "pro nastavení nebo změnu hesla použijte tento odkaz (platnost 24 hodin):\n\n"
            f"{reset_url}\n\n"
            "Pokud jste o změnu nežádali, ignorujte tento e-mail."
        
    )

    server: smtplib.SMTP
    if security == "SSL":
        server = smtplib.SMTP_SSL(host, int(cfg.port), timeout=20)
    else:
        server = smtplib.SMTP(host, int(cfg.port), timeout=20)
        if security == "STARTTLS":
            server.starttls()

    try:
        if username and password:
            server.login(username, password)
        server.send_message(msg)
    finally:
        server.quit()


@router.get("/", response_class=HTMLResponse)
def public_landing(request: Request, settings: Settings = Depends(Settings.from_env)):
    return _redirect("/login")


@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    if not admin_session_is_authenticated(request):
        return _redirect("/admin/login")

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


@router.get("/login", response_class=HTMLResponse)
def portal_login_page(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(Settings.from_env)):
    if _portal_session_user(request, db, settings):
        return _redirect("/portal")
    flash = request.session.pop("flash", None) if hasattr(request, "session") else None
    return templates.TemplateResponse(
        "portal_login.html",
        {
            **_base_ctx(request, settings=settings, hide_shell=True, show_splash=True, flash=flash),
        },
    )


@router.post("/login")
@rate_limit("user_login")
def portal_login_action(
    request: Request,
    email: str = Form(""),
    password: str = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    csrf_protect(request)
    user = _authenticate_portal_user(email=email, password=password, db=db)
    if not user:
        return templates.TemplateResponse(
            "portal_login.html",
            {
                **_base_ctx(request, settings=settings, hide_shell=True, show_splash=True),
                "error": "Neplatné přihlašovací údaje",
            },
            status_code=401,
        )
    resp = _redirect("/portal")
    set_user_session(resp, settings=settings, user_id=user.id, ttl_minutes=settings.user_session_ttl_minutes)
    return resp


@router.get("/login/forgot", response_class=HTMLResponse)
def portal_forgot_page(request: Request, settings: Settings = Depends(Settings.from_env)):
    flash = request.session.pop("flash", None) if hasattr(request, "session") else None
    return templates.TemplateResponse(
        "portal_forgot.html",
        {
            **_base_ctx(request, settings=settings, hide_shell=True, show_splash=True, flash=flash),
        },
    )


@router.post("/login/forgot")
@rate_limit("user_forgot")
def portal_forgot_action(
    request: Request,
    email: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    csrf_protect(request)
    email_norm = (email or "").strip().lower()
    user = db.scalar(select(PortalUser).where(PortalUser.email == email_norm, PortalUser.is_active.is_(True)))
    if not user:
        request.session["flash"] = {"type": "error", "message": "Uživatel nenalezen."}
        return _redirect("/login/forgot")

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = _now() + timedelta(hours=RESET_TOKEN_TTL_HOURS)

    row = PortalUserResetToken(user_id=user.id, token_hash=token_hash, expires_at=expires_at)
    db.add(row)
    db.commit()

    reset_url = f"{settings.public_base_url}/login/reset?token={raw_token}"
    try:
        cfg = _ensure_smtp_settings(db)
        _send_reset_email(settings=settings, cfg=cfg, to_email=user.email, reset_url=reset_url)
    except Exception as exc:
        request.session["flash"] = {"type": "error", "message": f"Odeslání selhalo: {exc}"}
        return _redirect("/login/forgot")

    request.session["flash"] = {"type": "success", "message": "Odkaz byl odeslán na e-mail."}
    return _redirect("/login")


def _reset_token_row(raw_token: str, db: Session) -> PortalUserResetToken | None:
    if not raw_token:
        return None
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    row = db.scalar(
        select(PortalUserResetToken).where(
            PortalUserResetToken.token_hash == token_hash,
            PortalUserResetToken.expires_at >= _now(),
        )
    )
    return row


@router.get("/login/reset", response_class=HTMLResponse)
def portal_reset_page(
    request: Request,
    token: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    row = _reset_token_row(token, db)
    if not row:
        request.session["flash"] = {"type": "error", "message": "Neplatný nebo expirovaný odkaz."}
        return _redirect("/login")
    return templates.TemplateResponse(
        "portal_reset.html",
        {
            **_base_ctx(request, settings=settings, hide_shell=True, show_splash=True),
            "token": token,
        },
    )


@router.post("/login/reset")
def portal_reset_action(
    request: Request,
    token: str = Form(""),
    password: str = Form(""),
    password_confirm: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    csrf_protect(request)
    row = _reset_token_row(token, db)
    if not row:
        request.session["flash"] = {"type": "error", "message": "Neplatný nebo expirovaný odkaz."}
        return _redirect("/login")

    if password != password_confirm:
        request.session["flash"] = {"type": "error", "message": "Hesla se neshodují."}
        return _redirect(f"/login/reset?token={token}")

    try:
        new_hash = hash_password(password)
    except Exception as exc:
        request.session["flash"] = {"type": "error", "message": str(exc)}
        return _redirect(f"/login/reset?token={token}")

    user = db.get(PortalUser, row.user_id)
    if not user or not user.is_active:
        request.session["flash"] = {"type": "error", "message": "Uživatel nenalezen."}
        return _redirect("/login")

    user.password_hash = new_hash
    db.add(user)
    db.commit()

    # Clean up all reset tokens for this user
    db.execute(delete(PortalUserResetToken).where(PortalUserResetToken.user_id == user.id))
    db.commit()

    resp = _redirect("/portal")
    set_user_session(resp, settings=settings, user_id=user.id, ttl_minutes=settings.user_session_ttl_minutes)
    return resp


@router.post("/logout")
def portal_logout(request: Request, settings: Settings = Depends(Settings.from_env)):
    csrf_protect(request)
    resp = _redirect("/login")
    clear_user_session(resp, settings=settings)
    return resp


@router.get("/portal", response_class=HTMLResponse)
def portal_home(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    user = _portal_session_user(request, db, settings)
    if not user:
        return _redirect("/login")
    return templates.TemplateResponse(
        "portal_home.html",
        {
            **_base_ctx(request, settings=settings, active_nav="portal", hide_shell=True),
            "user": {"name": user.name, "email": user.email, "role": PORTAL_ROLE_LABELS.get(user.role, user.role.value)},
        },
    )


@router.post("/admin/login")
@rate_limit("admin_login")
def admin_login_action(
    request: Request,
    username: str = Form(""),
    password: str = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    csrf_protect(request)
    if not admin_login_check(username=username, password=password, db=db, settings=settings):
        return templates.TemplateResponse(
            "admin_login.html",
            {
                **_base_ctx(request, settings=settings, hide_shell=True, show_splash=True),
                "error": "Neplatné přihlašovací údaje",
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
    category: str | None = None,
    status: str | None = None,
    room: int | None = None,
    date: str | None = None,
    sort: str = "created_desc",
    page: int = 1,
    per_page: int = 25,
    type: str | None = None,
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
        start = datetime(day.year, day.month, day.day, tzinfo=UTC)
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

    created_by = report.created_by_device.device_id

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


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    if not admin_session_is_authenticated(request):
        return _redirect("/admin/login")

    users = db.scalars(select(PortalUser).order_by(PortalUser.name.asc())).all()
    role_options = [
        {"value": role.value, "label": PORTAL_ROLE_LABELS.get(role, role.value)}
        for role in PortalUserRole
    ]
    user_rows = [
        {
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "role_label": PORTAL_ROLE_LABELS.get(u.role, u.role.value),
            "has_password": bool(u.password_hash),
        }
        for u in users
    ]

    flash = request.session.pop("flash", None) if hasattr(request, "session") else None
    return templates.TemplateResponse(
        "admin_users.html",
        {
            **_base_ctx(request, settings=settings, active_nav="users", flash=flash),
            "role_options": role_options,
            "users": user_rows,
            "csrf_token": csrf_token_ensure(request),
        },
    )


@router.post("/admin/users/create")
def admin_users_create(
    request: Request,
    name: str = Form(""),
    email: str = Form(""),
    role: str = Form(""),
    db: Session = Depends(get_db),
):
    try:
        admin_require(request)
        csrf_protect(request)
    except AdminAuthError:
        return _redirect("/admin/login")

    name = (name or "").strip()
    email_norm = (email or "").strip().lower()
    if not name or not email_norm:
        request.session["flash"] = {"type": "error", "message": "Jméno a e-mail jsou povinné."}
        return _redirect("/admin/users")
    if email_norm == ADMIN_USERNAME:
        request.session["flash"] = {"type": "error", "message": "Tento e-mail je vyhrazen pro admin účet."}
        return _redirect("/admin/users")

    try:
        role_enum = PortalUserRole(role)
    except Exception:
        request.session["flash"] = {"type": "error", "message": "Neplatný druh pohledu."}
        return _redirect("/admin/users")

    exists = db.scalar(select(PortalUser).where(PortalUser.email == email_norm))
    if exists:
        request.session["flash"] = {"type": "error", "message": "Uživatel s tímto e‑mailem už existuje."}
        return _redirect("/admin/users")

    user = PortalUser(name=name, email=email_norm, role=role_enum, password_hash=None)
    db.add(user)
    db.commit()

    request.session["flash"] = {"type": "success", "message": "Uživatel vytvořen."}
    return _redirect("/admin/users")


@router.post("/admin/users/{user_id}/send-reset")
def admin_users_send_reset(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    try:
        admin_require(request)
        csrf_protect(request)
    except AdminAuthError:
        return _redirect("/admin/login")

    user = db.get(PortalUser, int(user_id))
    if not user or not user.is_active:
        request.session["flash"] = {"type": "error", "message": "Uživatel nenalezen."}
        return _redirect("/admin/users")

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = _now() + timedelta(hours=RESET_TOKEN_TTL_HOURS)

    row = PortalUserResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(row)
    db.commit()

    reset_url = f"{settings.public_base_url}/login/reset?token={raw_token}"
    try:
        cfg = _ensure_smtp_settings(db)
        _send_reset_email(settings=settings, cfg=cfg, to_email=user.email, reset_url=reset_url)
    except Exception as exc:
        request.session["flash"] = {"type": "error", "message": f"Odeslání selhalo: {exc}"}
        return _redirect("/admin/users")

    request.session["flash"] = {"type": "success", "message": "Odkaz odeslán."}
    return _redirect("/admin/users")


@router.get("/admin/settings", response_class=HTMLResponse)
def admin_settings_page(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    if not admin_session_is_authenticated(request):
        return _redirect("/admin/login")
    cfg = _ensure_smtp_settings(db)
    flash = request.session.pop("flash", None) if hasattr(request, "session") else None
    return templates.TemplateResponse(
        "admin_settings.html",
        {
            **_base_ctx(request, settings=settings, active_nav="settings", flash=flash),
            "smtp": cfg,
            "csrf_token": csrf_token_ensure(request),
        },
    )


@router.post("/admin/settings/smtp")
def admin_settings_smtp_save(
    request: Request,
    host: str = Form(""),
    port: int = Form(0),
    security: str = Form("SSL"),
    username: str = Form(""),
    password: str = Form(""),
    from_email: str = Form(""),
    from_name: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(Settings.from_env),
):
    try:
        admin_require(request)
        csrf_protect(request)
    except AdminAuthError:
        return _redirect("/admin/login")

    cfg = _ensure_smtp_settings(db)
    cfg.host = (host or "").strip() or None
    cfg.port = int(port or 0) or None
    cfg.security = (security or "SSL").strip().upper()
    cfg.username = (username or "").strip() or None
    cfg.from_email = (from_email or "").strip() or None
    cfg.from_name = (from_name or "").strip() or None

    if password:
        if not settings.crypto_secret:
            request.session["flash"] = {
                "type": "error",
                "message": "CRYPTO_SECRET není nastaven, heslo nelze uložit šifrovaně.",
            }
            return _redirect("/admin/settings")
        crypto = Crypto.from_secret(settings.crypto_secret)
        cfg.password_enc = crypto.encrypt_str(password)

    cfg.updated_at = _now()
    db.add(cfg)
    db.commit()

    request.session["flash"] = {"type": "success", "message": "Uloženo."}
    return _redirect("/admin/settings")


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
                    work_img: Image.Image = img
                    if work_img.mode != "RGB":
                        work_img = work_img.convert("RGB")
                    work_img.thumbnail((480, 480), Image.Resampling.LANCZOS)
                    work_img.save(thumb, format="JPEG", quality=75, optimize=True, progressive=True)
                path = thumb
            except Exception:
                # fallback na původní 404 pokud generování selže
                path = thumb
        if not path.exists():
            raise HTTPException(status_code=404, detail="File missing")

    return FileResponse(path=path)
