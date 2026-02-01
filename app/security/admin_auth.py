from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from fastapi import HTTPException, Request, Response
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..db.models import AdminSingleton

# HOTEL constraint: single admin password (no accounts)
# We store only a password hash (argon2/bcrypt) and use server-side session cookie.

pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
)


class AdminAuthError(HTTPException):
    def __init__(self, status_code: int = 401, detail: str = "Not authenticated"):
        super().__init__(status_code=status_code, detail=detail)


@dataclass(frozen=True)
class AdminSession:
    authenticated: bool
    authenticated_at: datetime


def _utcnow() -> datetime:
    return datetime.now(UTC)


def verify_password(plain_password: str, password_hash: str) -> bool:
    if not plain_password or not password_hash:
        return False
    try:
        return bool(pwd_context.verify(plain_password, password_hash))
    except Exception:
        return False


def hash_password(plain_password: str) -> str:
    if not plain_password or len(plain_password) < 10:
        # Keep deterministic: enforce minimal length to avoid weak admin password.
        raise ValueError("Admin password must be at least 10 characters")
    return cast(str, pwd_context.hash(plain_password))


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _cookie_settings(settings: Settings) -> dict:
    # Cookie settings required by spec: HttpOnly, Secure, SameSite.
    # SameSite: Lax is a safe baseline for admin forms; Strict may break some flows.
    return {
        "httponly": True,
        "secure": settings.session_cookie_secure,
        "samesite": settings.session_cookie_samesite,
        "path": "/",
        # no explicit domain: binds to host (hotel.hcasc.cz)
    }


def set_admin_session(response: Response, settings: Settings, *, ttl_minutes: int) -> None:
    expires_at = _utcnow() + timedelta(minutes=ttl_minutes)
    response.set_cookie(
        settings.admin_session_cookie_name,
        "1",
        max_age=ttl_minutes * 60,
        expires=int(expires_at.timestamp()),
        **_cookie_settings(settings),
    )
    response.set_cookie(
        settings.admin_session_issued_cookie_name,
        str(int(_utcnow().timestamp())),
        max_age=ttl_minutes * 60,
        expires=int(expires_at.timestamp()),
        **_cookie_settings(settings),
    )


def clear_admin_session(response: Response, settings: Settings) -> None:
    response.delete_cookie(settings.admin_session_cookie_name, path="/")
    response.delete_cookie(settings.admin_session_issued_cookie_name, path="/")


def get_admin_session(request: Request, settings: Settings) -> AdminSession:
    marker = request.cookies.get(settings.admin_session_cookie_name)
    issued = request.cookies.get(settings.admin_session_issued_cookie_name)

    if marker != "1" or not issued:
        return AdminSession(authenticated=False, authenticated_at=_utcnow())

    try:
        issued_ts = int(issued)
        issued_at = datetime.fromtimestamp(issued_ts, tz=UTC)
    except Exception:
        return AdminSession(authenticated=False, authenticated_at=_utcnow())

    # Hard max session age check (defense-in-depth). Cookie max-age is primary.
    if _utcnow() - issued_at > timedelta(minutes=settings.admin_session_ttl_minutes):
        return AdminSession(authenticated=False, authenticated_at=issued_at)

    return AdminSession(authenticated=True, authenticated_at=issued_at)


def require_admin(
    request: Request,
    settings: Settings | None = None,
) -> AdminSession:
    settings = settings or get_settings()
    sess = get_admin_session(request, settings)
    if not sess.authenticated:
        raise AdminAuthError()
    return sess


def admin_session_is_authenticated(request: Request) -> bool:
    return get_admin_session(request, get_settings()).authenticated


def admin_require(request: Request) -> None:
    if not admin_session_is_authenticated(request):
        raise AdminAuthError()


def admin_logout(request: Request, response: Response | None = None) -> Response:
    resp = response or Response()
    clear_admin_session(resp, get_settings())
    return resp


def _get_or_seed_admin_singleton(db: Session, settings: Settings) -> AdminSingleton:
    try:
        row = db.execute(select(AdminSingleton).limit(1)).scalar_one_or_none()
    except OperationalError as exc:
        # Gracefully bootstrap if the admin_singleton tabulka ještě neexistuje (např. po zapomenuté migraci).
        if "admin_singleton" in str(getattr(exc, "orig", exc)).lower():
            AdminSingleton.__table__.create(bind=db.get_bind(), checkfirst=True)
            row = db.execute(select(AdminSingleton).limit(1)).scalar_one_or_none()
        else:
            raise
    if row is not None:
        return row

    if not settings.admin_password_hash:
        raise HTTPException(status_code=500, detail="Admin password is not configured")

    row = AdminSingleton(password_hash=settings.admin_password_hash)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def admin_login_check(*, password: str, db: Session, settings: Settings) -> bool:
    authenticate_admin_password(password, db=db, settings=settings)
    return True


def admin_change_password(*, current_password: str, new_password: str, db: Session, settings: Settings) -> str:
    authenticate_admin_password(current_password, db=db, settings=settings)

    new_hash = change_admin_password(new_password=new_password, settings=settings)
    row = _get_or_seed_admin_singleton(db, settings)
    row.password_hash = new_hash
    db.add(row)
    db.commit()
    return new_hash


def require_admin_for_media(
    request: Request,
    settings: Settings | None = None,
) -> None:
    """Dependency used by media auth endpoints.

    For /media/ protection we typically use Nginx auth_request to a small endpoint
    that depends on this function. This must be fast and must not leak info.
    """
    settings = settings or get_settings()
    sess = get_admin_session(request, settings)
    if not sess.authenticated:
        raise AdminAuthError(status_code=401, detail="Admin session required")


def authenticate_admin_password(plain_password: str, *, db: Session, settings: Settings) -> None:
    """Raises on failure.

    We use a single stored hash from settings.
    """
    if not plain_password:
        raise AdminAuthError(status_code=400, detail="Password is required")

    row = _get_or_seed_admin_singleton(db, settings)

    if not verify_password(plain_password, row.password_hash):
        raise AdminAuthError(status_code=401, detail="Invalid password")


def change_admin_password(
    *,
    new_password: str,
    settings: Settings,
) -> str:
    """Returns new hash.

    The caller must persist it (e.g., in DB singleton row or env secret rotation).
    In this project we prefer DB persistence via an admin_singleton row, but the
    config still supports bootstrap from env.
    """
    try:
        return hash_password(new_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


def is_htmx(request: Request) -> bool:
    # HTMX sends HX-Request: true
    return (request.headers.get("HX-Request") or "").lower() == "true"


def ensure_admin_or_redirect(
    request: Request,
    settings: Settings,
) -> Response | None:
    """Helper for server-rendered routes.

    Returns a redirect Response to /admin/login when unauthenticated,
    otherwise returns None.
    """
    sess = get_admin_session(request, settings)
    if sess.authenticated:
        return None

    # For HTMX requests, return 401 so client can swap to login partial.
    if is_htmx(request):
        raise AdminAuthError(status_code=401, detail="Login required")

    from fastapi.responses import RedirectResponse

    return RedirectResponse(url="/admin/login", status_code=303)
