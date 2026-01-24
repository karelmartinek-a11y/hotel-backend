from __future__ import annotations

from dataclasses import dataclass
from typing import Generator, Optional

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import models
from app.db.session import SessionLocal
from app.security.device_crypto import compute_device_token_hash


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_client_ip(request: Request) -> str:
    # Trust Nginx to pass X-Forwarded-For; take the left-most as original client.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def require_admin_session(request: Request, settings: Settings = Depends(get_settings)) -> None:
    # Admin session is stored server-side by Starlette SessionMiddleware.
    # We use a single flag in the session.
    if not request.session.get("admin_logged_in"):
        raise HTTPException(status_code=401, detail="ADMIN_NOT_AUTHENTICATED")


def require_csrf(request: Request, x_csrf_token: Optional[str] = Header(default=None)) -> None:
    # CSRF strategy:
    # - backend sets a per-session csrf_token in session and also exposes it to templates.
    # - HTMX or JS sends it back in X-CSRF-Token header.
    expected = request.session.get("csrf_token")
    if not expected:
        raise HTTPException(status_code=403, detail="CSRF_NOT_INITIALIZED")
    if not x_csrf_token or x_csrf_token != expected:
        raise HTTPException(status_code=403, detail="CSRF_INVALID")


@dataclass(frozen=True)
class Pagination:
    limit: int
    offset: int


def get_pagination(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> Pagination:
    # We accept query params: ?limit=..&offset=..
    # Hard bounds to keep admin UI snappy and to protect the DB.
    qp = request.query_params
    try:
        limit = int(qp.get("limit", str(settings.admin_list_default_limit)))
        offset = int(qp.get("offset", "0"))
    except ValueError:
        raise HTTPException(status_code=400, detail="PAGINATION_INVALID")

    if limit < 1:
        limit = 1
    if limit > settings.admin_list_max_limit:
        limit = settings.admin_list_max_limit
    if offset < 0:
        offset = 0

    return Pagination(limit=limit, offset=offset)


def require_device_token(
    request: Request,
    x_device_token: Optional[str] = Header(default=None, alias="X-Device-Token"),
    authorization: Optional[str] = Header(default=None),
) -> str:
    # Android auth: device token (issued after activation) must be provided.
    # Prefer X-Device-Token for simple clients; also allow Bearer for flexibility.
    token = None
    if x_device_token:
        token = x_device_token.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()

    if not token:
        raise HTTPException(status_code=401, detail="DEVICE_TOKEN_MISSING")

    # Basic sanity checks (real verification is done in routes using DB).
    if len(token) < 24 or len(token) > 256:
        raise HTTPException(status_code=401, detail="DEVICE_TOKEN_INVALID")

    return token


@dataclass(frozen=True)
class DeviceAuthContext:
    token: str
    client_ip: str


def get_device_auth_context(
    request: Request,
    token: str = Depends(require_device_token),
) -> DeviceAuthContext:
    return DeviceAuthContext(token=token, client_ip=get_client_ip(request))


def require_device(
    request: Request,
    x_device_token: Optional[str] = Header(default=None, alias="X-Device-Token"),
    x_device_id: Optional[str] = Header(default=None, alias="X-Device-Id"),
    x_device_name: Optional[str] = Header(default=None, alias="X-Device-Name"),
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> models.Device:
    """Resolve an ACTIVE device.

    Preferred auth:
    - X-Device-Token or Authorization: Bearer <token>

    Compatibility fallback (used by older Android builds):
    - X-Device-Id (not a secret; allowed only if device is ACTIVE)
    """

    token = None
    if x_device_token:
        token = x_device_token.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()

    if token:
        hashed = compute_device_token_hash(token)
        device = db.execute(select(models.Device).where(models.Device.token_hash == hashed)).scalar_one_or_none()
        if device is None or device.status != models.DeviceStatus.ACTIVE:
            raise HTTPException(status_code=401, detail="DEVICE_TOKEN_INVALID")
        _maybe_update_display_name(db, device, x_device_name)
        return device

    if x_device_id:
        device = db.execute(select(models.Device).where(models.Device.device_id == x_device_id)).scalar_one_or_none()
        if device is None:
            raise HTTPException(status_code=401, detail="DEVICE_NOT_REGISTERED")
        if device.status != models.DeviceStatus.ACTIVE:
            raise HTTPException(status_code=403, detail="DEVICE_NOT_ACTIVE")
        _maybe_update_display_name(db, device, x_device_name)
        return device

    raise HTTPException(status_code=401, detail="DEVICE_AUTH_MISSING")


def _maybe_update_display_name(db: Session, device: models.Device, raw_name: Optional[str]) -> None:
    if not raw_name:
        return
    name = raw_name.strip()
    if not name or name == device.display_name:
        return
    device.display_name = name
    db.add(device)
    try:
        db.commit()
    except Exception:
        db.rollback()
