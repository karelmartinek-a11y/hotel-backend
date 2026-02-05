from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from ..config import Settings, get_settings


@dataclass(frozen=True)
class PortalUserSession:
    authenticated: bool
    user_id: int | None
    issued_at: datetime | None


def _serializer(settings: Settings) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.session_secret, salt="portal-user-session")


def _cookie_settings(settings: Settings) -> dict:
    return {
        "httponly": True,
        "secure": settings.session_cookie_secure,
        "samesite": settings.session_cookie_samesite,
        "path": "/",
    }


def set_user_session(response: Response, settings: Settings, *, user_id: int, ttl_minutes: int) -> None:
    ser = _serializer(settings)
    token = ser.dumps({"uid": user_id})
    expires_at = datetime.now(UTC) + timedelta(minutes=ttl_minutes)
    response.set_cookie(
        settings.user_session_cookie_name,
        token,
        max_age=ttl_minutes * 60,
        expires=int(expires_at.timestamp()),
        **_cookie_settings(settings),
    )


def clear_user_session(response: Response, settings: Settings) -> None:
    response.delete_cookie(settings.user_session_cookie_name, path="/")


def get_user_session(request: Request, settings: Settings | None = None) -> PortalUserSession:
    settings = settings or get_settings()
    token = request.cookies.get(settings.user_session_cookie_name)
    if not token:
        return PortalUserSession(authenticated=False, user_id=None, issued_at=None)

    ser = _serializer(settings)
    try:
        data = ser.loads(token, max_age=settings.user_session_ttl_minutes * 60)
    except SignatureExpired:
        return PortalUserSession(authenticated=False, user_id=None, issued_at=None)
    except BadSignature:
        return PortalUserSession(authenticated=False, user_id=None, issued_at=None)

    uid = data.get("uid") if isinstance(data, dict) else None
    if not isinstance(uid, int):
        return PortalUserSession(authenticated=False, user_id=None, issued_at=None)

    return PortalUserSession(authenticated=True, user_id=uid, issued_at=None)
