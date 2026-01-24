from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


class CsrfError(HTTPException):
    def __init__(self, detail: str = "CSRF validation failed") -> None:
        super().__init__(status_code=403, detail=detail)


@dataclass(frozen=True)
class CsrfConfig:
    # NOTE: These defaults are intentionally strict and production-oriented.
    cookie_name: str = "hotel_csrf"
    header_name: str = "x-csrf-token"
    form_field: str = "csrf_token"
    ttl_seconds: int = 2 * 60 * 60  # 2 hours
    cookie_path: str = "/"
    # SameSite must be Lax/Strict; None would require third-party contexts.
    cookie_samesite: str = "Lax"


def _now() -> int:
    return int(time.time())


def _make_token() -> str:
    # 256-bit random token
    return secrets.token_urlsafe(32)


def set_csrf_cookie(
    response: Response,
    *,
    token: str,
    cfg: CsrfConfig,
    secure: bool,
) -> None:
    """Set CSRF cookie.

    We keep the CSRF token in a non-HttpOnly cookie so that HTMX/JS can read it
    and send it back in a header or form field.

    Admin session remains HttpOnly; CSRF token is a separate cookie.
    """
    response.set_cookie(
        key=cfg.cookie_name,
        value=token,
        max_age=cfg.ttl_seconds,
        expires=cfg.ttl_seconds,
        path=cfg.cookie_path,
        secure=secure,
        httponly=False,
        samesite=cfg.cookie_samesite,
    )


def clear_csrf_cookie(response: Response, *, cfg: CsrfConfig, secure: bool) -> None:
    response.delete_cookie(
        key=cfg.cookie_name,
        path=cfg.cookie_path,
        secure=secure,
        samesite=cfg.cookie_samesite,
    )


def issue_csrf_token(response: Response, *, cfg: CsrfConfig, secure: bool) -> str:
    token = _make_token()
    set_csrf_cookie(response, token=token, cfg=cfg, secure=secure)
    return token


def _get_cookie_token(request: Request, cfg: CsrfConfig) -> Optional[str]:
    return request.cookies.get(cfg.cookie_name)


def _get_presented_token(request: Request, cfg: CsrfConfig) -> Optional[str]:
    # Prefer header (HTMX supports adding headers), fallback to form field.
    hdr = request.headers.get(cfg.header_name)
    if hdr:
        return hdr.strip()

    # For form-encoded POSTs
    # NOTE: reading form is async; this function is sync by design.
    return None


async def verify_csrf(request: Request, *, cfg: CsrfConfig) -> None:
    """Verify CSRF for unsafe methods.

    Policy:
    - Only required for POST/PUT/PATCH/DELETE.
    - Require token in cookie AND in header or form field.
    - Tokens must match exactly.

    This is intentionally simple and robust.
    """
    if request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
        return

    cookie_token = _get_cookie_token(request, cfg)
    if not cookie_token:
        raise CsrfError("Missing CSRF cookie")

    presented = request.headers.get(cfg.header_name)
    if presented:
        presented_token = presented.strip()
    else:
        # Try form field
        try:
            form = await request.form()
        except Exception:
            form = None
        presented_token = None
        if form is not None:
            v = form.get(cfg.form_field)
            if isinstance(v, str):
                presented_token = v.strip()

    if not presented_token:
        raise CsrfError("Missing CSRF token")

    # Constant-time compare
    if not secrets.compare_digest(cookie_token, presented_token):
        raise CsrfError("Invalid CSRF token")


def ensure_csrf_cookie(request: Request, response: Response, *, cfg: CsrfConfig, secure: bool) -> str:
    """Ensure a CSRF cookie exists; if not, issue a new one.

    Designed for GET handlers rendering admin pages (Jinja templates):
    call this and embed the returned token into hidden fields.
    """
    token = _get_cookie_token(request, cfg)
    if token:
        return token

    return issue_csrf_token(response, cfg=cfg, secure=secure)


class CSRFMiddleware(BaseHTTPMiddleware):
    """Simple middleware to enforce double-submit CSRF for state-changing requests."""

    def __init__(self, app, cfg: CsrfConfig | None = None, secure: bool = True):
        super().__init__(app)
        self.cfg = cfg or CsrfConfig()
        self.secure = secure

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        # CSRF is required only for browser-admin cookie-auth routes.
        # Android/device API calls are token/header-based and must not be blocked by CSRF.
        enforce = request.url.path.startswith("/admin")

        # Ensure a deterministic token is available for templates.
        token = request.cookies.get(self.cfg.cookie_name)
        if not token:
            token = _make_token()
        request.state.csrf_token = token

        if enforce and request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            # IMPORTANT:
            # - BaseHTTPMiddleware cannot safely consume the request body without replaying it.
            # - We therefore verify CSRF using the header when present, otherwise we parse the
            #   URL-encoded form body and then replay it for downstream Form(...) parsing.
            cookie_token = _get_cookie_token(request, self.cfg)
            if not cookie_token:
                return JSONResponse(status_code=403, content={"detail": "Missing CSRF cookie"})

            presented = request.headers.get(self.cfg.header_name)
            body_bytes: bytes | None = None
            if presented:
                presented_token = presented.strip()
            else:
                body_bytes = await request.body()
                presented_token: Optional[str] = None

                ct = (request.headers.get("content-type") or "").lower()
                if "application/x-www-form-urlencoded" in ct:
                    try:
                        parsed = parse_qs(body_bytes.decode("utf-8"), keep_blank_values=True)
                        vals = parsed.get(self.cfg.form_field) or []
                        if vals and isinstance(vals[0], str):
                            presented_token = vals[0].strip() or None
                    except Exception:
                        presented_token = None

            if not presented_token:
                return JSONResponse(status_code=403, content={"detail": "Missing CSRF token"})

            if not secrets.compare_digest(cookie_token, presented_token):
                return JSONResponse(status_code=403, content={"detail": "Invalid CSRF token"})

            # Replay consumed body for downstream handlers.
            if body_bytes is not None:
                async def _receive():
                    nonlocal body_bytes
                    if body_bytes is None:
                        return {"type": "http.request", "body": b"", "more_body": False}
                    b = body_bytes
                    body_bytes = None
                    return {"type": "http.request", "body": b, "more_body": False}

                request = Request(request.scope, _receive)
                request.state.csrf_token = token

        response = await call_next(request)

        # Ensure token cookie exists for subsequent POSTs and keep token stable within TTL.
        if enforce and not request.cookies.get(self.cfg.cookie_name):
            set_csrf_cookie(response, token=token, cfg=self.cfg, secure=self.secure)

        return response


# Legacy helpers expected by routes
def csrf_protect(request: Request) -> None:
    # Middleware handles CSRF; this placeholder keeps sync routes readable.
    return None


def csrf_token_ensure(request: Request, response: Optional[Response] = None) -> str:
    token = getattr(request.state, "csrf_token", None)
    if token:
        return token

    resp = response or Response()
    token = ensure_csrf_cookie(request, resp, cfg=CsrfConfig(), secure=True)
    request.state.csrf_token = token
    return token
