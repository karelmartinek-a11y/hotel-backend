from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Callable
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response

from app.api.breakfast import router as breakfast_api_router
from app.api.device import router as device_api_router
from app.api.reports import router as reports_api_router
from app.config import settings
from app.security.admin_auth import AdminAuthError, require_admin_for_media
from app.security.csrf import CsrfConfig, CSRFMiddleware
from app.security.rate_limit import RateLimitMiddleware
from app.services.breakfast.scheduler import breakfast_fetch_loop
from app.web.routes import router as web_router
from app.web.routes_admin import router as admin_breakfast_router


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Start background breakfast fetch loop.
        # It is time-window guarded (default 02:00–03:00) and retries every 5 minutes on failure.
        task = asyncio.create_task(breakfast_fetch_loop())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(Exception):
                await task

    app = FastAPI(
        title="ASC Hotel Chodov",
        version=settings.APP_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    # If you need cross-origin (e.g. admin behind same domain), keep strict.
    # We primarily serve same-origin via Nginx vhost hotel.hcasc.cz.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://hotel.hcasc.cz"],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-CSRF-Token", "Authorization"],
    )

    # Server-side session cookie for admin web.
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.SESSION_SECRET,
        session_cookie=settings.SESSION_COOKIE_NAME,
        https_only=True,
        same_site="lax",
        max_age=settings.SESSION_MAX_AGE_SECONDS,
    )

    # CSRF protection for admin web actions (POST) and any cookie-auth endpoints.
    app.add_middleware(
        CSRFMiddleware,
        cfg=CsrfConfig(cookie_samesite="none"),
        secure=True,
    )

    # Rate limiting (admin login, device polling/challenge/verify, uploads, etc.)
    app.add_middleware(RateLimitMiddleware)

    # Static assets for server-rendered admin/public web
    app.mount("/static", StaticFiles(directory="app/web/static"), name="static")

    # Routers
    app.include_router(web_router)
    # Canonical API base path is /api; keep /api/v1 as a compatibility alias.
    app.include_router(device_api_router, prefix="/api")
    app.include_router(reports_api_router, prefix="/api")
    app.include_router(device_api_router, prefix="/api/v1")
    app.include_router(reports_api_router, prefix="/api/v1")
    app.include_router(breakfast_api_router, prefix="/api")
    app.include_router(admin_breakfast_router)

    @app.get("/api/health")
    async def health() -> dict:
        return {
            "ok": True,
            "app": "hotel",
            "time": int(time.time()),
        }

    @app.get("/api/version")
    async def version() -> dict:
        return {
            "backend_deploy_tag": settings.deploy_tag,
            "environment": settings.environment,
            "version": settings.APP_VERSION,
        }

    @app.get("/api/v1/health")
    async def health_v1() -> dict:
        return await health()

    @app.get("/api/internal/media-auth")
    async def media_auth(_: Request, __: None = Depends(require_admin_for_media)) -> Response:
        # Used by Nginx auth_request to protect /media/ (must return 2xx or 401/403).
        return Response(status_code=204)

    @app.exception_handler(AdminAuthError)
    async def admin_auth_exception_handler(request: Request, exc: AdminAuthError) -> Response:
        if request.url.path.startswith("/admin"):
            return RedirectResponse("/admin/login", status_code=303)
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(HTTPException)
    async def http_exception_handler_custom(request: Request, exc: HTTPException) -> Response:
        if exc.detail == "Not authenticated" and request.url.path.startswith("/admin"):
            return RedirectResponse("/admin/login", status_code=303)
        return await http_exception_handler(request, exc)

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
        # Avoid leaking internals. Log details in app logging (configured elsewhere).
        # NOTE: We intentionally keep payload generic. For /admin/login diagnostics we include
        # only exception type (no message/traceback) to help debug production issues.
        extra: dict[str, str] | None = None
        if request.url.path == "/admin/login":
            extra = {"type": type(exc).__name__}
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "Internal server error",
                    **(extra or {}),
                }
            },
        )

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable):
        resp = await call_next(request)
        # Security headers should primarily be set by Nginx, but we add a safe baseline here too.
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
        return resp

    return app


app = create_app()
