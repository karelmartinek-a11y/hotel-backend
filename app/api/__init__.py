"""HOTEL backend API package.

This package groups all JSON API routers under /api.
Web (Jinja2/HTMX) routes live under app.web.
"""

from fastapi import APIRouter

from .breakfast import router as breakfast_router
from .device import router as device_router
from .reports import router as reports_router

api_router = APIRouter()

# Device lifecycle (register/status/challenge/verify)
api_router.include_router(device_router, prefix="/v1", tags=["device"])

# Reports CRUD/workflow + polling new-since
api_router.include_router(reports_router, prefix="/v1", tags=["reports"])

# Breakfast workflow (Better Hotel import + check)
api_router.include_router(breakfast_router, prefix="")
