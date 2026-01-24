from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional, TypeVar, Awaitable

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


@dataclass(frozen=True)
class RateLimitRule:
    """Simple in-process (per-worker) rate limiting.

    Notes:
    - This is NOT a distributed rate limiter. With multiple gunicorn workers,
      limits apply per worker.
    - This is intentional here to avoid external dependencies and services.

    For production with multiple workers, tune limits conservatively.
    """

    key: str
    window_seconds: int
    max_requests: int


class _FixedWindowCounter:
    __slots__ = ("window_start", "count")

    def __init__(self) -> None:
        self.window_start = 0
        self.count = 0


class InProcessRateLimiter:
    """A tiny fixed-window limiter keyed by (rule.key, client_key).

    client_key should include IP and optionally a device id / username.
    """

    def __init__(self) -> None:
        self._data: dict[str, _FixedWindowCounter] = {}

    def hit(self, *, bucket: str, window_seconds: int, max_requests: int) -> bool:
        now = int(time.time())
        c = self._data.get(bucket)
        if c is None:
            c = _FixedWindowCounter()
            self._data[bucket] = c

        # roll window
        if now - c.window_start >= window_seconds:
            c.window_start = now
            c.count = 0

        c.count += 1
        return c.count <= max_requests

    def limit(self, rule: RateLimitRule | str):
        """Compatibility helper for @limiter.limit(...)."""
        return rate_limit(rule)


limiter = InProcessRateLimiter()


def _client_ip(request: Request) -> str:
    # Nginx should be configured to set X-Forwarded-For.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        # first is original
        return xff.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _client_key(request: Request, *, extra: Optional[str] = None) -> str:
    ip = _client_ip(request)
    if extra:
        return f"{ip}:{extra}"
    return ip


F = TypeVar("F", bound=Callable[..., Awaitable] | Callable[..., object])


def rate_limit(rule: RateLimitRule | str, *, extra_key_fn: Optional[Callable[[Request], str]] = None):
    """Can be used as dependency factory or as a no-op decorator (string rules)."""

    if isinstance(rule, RateLimitRule):

        async def dep(request: Request) -> None:
            extra = None
            if extra_key_fn is not None:
                try:
                    extra = extra_key_fn(request)
                except Exception:
                    # Don't break request if we fail to extract extra key.
                    extra = None

            client = _client_key(request, extra=extra)
            bucket = f"{rule.key}:{client}"
            ok = limiter.hit(bucket=bucket, window_seconds=rule.window_seconds, max_requests=rule.max_requests)
            if not ok:
                raise HTTPException(status_code=429, detail="Too Many Requests")

        return dep

    # When used as decorator with a string key, return identity (no-op enforcement).
    def decorator(func: F) -> F:
        return func

    return decorator


# Opinionated default rules for HOTEL.
# Tune conservatively because limiter is per-worker.
ADMIN_LOGIN = RateLimitRule(key="admin_login", window_seconds=60, max_requests=10)
DEVICE_STATUS = RateLimitRule(key="device_status", window_seconds=60, max_requests=120)
DEVICE_CHALLENGE = RateLimitRule(key="device_challenge", window_seconds=60, max_requests=60)
DEVICE_VERIFY = RateLimitRule(key="device_verify", window_seconds=60, max_requests=60)
DEVICE_NEW_SINCE = RateLimitRule(key="device_new_since", window_seconds=60, max_requests=60)
REPORT_CREATE = RateLimitRule(key="report_create", window_seconds=60, max_requests=20)


def x_device_id_key(request: Request) -> str:
    """Extract a stable device identifier for rate limiting when available."""

    return request.headers.get("x-device-id", "")[:64]


class RateLimitMiddleware(BaseHTTPMiddleware):
    """No-op middleware placeholder (per-route limits use @limiter)."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        return await call_next(request)
