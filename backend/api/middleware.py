"""
Security middleware (Phase 8) — additive hardening.

  * SecurityHeadersMiddleware — standard hardening headers on every response.
  * BodySizeLimitMiddleware   — reject oversized request bodies (413).
  * RateLimitMiddleware       — lightweight in-memory per-client limit (429).

None of these change security decisions; they reduce attack surface around the
authoritative engine. Rate limiting is opt-in (0 = disabled) so it never
interferes with tests or benchmarks.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# Health is always reachable (liveness) regardless of rate limits.
_EXEMPT_PATHS = {"/health"}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        # This is a JSON API; a strict CSP is safe and blocks accidental HTML/JS.
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        # Never let decisions/audit data be cached by intermediaries.
        response.headers.setdefault("Cache-Control", "no-store")
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_bytes: int) -> None:
        super().__init__(app)
        self._max = max_bytes

    async def dispatch(self, request: Request, call_next):
        if self._max > 0:
            cl = request.headers.get("content-length")
            if cl is not None:
                try:
                    if int(cl) > self._max:
                        return JSONResponse(
                            {"detail": "Request body too large"},
                            status_code=413,
                        )
                except ValueError:
                    return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window limit keyed by API key (if present) else client IP."""

    def __init__(self, app, per_minute: int) -> None:
        super().__init__(app)
        self._limit = per_minute
        self._window = 60.0
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _key(self, request: Request) -> str:
        api_key = request.headers.get("x-api-key")
        if api_key:
            return f"k:{hash(api_key)}"
        client = request.client
        return f"ip:{client.host if client else 'unknown'}"

    async def dispatch(self, request: Request, call_next):
        if self._limit <= 0 or request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        now = time.monotonic()
        key = self._key(request)
        with self._lock:
            dq = self._hits.setdefault(key, deque())
            while dq and now - dq[0] > self._window:
                dq.popleft()
            if len(dq) >= self._limit:
                retry = max(1, int(self._window - (now - dq[0])))
                return JSONResponse(
                    {"detail": "Rate limit exceeded"},
                    status_code=429,
                    headers={"Retry-After": str(retry)},
                )
            dq.append(now)
        return await call_next(request)
