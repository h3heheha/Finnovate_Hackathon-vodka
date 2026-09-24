"""Request-level protections: who is calling, rate limits, security headers, admin checks.

Added after a security review (see SECURITY.md at the project root):
  - client_key(): one identity per device (IP address), used to count *independent* reporters
    and for rate limits. A client can't mint new identities by changing its own reporter_id.
  - RateLimitMiddleware: per-device budget for the endpoints that cost CPU or paid API credits.
  - SecurityHeadersMiddleware: nosniff, no framing, no referrer leaks.
  - require_admin(): admin endpoints stay disabled until a strong token is configured.
"""
from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

LOOPBACK = {"127.0.0.1", "::1", "localhost"}
# The FraudLens app served at /app runs inside this server and calls the API over loopback.
# It forwards the real browser's IP in this header; the header is ignored from any other address.
FORWARDED_CLIENT_HEADER = "x-fraudlens-client-ip"
WEAK_ADMIN_TOKENS = {"", "change-me", "changeme", "admin", "password", "secret", "token"}


def client_key(request: Request) -> str:
    host = request.client.host if request.client else "unknown"
    if host in LOOPBACK:
        fwd = request.headers.get(FORWARDED_CLIENT_HEADER, "").strip()
        if fwd:
            return fwd[:64]
    return host


def source_id(request: Request) -> str:
    """Anonymous, stable id for a device (salted hash of its address), never stored in clear."""
    return hashlib.sha256(f"fraudlens-source:{client_key(request)}".encode()).hexdigest()[:16]


def require_admin(token: str | None, configured: str | None) -> None:
    configured = (configured or "").strip()
    if configured.lower() in WEAK_ADMIN_TOKENS or len(configured) < 16:
        raise HTTPException(503, "Admin endpoints are disabled. Set FRAUDLENS_ADMIN_TOKEN in backend/.env to a "
                                 "random value of at least 16 characters to enable them.")
    if not token or not hmac.compare_digest(token.encode(), configured.encode()):
        raise HTTPException(401, "Invalid admin token")


# (method, path prefix) -> weight. Everything else is free.
_LIMITED = {
    ("POST", "/analyze"): 1, ("POST", "/report"): 2, ("POST", "/feedback"): 1,
    ("POST", "/payments/check"): 1, ("GET", "/intel/url"): 1, ("GET", "/intel/phone"): 1,
    ("POST", "/admin/"): 5,
}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding one-minute window per device. `per_minute <= 0` switches it off."""

    def __init__(self, app, api_prefix: str, per_minute: int):
        super().__init__(app)
        self.prefix = api_prefix.rstrip("/")
        self.per_minute = per_minute
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _weight(self, method: str, path: str) -> int:
        if not path.startswith(self.prefix + "/"):
            return 0
        rest = path[len(self.prefix):]
        for (m, p), w in _LIMITED.items():
            if method == m and rest.startswith(p):
                return w
        return 0

    async def dispatch(self, request: Request, call_next):
        weight = self._weight(request.method, request.url.path) if self.per_minute > 0 else 0
        if weight:
            key, now = client_key(request), time.monotonic()
            with self._lock:
                q = self._hits[key]
                while q and now - q[0] > 60:
                    q.popleft()
                if len(q) + weight > self.per_minute:
                    retry = int(60 - (now - q[0])) + 1 if q else 60
                    return JSONResponse({"detail": "Too many requests from this device. Wait a minute and try "
                                                   "again."}, status_code=429, headers={"Retry-After": str(retry)})
                q.extend([now] * weight)
                if len(self._hits) > 10_000:  # bound memory under a flood of distinct addresses
                    for k in [k for k, v in self._hits.items() if not v or now - v[-1] > 60]:
                        del self._hits[k]
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response
