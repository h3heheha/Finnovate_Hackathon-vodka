"""Security layer shared by every route.

- Install tokens: the Chrome extension registers once and gets a signed token (HMAC-SHA256).
  The token, not anything the client claims, is its identity for reports and rate limits.
- Client key: "ext:<install id>" for a valid token, otherwise "ip:<address>".
- Rate limits: sliding window per client and per endpoint group (429 + Retry-After).
- Origin guard: a web page in someone's browser can't make the API do work, even with
  requests that CORS doesn't block (e.g. an <img> GET that would burn paid lookups).
- Admin: constant-time token check; admin is locked when the token is weak or empty.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .config import LOCAL_ORIGIN_REGEX, Settings, get_settings

log = logging.getLogger("fraudlens.security")
TOKEN_HEADER = "X-FraudLens-Install"
_LOCAL_ORIGIN = re.compile(LOCAL_ORIGIN_REGEX)

_runtime_secret = secrets.token_hex(32)
_runtime_salt = secrets.token_hex(16)


_file_secret: str | None = None


def _secret(settings: Settings) -> bytes:
    """FRAUDLENS_INSTALL_SECRET if set; otherwise a random secret kept in data/runtime/.install_secret,
    so restarting the server doesn't log every browser out (the file is never in the submission zip)."""
    global _file_secret
    if settings.install_secret:
        return settings.install_secret.encode()
    if _file_secret is None:
        path = settings.data_dir / "runtime" / ".install_secret"
        try:
            if path.exists() and len(path.read_text().strip()) >= 32:
                _file_secret = path.read_text().strip()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                _file_secret = secrets.token_hex(32)
                path.write_text(_file_secret)
        except OSError:
            _file_secret = _runtime_secret
    return _file_secret.encode()


def hash_salt() -> str:
    return get_settings().hash_salt or _runtime_salt


# ---- install tokens -------------------------------------------------------------------------
def issue_token(settings: Settings) -> dict:
    install_id = secrets.token_hex(8)
    issued = int(time.time())
    payload = f"v1.{install_id}.{issued}"
    sig = hmac.new(_secret(settings), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return {"install_id": install_id, "token": f"{payload}.{sig}",
            "expires_in": settings.install_token_days * 86400}


def verify_token(token: str | None, settings: Settings) -> str | None:
    """Returns the install id for a valid, unexpired token; None otherwise."""
    if not token or len(token) > 200:
        return None
    parts = token.split(".")
    if len(parts) != 4 or parts[0] != "v1":
        return None
    _, install_id, issued, sig = parts
    if not re.fullmatch(r"[0-9a-f]{16}", install_id) or not issued.isdigit():
        return None
    expected = hmac.new(_secret(settings), f"v1.{install_id}.{issued}".encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(expected, sig):
        return None
    if time.time() - int(issued) > settings.install_token_days * 86400:
        return None
    return install_id


def _valid_ip(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address((value or "").strip())) if value else None
    except ValueError:
        return None


def client_ip(request: Request) -> str:
    """The visitor's address. Behind Render, Cloudflare puts it in True-Client-IP / CF-Connecting-IP
    (overwriting anything the visitor sent), so it can't be faked with a made-up X-Forwarded-For."""
    settings = get_settings()
    mode = (settings.client_ip_header or "auto").strip().lower()
    names: list[str] = []
    if mode == "auto":
        if os.environ.get("RENDER"):
            names = ["true-client-ip", "cf-connecting-ip"]
    elif mode not in ("", "none", "off"):
        names = [mode]
    for name in names:
        ip = _valid_ip(request.headers.get(name))
        if ip:
            return ip
    return request.client.host if request.client else "unknown"


def client_net(ip: str) -> str:
    """The visitor's network (IPv4 /24, IPv6 /48): several devices at one venue count as one reporter."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


def client_key(request: Request) -> str:
    """Who is calling: set by the middleware (token → ext:<id>, else ip:<address>)."""
    return getattr(request.state, "client_key", None) or f"ip:{client_ip(request)}"


# ---- admin ---------------------------------------------------------------------------------
def check_admin(token: str | None, settings: Settings) -> None:
    if not settings.admin_enabled:
        raise HTTPException(503, "Admin endpoints are locked: set a strong FRAUDLENS_ADMIN_TOKEN "
                                 "(24+ random characters) in backend/.env and restart.")
    if not token or not hmac.compare_digest(token.encode(), settings.admin_token.strip().encode()):
        raise HTTPException(401, "Invalid admin token")


# ---- rate limiting -------------------------------------------------------------------------
class RateLimiter:
    def __init__(self):
        self._hits: dict[tuple[str, str], deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, bucket: str, limit: int, window: int) -> int:
        """Record one request. Returns 0 if allowed, otherwise seconds until the next free slot."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[(key, bucket)]
            while q and now - q[0] >= window:
                q.popleft()
            if len(q) >= limit:
                return max(1, int(window - (now - q[0])) + 1)
            q.append(now)
            if len(self._hits) > 50_000:  # keep memory bounded
                self._hits = defaultdict(deque, {k: v for k, v in self._hits.items() if v})
            return 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


def bucket_for(path: str, prefix: str) -> str:
    p = path[len(prefix):] if path.startswith(prefix) else path
    if p.startswith("/analyze"):
        return "analyze"
    if p.startswith("/intel/phone"):
        return "intel_phone"
    if p.startswith("/intel/url"):
        return "intel_url"
    if p.startswith("/report") or p.startswith("/feedback"):
        return "report"
    if p.startswith("/extension/register"):
        return "register"
    if p.startswith("/admin"):
        return "admin"
    if p.startswith("/payments"):
        return "payments"
    if p.startswith("/status/providers"):
        return "selftest"
    return "default"


def origin_allowed(origin: str, settings: Settings) -> bool:
    return origin in settings.allowed_origins or bool(_LOCAL_ORIGIN.match(origin))


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        path = request.url.path
        if request.method == "OPTIONS" or not path.startswith(settings.api_prefix):
            return await call_next(request)  # CORS preflight, /health, /docs

        # 1) Origin guard: browsers always say where a request comes from.
        origin = request.headers.get("origin")
        fetch_site = request.headers.get("sec-fetch-site")
        if origin and origin != "null" and not origin_allowed(origin, settings):
            return JSONResponse({"detail": "Origin not allowed"}, status_code=403)
        if not origin and fetch_site == "cross-site":
            return JSONResponse({"detail": "Cross-site requests are not allowed"}, status_code=403)

        # 2) Identity: a signed install token, or the IP address.
        bucket = bucket_for(path, settings.api_prefix)
        raw = request.headers.get(TOKEN_HEADER)
        install_id = verify_token(raw, settings) if raw else None
        if raw and not install_id and bucket != "register":
            return JSONResponse({"detail": "invalid_install_token"}, status_code=401)
        if settings.require_install_token and not install_id and bucket != "register":
            return JSONResponse({"detail": "install_token_required"}, status_code=401)
        request.state.install_id = install_id
        request.state.client_key = f"ext:{install_id}" if install_id else f"ip:{client_ip(request)}"

        # 3) Rate limit (registration is always limited per IP so tokens can't be farmed).
        if settings.rate_limit_enabled:
            limit, window = settings.rate_limits.get(bucket, settings.rate_limits["default"])
            key = f"ip:{client_ip(request)}" if bucket in ("register", "admin") else request.state.client_key
            wait = limiter.hit(key, bucket, limit, window)
            if not wait and bucket in settings.global_limits:   # everybody together
                g_limit, g_window = settings.global_limits[bucket]
                wait = limiter.hit("global", bucket, g_limit, g_window)
            if wait:
                return JSONResponse({"detail": "Too many requests, slow down.", "retry_after": wait},
                                    status_code=429, headers={"Retry-After": str(wait)})
        return await call_next(request)
