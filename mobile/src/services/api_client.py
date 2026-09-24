"""Talks to the FraudLens FastAPI backend, with an offline fallback for demos.

If the server can't be reached, the client answers from assets/demo_cache.json
(pre-computed results for the demo samples, created by
backend/scripts/export_demo_cache.py). Every method returns (data, offline).
"""
import json
import os

import httpx

from config import API_PREFIX, DEFAULT_API_URL, REQUEST_TIMEOUT

_CACHE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "demo_cache.json")


class OfflineError(Exception):
    """Raised when the server is unreachable and there is no cached answer."""


class RateLimitedError(Exception):
    """The server asked this device to slow down (HTTP 429)."""


class ApiClient:
    def __init__(self, base_url: str = DEFAULT_API_URL):
        self.base_url = base_url.rstrip("/")
        self.online: bool | None = None
        # When the app is served by the backend (web mode), this is the browser's IP. The server only
        # trusts it on loopback calls, and uses it to count independent devices and for rate limits.
        self.client_ip: str | None = None
        self._cache = self._load_cache()

    # ---- plumbing -----------------------------------------------------------
    @staticmethod
    def _load_cache() -> dict:
        try:
            with open(_CACHE_PATH, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def set_base_url(self, url: str) -> None:
        self.base_url = url.strip().rstrip("/")
        self.online = None

    async def _request(self, method: str, path: str, **kwargs):
        url = f"{self.base_url}{API_PREFIX}{path}" if path != "/health" else f"{self.base_url}/health"
        headers = {"X-FraudLens-Client-IP": self.client_ip} if self.client_ip else None
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, headers=headers) as client:
            resp = await client.request(method, url, **kwargs)
            if resp.status_code == 429:
                self.online = True
                raise RateLimitedError("Too many checks from this device in a minute. Wait a moment and try again.")
            resp.raise_for_status()
            self.online = True
            return resp.json()

    async def _with_fallback(self, method: str, path: str, fallback, **kwargs):
        try:
            return await self._request(method, path, **kwargs), False
        except (httpx.HTTPError, OSError) as exc:
            if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code < 500:
                raise
            self.online = False
            data = fallback() if callable(fallback) else fallback
            if data is None:
                raise OfflineError("Can't reach the FraudLens server. Check the server address in settings.")
            return data, True

    # ---- endpoints ----------------------------------------------------------
    async def health(self) -> dict | None:
        try:
            return await self._request("GET", "/health")
        except (httpx.HTTPError, OSError):
            self.online = False
            return None

    async def analyze(self, text: str, channel: str = "sms", sender: str | None = None):
        return await self._with_fallback(
            "POST", "/analyze", lambda: self._cache.get("analyses", {}).get(text),
            json={"text": text, "channel": channel, "sender": sender or None},
        )

    async def samples(self):
        return await self._with_fallback("GET", "/samples", self._cache.get("samples", []))

    async def tactics(self):
        return await self._with_fallback("GET", "/learn/tactics", self._cache.get("tactics", []))

    async def quiz(self):
        return await self._with_fallback("GET", "/learn/quiz", self._cache.get("quiz", []))

    async def directory(self):
        return await self._with_fallback("GET", "/directory", self._cache.get("directory", {}))

    async def feedback(self, analysis_id: str, verdict: str) -> bool:
        try:
            await self._request("POST", "/feedback", json={"analysis_id": analysis_id, "verdict": verdict})
            return True
        except (httpx.HTTPError, OSError, RateLimitedError):
            return False

    async def report(self, text: str, label: str, reporter_id: str, sender: str | None = None,
                     category: str | None = None) -> dict:
        """Report a message as scam / genuine. Raises OfflineError when the server is unreachable."""
        try:
            return await self._request("POST", "/report", json={
                "text": text, "label": label, "reporter_id": reporter_id, "sender": sender or None,
                "category": category})
        except (httpx.HTTPError, OSError):
            self.online = False
            raise OfflineError("Reports need a connection to the FraudLens server.")
        except RateLimitedError as exc:
            raise OfflineError(str(exc))
