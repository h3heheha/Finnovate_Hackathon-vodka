"""Shared allowances for free external services (AI, VirusTotal, Safe Browsing).

Counted for ALL users together, in memory: a per-minute window plus a per-day total. When an
allowance is used up the service is simply skipped for that request (the check still works with
the other layers) instead of the provider blocking our key for the rest of the day.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from datetime import date


class Allowance:
    def __init__(self, per_day: int, per_minute: int | None = None):
        self.per_day, self.per_minute = per_day, per_minute
        self._day, self._used = date.today(), 0
        self._minute: deque[float] = deque()
        self._lock = threading.Lock()

    def take(self) -> str | None:
        """None when allowed (and counted); otherwise the reason it isn't."""
        with self._lock:
            today = date.today()
            if today != self._day:
                self._day, self._used = today, 0
            if self._used >= self.per_day:
                return "daily allowance used"
            if self.per_minute:
                now = time.monotonic()
                while self._minute and now - self._minute[0] >= 60:
                    self._minute.popleft()
                if len(self._minute) >= self.per_minute:
                    return "per-minute allowance used"
                self._minute.append(now)
            self._used += 1
            return None

    def refund(self) -> None:
        with self._lock:
            self._used = max(0, self._used - 1)
            if self._minute:
                self._minute.pop()

    @property
    def used_today(self) -> int:
        return self._used if self._day == date.today() else 0


class PerKeyAllowance:
    """A daily allowance per key (one browser, one network). Bounded memory."""

    def __init__(self, per_day: int, max_keys: int = 20000):
        self.per_day, self.max_keys = per_day, max_keys
        self._day, self._used = date.today(), {}
        self._lock = threading.Lock()

    def take(self, key: str) -> bool:
        with self._lock:
            if date.today() != self._day:
                self._day, self._used = date.today(), {}
            n = self._used.get(key, 0)
            if n >= self.per_day:
                return False
            if len(self._used) >= self.max_keys and key not in self._used:
                return False   # too many different callers today: be safe, skip the AI
            self._used[key] = n + 1
            return True
