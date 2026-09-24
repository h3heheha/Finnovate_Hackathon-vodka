"""Tiny SQLite cache (with TTL) and daily budget counter for external API calls.

Every provider result is cached, so a scam forwarded to 50 people costs one
lookup. The budget table stops us from burning the IPQS free plan (35/day).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import date
from pathlib import Path


class IntelCache:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute("CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT, exp REAL)")
            self._db.execute("CREATE TABLE IF NOT EXISTS budget (day TEXT, name TEXT, n INTEGER, "
                             "PRIMARY KEY(day, name))")
            self._db.commit()

    def get(self, key: str):
        with self._lock:
            row = self._db.execute("SELECT v, exp FROM cache WHERE k=?", (key,)).fetchone()
        if not row or row[1] < time.time():
            return None
        return json.loads(row[0])

    def set(self, key: str, value, ttl_seconds: float) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?)",
                             (key, json.dumps(value), time.time() + ttl_seconds))
            self._db.commit()

    def used_today(self, name: str) -> int:
        with self._lock:
            row = self._db.execute("SELECT n FROM budget WHERE day=? AND name=?",
                                   (date.today().isoformat(), name)).fetchone()
        return row[0] if row else 0

    def take(self, name: str, limit: int) -> bool:
        """Consume one unit of today's budget. False when the budget is spent."""
        with self._lock:
            day = date.today().isoformat()
            row = self._db.execute("SELECT n FROM budget WHERE day=? AND name=?", (day, name)).fetchone()
            n = row[0] if row else 0
            if n >= limit:
                return False
            self._db.execute("INSERT OR REPLACE INTO budget VALUES (?,?,?)", (day, name, n + 1))
            self._db.commit()
            return True

    def refund(self, name: str) -> None:
        """Give back a unit when the call failed (network error), so failures don't eat the budget."""
        with self._lock:
            self._db.execute("UPDATE budget SET n = MAX(n - 1, 0) WHERE day=? AND name=?",
                             (date.today().isoformat(), name))
            self._db.commit()
