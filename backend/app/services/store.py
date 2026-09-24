"""In-memory store for analyses, flagged payees and anonymised trend data.

Swap this for a database later (SQLite/Postgres) by implementing the same
methods. Account numbers and wallets are stored only as salted SHA-256 hashes,
never in clear text.
"""
import hashlib
import re
import threading
from collections import Counter, deque
from datetime import datetime, timezone

_SALT = "fraudlens-demo-salt"  # move to settings / secret store in production


def fingerprint(identifier: str) -> str:
    norm = re.sub(r"[\s\-]", "", identifier).upper()
    return hashlib.sha256(f"{_SALT}:{norm}".encode()).hexdigest()


def _official_phones() -> set[str]:
    """Phone numbers from the verified directory: these can never be flagged as scam numbers."""
    try:
        from ..engine.pipeline import normalise_phone
        from ..knowledge import loader
        phones = set()
        for org in loader.organisations():
            for p in ([org.get("phone")] if isinstance(org.get("phone"), str) else (org.get("phone") or [])) + \
                     list(org.get("phones") or []):
                if p:
                    phones.add(f"tel:{normalise_phone(str(p))}")
        return phones
    except Exception:  # directory problems must never break scanning
        return set()


class Store:
    def __init__(self, max_items: int = 1000):
        # True when report_confirmations >= 2: reputation counts independent devices, not messages.
        self.strict_sources = True
        self._lock = threading.Lock()
        self._analyses: dict[str, dict] = {}
        self._order: deque[str] = deque(maxlen=max_items)
        self._flagged: dict[str, dict] = {}
        self._feedback: list[dict] = []

    # ---- analyses -------------------------------------------------------
    def save_analysis(self, analysis: dict, risky_identifiers: list[str], source: str | None = None) -> None:
        with self._lock:
            if len(self._order) == self._order.maxlen:
                self._analyses.pop(self._order[0], None)
            self._order.append(analysis["analysis_id"])
            # Keep only what later features need: no message text is stored.
            self._analyses[analysis["analysis_id"]] = {
                "analysis_id": analysis["analysis_id"],
                "created_at": analysis["created_at"],
                "risk_score": analysis["risk_score"],
                "risk_level": analysis["risk_level"],
                "category": analysis["category"],
                "tactics": [t["tactic"] for t in analysis["tactics"]],
                "account_hashes": [fingerprint(i) for i in risky_identifiers],
            }
        if analysis["risk_level"] == "high":
            self.flag_identifiers(risky_identifiers, analysis["category"], analysis["risk_score"], source=source)

    def flag_identifiers(self, identifiers: list[str], category: str, score: int, source: str | None = None) -> None:
        """Remember accounts / numbers / links seen in scams (hashed, never in clear text).

        Official numbers from the verified directory are never flagged, so nobody can "frame" a bank's
        real number as a scam caller. `source` is an anonymous device id used to count independent reports.
        """
        official = _official_phones()
        with self._lock:
            for ident in dict.fromkeys(i for i in identifiers if i):
                if ident in official:
                    continue
                entry = self._flagged.setdefault(fingerprint(ident), {
                    "first_seen": datetime.now(timezone.utc).isoformat(), "reports": 0, "max_score": 0,
                    "category": category, "sources": set(),
                })
                entry["reports"] += 1
                entry["sources"].add(source or "unknown")
                entry["max_score"] = max(entry["max_score"], score)

    def _count(self, entry: dict) -> int:
        return len(entry.get("sources") or ()) if self.strict_sources else entry.get("reports", 0)

    def reputation(self, identifiers: list[str]) -> int:
        """How many independent devices (demo mode: flagged messages) reported any of these identifiers."""
        return max((self._count(self._flagged[fp]) for fp in (fingerprint(i) for i in identifiers if i)
                    if fp in self._flagged), default=0)

    def get_analysis(self, analysis_id: str) -> dict | None:
        return self._analyses.get(analysis_id)

    def flagged(self, identifier: str) -> dict | None:
        entry = self._flagged.get(fingerprint(identifier))
        return {k: v for k, v in entry.items() if k != "sources"} if entry else None

    # ---- feedback --------------------------------------------------------
    def add_feedback(self, item: dict) -> None:
        with self._lock:
            self._feedback.append({**item, "at": datetime.now(timezone.utc).isoformat()})

    # ---- radar -------------------------------------------------------------
    def radar(self) -> dict:
        with self._lock:
            items = list(self._analyses.values())
        cats = Counter(a["category"] for a in items if a["risk_level"] != "low")
        tactics = Counter(t for a in items if a["risk_level"] != "low" for t in a["tactics"])
        levels = Counter(a["risk_level"] for a in items)
        return {
            "total_checks": len(items),
            "by_level": dict(levels),
            "by_category": dict(cats.most_common()),
            "top_tactics": dict(tactics.most_common(8)),
            "flagged_payees": len(self._flagged),
            "feedback_count": len(self._feedback),
        }


store = Store()
