"""In-memory store for analyses, flagged payees and anonymised trend data.

Swap this for a database later (SQLite/Postgres) by implementing the same
methods. Account numbers and wallets are stored only as salted SHA-256 hashes,
never in clear text. The salt comes from FRAUDLENS_HASH_SALT (random per run if unset).

Two kinds of flags (anti-poisoning):
- community flags: only from CONFIRMED user reports; every client sees them.
- personal flags: from a client's own high-risk scans; only that client sees them. They power
  Pause-Before-Pay ("you scanned a scam with this account") and Shield's caller check, but
  nobody can make an innocent number look like a scam to other people just by scanning it.
"""
import hashlib
import re
import threading
from collections import Counter, OrderedDict, deque
from datetime import datetime, timezone

from ..core.security import hash_salt

MAX_CLIENTS = 5000
MAX_PERSONAL_FLAGS = 500


def fingerprint(identifier: str) -> str:
    norm = re.sub(r"[\s\-]", "", identifier).upper()
    return hashlib.sha256(f"{hash_salt()}:{norm}".encode()).hexdigest()


def _new_entry(category: str) -> dict:
    return {"first_seen": datetime.now(timezone.utc).isoformat(), "reports": 0, "max_score": 0,
            "category": category}


class Store:
    def __init__(self, max_items: int = 1000):
        self._lock = threading.Lock()
        self._analyses: dict[str, dict] = {}
        self._order: deque[str] = deque(maxlen=max_items)
        self._flagged: dict[str, dict] = {}                        # community (confirmed reports)
        self._personal: "OrderedDict[str, OrderedDict[str, dict]]" = OrderedDict()  # client -> flags
        self._feedback: list[dict] = []

    # ---- analyses -------------------------------------------------------
    def save_analysis(self, analysis: dict, risky_identifiers: list[str], client: str | None = None,
                      scope: str = "personal") -> None:
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
            if scope == "community":
                self.flag_identifiers(risky_identifiers, analysis["category"], analysis["risk_score"])
            elif scope == "personal" and client:
                self.flag_personal(client, risky_identifiers, analysis["category"], analysis["risk_score"])

    def flag_identifiers(self, identifiers: list[str], category: str, score: int) -> None:
        """Community flag (confirmed reports only): hashed, never in clear text."""
        with self._lock:
            for ident in dict.fromkeys(i for i in identifiers if i):
                entry = self._flagged.setdefault(fingerprint(ident), _new_entry(category))
                entry["reports"] += 1
                entry["max_score"] = max(entry["max_score"], score)

    def flag_personal(self, client: str, identifiers: list[str], category: str, score: int) -> None:
        with self._lock:
            flags = self._personal.setdefault(client, OrderedDict())
            self._personal.move_to_end(client)
            while len(self._personal) > MAX_CLIENTS:
                self._personal.popitem(last=False)
            for ident in dict.fromkeys(i for i in identifiers if i):
                fp = fingerprint(ident)
                entry = flags.setdefault(fp, _new_entry(category))
                flags.move_to_end(fp)
                entry["reports"] += 1
                entry["max_score"] = max(entry["max_score"], score)
            while len(flags) > MAX_PERSONAL_FLAGS:
                flags.popitem(last=False)

    def _lookup(self, fp: str, client: str | None) -> dict | None:
        community = self._flagged.get(fp)
        personal = self._personal.get(client, {}).get(fp) if client else None
        if community and personal:
            return max(community, personal, key=lambda e: e["reports"])
        return community or personal

    def reputation(self, identifiers: list[str], client: str | None = None) -> int:
        """How many flagged messages contained any of these identifiers (community + this client's own)."""
        return max(((self._lookup(fingerprint(i), client) or {}).get("reports", 0) for i in identifiers if i),
                   default=0)

    def get_analysis(self, analysis_id: str) -> dict | None:
        return self._analyses.get(analysis_id)

    def flagged(self, identifier: str, client: str | None = None) -> dict | None:
        return self._lookup(fingerprint(identifier), client)

    # ---- feedback --------------------------------------------------------
    def add_feedback(self, item: dict) -> None:
        with self._lock:
            self._feedback.append({**item, "at": datetime.now(timezone.utc).isoformat()})
            del self._feedback[:-5000]  # bounded

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
