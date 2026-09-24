"""Scam memory: nearest-neighbour search over known scam and genuine messages.

This is the part that learns instantly. When enough independent users report
the same message (or near-duplicates of it), it is confirmed and added to the
memory, so reworded or translated variants are caught on the very next scan,
without retraining anything.

Anti-poisoning:
  * A reported scam first protects only the people who reported it ("personal"). It protects
    EVERYONE only once `community_confirmations` reporters from different networks (IP /24) report
    it, so one person, or one script with many install tokens, can't change what others see.
  * `confirmations` is how many reports a message needs before it is used at all (1 for a live demo).
  * "This is genuine" reports never change the memory: they are kept for review, so scammers
    can't use them to hide a scam.

Only redacted text is stored (personal data is replaced before embedding).
"""
from __future__ import annotations

import hashlib
import re
import json
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np

from .embedders import BaseEmbedder


_LINK = re.compile(r"(?i)\b(?:https?://|www\.)\S+|\b[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,24}(?:/\S*)?")


def mask_links(text: str) -> str:
    return _LINK.sub("[LINK]", text)


@dataclass
class MemoryItem:
    id: str
    label: str                  # "scam" | "legit"
    text: str                   # redacted text
    category: str = "generic"
    source: str = "report"      # training | seed | report
    reports: int = 1
    reporters: list[str] = field(default_factory=list)       # hashed install ids / clients
    reporter_nets: list[str] = field(default_factory=list)   # hashed networks (IP /24) of the reporters
    confirmed: bool = True
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def public(self, similarity: float) -> dict:
        return {
            "id": self.id, "label": self.label, "similarity": round(float(similarity), 3),
            "category": self.category, "source": self.source, "reports": self.reports,
            "created_at": self.created_at,
            # Reported text is shown to OTHER users, so links and web addresses in it are masked:
            # a reporter can't use FraudLens's own screen to advertise a link or a "helpline".
            "preview": (mask_links(self.text) if self.source == "report" else self.text)[:140],
        }


@dataclass
class Calibration:
    """Embedder-specific similarity thresholds (set by training, sensible defaults otherwise)."""

    match: float      # at/above this, treat as the same scam
    low: float        # below this, similarity means nothing
    duplicate: float  # two reports this close are the "same message"


DEFAULT_CALIBRATION = {
    "e5-small-onnx": Calibration(match=0.90, low=0.84, duplicate=0.95),
    "hashing-v1": Calibration(match=0.60, low=0.42, duplicate=0.80),
}


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


class ScamMemory:
    def __init__(self, embedder: BaseEmbedder, runtime_dir: Path, confirmations: int = 2,
                 calibration: Calibration | None = None, community_confirmations: int = 3):
        self.embedder = embedder
        self.confirmations = max(1, confirmations)
        self.community_confirmations = max(self.confirmations, community_confirmations)
        self.review: list[dict] = []   # "this is genuine" reports, for a person to review
        self.calibration = calibration or DEFAULT_CALIBRATION.get(embedder.id, Calibration(0.9, 0.8, 0.95))
        self._lock = threading.Lock()
        self.items: list[MemoryItem] = []
        self.vectors = np.zeros((0, embedder.dim), dtype=np.float32)
        self.pending: list[MemoryItem] = []
        self.pending_vectors = np.zeros((0, embedder.dim), dtype=np.float32)
        self.runtime_file = runtime_dir / "memory_runtime.json"
        runtime_dir.mkdir(parents=True, exist_ok=True)

    # ---- who sees a reported scam ------------------------------------------------------
    def is_community(self, item: MemoryItem) -> bool:
        return item.source != "report" or len(item.reporter_nets) >= self.community_confirmations

    def _hidden(self, viewer: str | None) -> list[int]:
        """Indices of reported items this viewer must not see (someone else's personal reports)."""
        v = _h(viewer) if viewer else None
        return [i for i, it in enumerate(self.items)
                if it.source == "report" and not self.is_community(it) and v not in it.reporters]

    # ---- loading ------------------------------------------------------------------
    def add_bulk(self, items: list[MemoryItem], vectors: np.ndarray | None = None) -> None:
        if not items:
            return
        if vectors is None:
            vectors = self.embedder.embed([i.text for i in items])
        with self._lock:
            self.items.extend(items)
            self.vectors = np.vstack([self.vectors, vectors.astype(np.float32)])

    def load_runtime(self) -> None:
        """Reload confirmed reports and pending reports saved by previous runs (re-embedded)."""
        if not self.runtime_file.exists():
            return
        data = json.loads(self.runtime_file.read_text(encoding="utf-8"))
        known = set(MemoryItem.__dataclass_fields__)
        confirmed = [MemoryItem(**{k: v for k, v in d.items() if k in known}) for d in data.get("confirmed", [])]
        pending = [MemoryItem(**{k: v for k, v in d.items() if k in known}) for d in data.get("pending", [])]
        self.review = list(data.get("review", []))[-500:]
        self.add_bulk(confirmed)
        if pending:
            self.pending = pending
            self.pending_vectors = self.embedder.embed([p.text for p in pending])

    def _save_runtime(self) -> None:
        data = {
            "confirmed": [asdict(i) for i in self.items if i.source == "report"],
            "pending": [asdict(p) for p in self.pending],
            "review": self.review[-500:],
        }
        tmp = self.runtime_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.runtime_file)

    # ---- search -----------------------------------------------------------------
    def search(self, vector: np.ndarray, k: int = 3, exclude: int | None = None,
               viewer: str | None = None) -> list[tuple[MemoryItem, float]]:
        with self._lock:
            if not len(self.items):
                return []
            sims = self.vectors @ vector.astype(np.float32)
            if exclude is not None:
                sims[exclude] = -1
            hidden = self._hidden(viewer)
            if hidden:
                sims[hidden] = -1
            top = np.argsort(-sims)[:k]
            return [(self.items[i], float(sims[i])) for i in top]

    def best(self, vector: np.ndarray, viewer: str | None = None) -> tuple[tuple[MemoryItem, float] | None, tuple[MemoryItem, float] | None]:
        """Closest confirmed scam and closest confirmed genuine message (that this viewer may see)."""
        with self._lock:
            if not len(self.items):
                return None, None
            sims = self.vectors @ vector.astype(np.float32)
            hidden = set(self._hidden(viewer))
            out = []
            for label in ("scam", "legit"):
                idx = [i for i, it in enumerate(self.items) if it.label == label and i not in hidden]
                if not idx:
                    out.append(None)
                    continue
                j = max(idx, key=lambda i: sims[i])
                out.append((self.items[j], float(sims[j])))
            return out[0], out[1]

    def strength(self, similarity: float | None) -> float:
        """Map a raw cosine similarity to 0..1 (1 = same scam)."""
        if similarity is None:
            return 0.0
        c = self.calibration
        return float(np.clip((similarity - c.low) / max(c.match - c.low, 1e-6), 0.0, 1.0))

    # ---- learning from reports -------------------------------------------------------
    def report(self, redacted_text: str, label: str, reporter: str, category: str = "generic",
               reporter_net: str | None = None) -> dict:
        """Register a user report. Returns what happened:
        pending / confirmed / reinforced / rejected / noted, plus `new_reporter` (did this report count?)
        and `community` (does the scam now protect everyone?)."""
        vec = self.embedder.embed_one(redacted_text)
        reporter_hash = _h(reporter)
        net_hash = _h(reporter_net or reporter)
        dup = self.calibration.duplicate
        with self._lock:
            nearest = None
            if len(self.items):
                sims = self.vectors @ vec
                j = int(np.argmax(sims))
                if sims[j] >= dup:
                    nearest = (j, float(sims[j]))

            # "Genuine" reports never change the memory (a scammer could use them to hide a scam).
            if label != "scam":
                if nearest and self.items[nearest[0]].label == "scam":
                    item = self.items[nearest[0]]
                    return {"status": "rejected", "reason": "This message matches a confirmed scam.",
                            "match": item.public(nearest[1]), "new_reporter": False, "community": False}
                self.review.append({"text": redacted_text[:500], "category": category, "reporter": reporter_hash,
                                    "at": time.time()})
                del self.review[:-500]
                self._save_runtime()
                return {"status": "noted", "new_reporter": False, "community": False}

            def count(item: MemoryItem) -> bool:
                new = reporter_hash not in item.reporters
                if new:
                    item.reporters.append(reporter_hash)
                    item.reports += 1
                if net_hash not in item.reporter_nets:
                    item.reporter_nets.append(net_hash)
                item.last_seen = time.time()
                return new

            # 1) Already in memory? Reinforce.
            if nearest and self.items[nearest[0]].label == "scam":
                item = self.items[nearest[0]]
                was_community = self.is_community(item)
                new = count(item) if item.source == "report" else False
                self._save_runtime()
                return {"status": "reinforced", "reports": item.reports, "match": item.public(nearest[1]),
                        "new_reporter": new or (self.is_community(item) and not was_community),
                        "community": self.is_community(item)}

            # 2) Matches a pending report? Count it.
            target = None
            if len(self.pending):
                psims = self.pending_vectors @ vec
                j = int(np.argmax(psims))
                if psims[j] >= dup and self.pending[j].label == label:
                    target = j
            if target is None:
                item = MemoryItem(id=uuid.uuid4().hex[:10], label=label, text=redacted_text, category=category,
                                  source="report", reports=0, reporters=[], reporter_nets=[], confirmed=False)
                self.pending.append(item)
                self.pending_vectors = np.vstack([self.pending_vectors, vec[None, :]])
                target = len(self.pending) - 1
            item = self.pending[target]
            new = count(item)

            # 3) Enough reports -> confirmed -> in the memory right now (for its reporters, or for everyone).
            if item.reports >= self.confirmations:
                item.confirmed = True
                self.items.append(item)
                self.vectors = np.vstack([self.vectors, self.pending_vectors[target][None, :]])
                self.pending.pop(target)
                self.pending_vectors = np.delete(self.pending_vectors, target, axis=0)
                self._save_runtime()
                return {"status": "confirmed", "reports": item.reports, "match": item.public(1.0),
                        "new_reporter": new, "community": self.is_community(item),
                        "community_needed": self.community_confirmations}
            self._save_runtime()
            return {"status": "pending", "reports": item.reports, "needed": self.confirmations,
                    "new_reporter": new, "community": False}

    def confirmed_reports(self) -> list[MemoryItem]:
        return [i for i in self.items if i.source == "report"]

    def stats(self) -> dict:
        labels = [i.label for i in self.items]
        return {
            "size": len(self.items), "scams": labels.count("scam"), "genuine": labels.count("legit"),
            "confirmed_reports": len(self.confirmed_reports()), "pending_reports": len(self.pending),
            "community_reports": len([i for i in self.confirmed_reports() if self.is_community(i)]),
            "confirmations_required": self.confirmations,
            "community_confirmations": self.community_confirmations,
            "genuine_reports_for_review": len(self.review),
            "match_threshold": self.calibration.match,
        }
