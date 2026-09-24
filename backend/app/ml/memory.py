"""Scam memory: nearest-neighbour search over known scam and genuine messages.

This is the part that learns instantly. When enough independent users report
the same message (or near-duplicates of it), it is confirmed and added to the
memory, so reworded or translated variants are caught on the very next scan,
without retraining anything.

Anti-poisoning: a single report never changes the memory. A message needs
`confirmations` distinct reporters, and a "genuine" report can never overwrite
a confirmed scam.

Only redacted text is stored (personal data is replaced before embedding).
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np

from .embedders import BaseEmbedder


@dataclass
class MemoryItem:
    id: str
    label: str                  # "scam" | "legit"
    text: str                   # redacted text
    category: str = "generic"
    source: str = "report"      # training | seed | report
    reports: int = 1
    reporters: list[str] = field(default_factory=list)
    confirmed: bool = True
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def public(self, similarity: float) -> dict:
        return {
            "id": self.id, "label": self.label, "similarity": round(float(similarity), 3),
            "category": self.category, "source": self.source, "reports": self.reports,
            "created_at": self.created_at, "preview": self.text[:140],
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


class ScamMemory:
    def __init__(self, embedder: BaseEmbedder, runtime_dir: Path, confirmations: int = 2,
                 calibration: Calibration | None = None):
        self.embedder = embedder
        self.confirmations = max(1, confirmations)
        self.calibration = calibration or DEFAULT_CALIBRATION.get(embedder.id, Calibration(0.9, 0.8, 0.95))
        self._lock = threading.Lock()
        self.items: list[MemoryItem] = []
        self.vectors = np.zeros((0, embedder.dim), dtype=np.float32)
        self.pending: list[MemoryItem] = []
        self.pending_vectors = np.zeros((0, embedder.dim), dtype=np.float32)
        self.runtime_file = runtime_dir / "memory_runtime.json"
        runtime_dir.mkdir(parents=True, exist_ok=True)

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
        confirmed = [MemoryItem(**d) for d in data.get("confirmed", [])]
        pending = [MemoryItem(**d) for d in data.get("pending", [])]
        self.add_bulk(confirmed)
        if pending:
            self.pending = pending
            self.pending_vectors = self.embedder.embed([p.text for p in pending])

    def _save_runtime(self) -> None:
        data = {
            "confirmed": [asdict(i) for i in self.items if i.source == "report"],
            "pending": [asdict(p) for p in self.pending],
        }
        tmp = self.runtime_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.runtime_file)

    # ---- search -----------------------------------------------------------------
    def search(self, vector: np.ndarray, k: int = 3, exclude: int | None = None) -> list[tuple[MemoryItem, float]]:
        with self._lock:
            if not len(self.items):
                return []
            sims = self.vectors @ vector.astype(np.float32)
            if exclude is not None:
                sims[exclude] = -1
            top = np.argsort(-sims)[:k]
            return [(self.items[i], float(sims[i])) for i in top]

    def best(self, vector: np.ndarray) -> tuple[tuple[MemoryItem, float] | None, tuple[MemoryItem, float] | None]:
        """Closest confirmed scam and closest confirmed genuine message."""
        with self._lock:
            if not len(self.items):
                return None, None
            sims = self.vectors @ vector.astype(np.float32)
            out = []
            for label in ("scam", "legit"):
                idx = [i for i, it in enumerate(self.items) if it.label == label]
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
    def report(self, redacted_text: str, label: str, reporter: str, category: str = "generic") -> dict:
        """Register a user report. Returns what happened (pending / confirmed / reinforced / rejected)."""
        vec = self.embedder.embed_one(redacted_text)
        reporter_hash = hashlib.sha256(reporter.encode()).hexdigest()[:16]
        dup = self.calibration.duplicate
        with self._lock:
            # 1) Already in memory? Reinforce (or refuse a conflicting "genuine" report).
            if len(self.items):
                sims = self.vectors @ vec
                j = int(np.argmax(sims))
                if sims[j] >= dup:
                    item = self.items[j]
                    if item.label != label:
                        if item.label == "scam":
                            return {"status": "rejected", "reason": "This message matches a confirmed scam.",
                                    "match": item.public(sims[j])}
                        # a confirmed "legit" reported as scam: count it as a new pending scam report
                    else:
                        if reporter_hash not in item.reporters:
                            item.reporters.append(reporter_hash)
                            item.reports += 1
                        item.last_seen = time.time()
                        self._save_runtime()
                        return {"status": "reinforced", "reports": item.reports, "match": item.public(sims[j])}

            # 2) Matches a pending report from someone else? Count it.
            target = None
            if len(self.pending):
                psims = self.pending_vectors @ vec
                j = int(np.argmax(psims))
                if psims[j] >= dup and self.pending[j].label == label:
                    target = j
            if target is None:
                item = MemoryItem(id=uuid.uuid4().hex[:10], label=label, text=redacted_text, category=category,
                                  source="report", reports=0, reporters=[], confirmed=False)
                self.pending.append(item)
                self.pending_vectors = np.vstack([self.pending_vectors, vec[None, :]])
                target = len(self.pending) - 1
            item = self.pending[target]
            if reporter_hash not in item.reporters:
                item.reporters.append(reporter_hash)
                item.reports += 1
            item.last_seen = time.time()

            # 3) Enough independent reporters → confirmed → joins the memory right now.
            if item.reports >= self.confirmations:
                item.confirmed = True
                self.items.append(item)
                self.vectors = np.vstack([self.vectors, self.pending_vectors[target][None, :]])
                self.pending.pop(target)
                self.pending_vectors = np.delete(self.pending_vectors, target, axis=0)
                self._save_runtime()
                return {"status": "confirmed", "reports": item.reports, "match": item.public(1.0)}
            self._save_runtime()
            return {"status": "pending", "reports": item.reports, "needed": self.confirmations}

    def confirmed_reports(self) -> list[MemoryItem]:
        return [i for i in self.items if i.source == "report"]

    def stats(self) -> dict:
        labels = [i.label for i in self.items]
        return {
            "size": len(self.items), "scams": labels.count("scam"), "genuine": labels.count("legit"),
            "confirmed_reports": len(self.confirmed_reports()), "pending_reports": len(self.pending),
            "confirmations_required": self.confirmations,
            "match_threshold": self.calibration.match,
        }
