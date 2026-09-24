"""MLService: loads every verification model once and answers the pipeline's questions.

Layers (each optional, the system degrades gracefully):
    embedder    e5-small ONNX (or hashing fallback)
    classifier  ONNX logistic regression trained on your labelled data
    memory      scam memory (instant learning from confirmed reports)
    url model   pre-trained ONNX phishing-URL model
    combiner    default noisy-OR or learned logistic regression
"""
from __future__ import annotations

import csv
import json
import logging
import threading
from pathlib import Path

import numpy as np

from ..core.config import Settings
from ..engine.redaction import redact
from .classifier import OnnxClassifier
from .combiner import Combiner, Signals
from .embedders import load_embedder
from .memory import Calibration, MemoryItem, ScamMemory
from .registry import Registry
from .url_model import load_url_model

log = logging.getLogger("fraudlens.ml")
HARD_TACTICS = {"credential_request", "payment_request", "payment_redirection", "unusual_payment"}
SEED_FILE = "seed/curated_messages.csv"


def signals_from(*, rules_score: int, tactics: set[str], classifier_p: float | None, sim_scam: float | None,
                 sim_legit: float | None, memory: ScamMemory | None, url_probs: list[float] | None,
                 community: int) -> Signals:
    """The single place where layer outputs become combiner features.

    Used by live analysis AND by training, so the combiner always sees identical features.
    """
    mem = memory.strength(sim_scam) if memory else 0.0
    gen = memory.strength(sim_legit) if memory else 0.0
    if sim_scam is not None and sim_legit is not None and sim_legit >= sim_scam:
        mem *= 0.25  # closer to a genuine message than to any scam
    return Signals(
        rules=rules_score / 100.0,
        classifier=classifier_p,
        memory=mem,
        genuine=gen,
        url=max(url_probs) if url_probs else 0.0,
        community=float(community),
        hard_flag=1.0 if tactics & HARD_TACTICS else 0.0,
    )


def build_signals(*, rules_score: int, tactics: set[str], classifier_p: float | None, memory: ScamMemory | None,
                  vector: np.ndarray | None, url_probs: list[float] | None, community: int) -> tuple[Signals, dict]:
    best_scam = best_legit = None
    matches = []
    if memory is not None and vector is not None:
        best_scam, best_legit = memory.best(vector)
        matches = memory.search(vector, k=3)
    signals = signals_from(rules_score=rules_score, tactics=tactics, classifier_p=classifier_p,
                           sim_scam=best_scam[1] if best_scam else None,
                           sim_legit=best_legit[1] if best_legit else None,
                           memory=memory, url_probs=url_probs, community=community)
    return signals, {"best_scam": best_scam, "best_legit": best_legit, "matches": matches}


class MLService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._lock = threading.Lock()
        self.embedder = load_embedder(settings.embedder, settings.models_dir, settings.onnx_threads)
        self.url_model = load_url_model(settings.models_dir)
        self.registry = Registry(settings.models_dir, self.embedder.id)
        self.reload()

    # ---- loading ---------------------------------------------------------------------
    def reload(self) -> None:
        """(Re)load the champion artifacts. Called at start-up and after retraining."""
        with self._lock:
            art = self.registry.current_dir()
            self.version = art.name if art else None
            self.classifier = None
            if art and (art / "classifier.onnx").exists():
                clf = OnnxClassifier(art / "classifier.onnx")
                if clf.dim == self.embedder.dim:
                    self.classifier = clf
            self.combiner = Combiner.load(art / "combiner.json" if art else None)
            cal = None
            if art and (art / "calibration.json").exists():
                cal = Calibration(**json.loads((art / "calibration.json").read_text(encoding="utf-8")))
            runtime_dir = self.settings.data_dir / "runtime" / self.embedder.id
            memory = ScamMemory(self.embedder, runtime_dir, self.settings.report_confirmations, cal)
            if art and (art / "memory_seed.npz").exists():
                meta = json.loads((art / "memory_seed.json").read_text(encoding="utf-8"))
                vecs = np.load(art / "memory_seed.npz")["vectors"]
                memory.add_bulk([MemoryItem(**m) for m in meta], vecs)
            else:
                memory.add_bulk(self._bootstrap_items())
            memory.load_runtime()
            self.memory = memory
            log.info("ML ready: embedder=%s classifier=%s combiner=%s memory=%d url_model=%s",
                     self.embedder.id, bool(self.classifier), self.combiner.mode, len(memory.items),
                     bool(self.url_model))

    def _bootstrap_items(self) -> list[MemoryItem]:
        """Before any training: seed the memory with the curated messages."""
        items = []
        for row in read_seed_csv(self.settings.data_dir / SEED_FILE):
            items.append(MemoryItem(id=f"seed-{len(items)}", label=row["label"], text=redact(row["text"]).text,
                                    category=row.get("category") or "generic", source="seed", reports=1))
        # The demo samples are deliberately NOT added: they stay "unseen" so the demo shows the
        # full engine working, and they double as a small hold-out check.
        return items

    # ---- inference -------------------------------------------------------------------
    def embed(self, redacted_text: str) -> np.ndarray:
        return self.embedder.embed_one(redacted_text)

    def classify(self, vector: np.ndarray) -> float | None:
        if self.classifier is None:
            return None
        return float(self.classifier.predict_proba(vector[None, :])[0])

    def url_scores(self, urls: list[str]) -> list[float]:
        if not self.url_model or not urls:
            return []
        try:
            return self.url_model.predict(urls)
        except Exception as exc:
            log.warning("URL model failed: %s", exc)
            return []

    def verify(self, *, redacted_text: str, rules_score: int, tactics: set[str], urls: list[str],
               community: int) -> dict:
        vec = self.embed(redacted_text)
        clf_p = self.classify(vec)
        url_probs = self.url_scores(urls)
        signals, found = build_signals(rules_score=rules_score, tactics=tactics, classifier_p=clf_p,
                                       memory=self.memory, vector=vec, url_probs=url_probs, community=community)
        combined = self.combiner.combine(signals)
        return {"signals": signals, "combined": combined, "classifier": clf_p,
                "url_scores": list(zip(urls, url_probs)), "found": found}

    # ---- learning --------------------------------------------------------------------
    def report(self, redacted_text: str, label: str, reporter: str, category: str) -> dict:
        return self.memory.report(redacted_text, label, reporter, category)

    def status(self) -> dict:
        return {
            "embedder": self.embedder.id,
            "embedder_dim": self.embedder.dim,
            "classifier": "onnx-logreg" if self.classifier else None,
            "combiner": self.combiner.mode,
            "url_model": self.url_model.id if self.url_model else None,
            "model_version": self.version,
            "memory": self.memory.stats(),
        }


def read_seed_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as fh:
        return [r for r in csv.DictReader(fh) if r.get("text") and r.get("label") in ("scam", "legit")]
