"""Versioned model artifacts with champion/challenger promotion and rollback.

models/artifacts/<embedder-id>/
    current.json            {"version": "v20260923-1405"}  <- the champion
    v20260923-1405/
        classifier.onnx     scam classifier (logistic regression, ONNX)
        combiner.json       learned weights for combining the layers
        calibration.json    similarity thresholds for the scam memory
        memory_seed.npz     embeddings of training messages (scam + genuine)
        memory_seed.json    their redacted text / labels / categories
        metrics.json        evaluation results used for promotion
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path


class Registry:
    def __init__(self, models_dir: Path, embedder_id: str):
        self.base = models_dir / "artifacts" / embedder_id
        self.base.mkdir(parents=True, exist_ok=True)
        self.pointer = self.base / "current.json"

    def current_version(self) -> str | None:
        if self.pointer.exists():
            return json.loads(self.pointer.read_text(encoding="utf-8")).get("version")
        return None

    def current_dir(self) -> Path | None:
        v = self.current_version()
        d = self.base / v if v else None
        return d if d and d.exists() else None

    def new_version_dir(self) -> Path:
        """A fresh folder per training run. Two runs in the same second get -2, -3… so a new
        model can never overwrite the champion it is being compared against."""
        stamp = time.strftime("v%Y%m%d-%H%M%S")
        d, n = self.base / stamp, 1
        while True:
            try:
                d.mkdir(parents=True, exist_ok=False)
                return d
            except FileExistsError:
                n += 1
                d = self.base / f"{stamp}-{n}"

    def promote(self, version_dir: Path) -> None:
        tmp = self.pointer.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": version_dir.name, "promoted_at": time.time()}), encoding="utf-8")
        tmp.replace(self.pointer)

    def versions(self) -> list[dict]:
        out = []
        for d in sorted(self.base.glob("v*"), reverse=True):
            m = d / "metrics.json"
            if not m.exists():  # an interrupted training run: never offer it for rollback
                continue
            out.append({"version": d.name, "current": d.name == self.current_version(),
                        "metrics": json.loads(m.read_text(encoding="utf-8")) if m.exists() else None})
        return out

    def rollback(self) -> str | None:
        """Point back to the previous version (if any)."""
        names = [v["version"] for v in self.versions()]
        cur = self.current_version()
        if cur in names and names.index(cur) + 1 < len(names):
            prev = self.base / names[names.index(cur) + 1]
            self.promote(prev)
            return prev.name
        return None

    def discard(self, version_dir: Path) -> None:
        shutil.rmtree(version_dir, ignore_errors=True)
