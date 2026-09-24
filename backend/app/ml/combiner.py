"""Combines every verification layer into one explainable risk probability.

Signals (all 0..1):
    rules       rule-engine score (tactics, links, combos, trust signals)
    classifier  AI language model: probability the message is a scam
    memory      how strongly it matches a confirmed scam in the scam memory
    genuine     how strongly it matches a confirmed genuine message
    url         phishing probability from the pre-trained URL model (max over links)
    community   1 if a number/account/link in it was reported by other users
    hard_flag   1 if it asks for codes, money, a new account or crypto

Two modes:
  * default  - hand-set, documented noisy-OR (used until you train).
  * learned  - logistic regression fitted by scripts/train.py on your labelled data.
Both return points per layer that add up exactly to the final score, so the app
can show "how the score was built".
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

FEATURES = ["rules", "classifier", "memory", "genuine", "url", "community", "hard_flag"]
LABELS = {
    "rules": "Warning-sign rules",
    "classifier": "AI language model",
    "memory": "Scam memory",
    "url": "Link model",
    "community": "Community reports",
}
MATCH_FLOOR = 0.85  # a confirmed-scam match always means at least 85/100


@dataclass
class Signals:
    rules: float
    classifier: float | None = None
    memory: float = 0.0
    genuine: float = 0.0
    url: float | None = None
    community: float = 0.0
    hard_flag: float = 0.0

    def vector(self, defaults: dict[str, float]) -> list[float]:
        out = []
        for f in FEATURES:
            v = getattr(self, f)
            out.append(defaults.get(f, 0.0) if v is None else float(v))
        return out


@dataclass
class Combined:
    probability: float
    breakdown: list[dict]
    notes: list[str] = field(default_factory=list)
    mode: str = "default"
    weights: dict[str, float] = field(default_factory=dict)  # evidence per layer, turned into points


def _points(final_score: int, weights: dict[str, float]) -> list[dict]:
    positive = {k: v for k, v in weights.items() if v > 1e-6}
    total = sum(positive.values())
    if final_score <= 0 or total <= 0:
        return []
    items = [{"source": k, "label": LABELS[k], "points": int(round(final_score * v / total))}
             for k, v in positive.items()]
    drift = final_score - sum(i["points"] for i in items)
    if items and drift:
        max(items, key=lambda i: i["points"])["points"] += drift
    items = [i for i in items if i["points"] > 0]
    return sorted(items, key=lambda i: -i["points"])


class Combiner:
    def __init__(self, params: dict | None = None):
        self.params = params
        self.mode = "learned" if params else "default"

    @classmethod
    def load(cls, path: Path | None) -> "Combiner":
        if path and path.exists():
            return cls(json.loads(path.read_text(encoding="utf-8")))
        return cls()

    def combine(self, s: Signals) -> Combined:
        result = self._learned(s) if self.params else self._default(s)
        if s.memory >= 1.0 and result.probability < MATCH_FLOOR:
            others = sum(v for k, v in result.weights.items() if k != "memory")
            result.weights["memory"] = max(result.weights.get("memory", 0.0), 1.5 * others, 1.0)
            result.probability = MATCH_FLOOR
            result.notes = [n for n in result.notes if "lower" not in n]
            result.notes.append("Matches a confirmed scam in the FraudLens memory, so the score is at least 85.")
        return result

    # ---- default: transparent noisy-OR -------------------------------------------
    def _default(self, s: Signals) -> Combined:
        parts = {
            "rules": s.rules,
            "classifier": 0.75 * max(0.0, (s.classifier - 0.5) / 0.5) if s.classifier is not None else 0.0,
            "memory": 0.92 * s.memory,
            "url": 0.6 * max(0.0, (s.url - 0.5) / 0.5) if s.url is not None else 0.0,
            "community": min(0.8, 0.5 + 0.1 * (s.community - 1)) if s.community > 0 else 0.0,
        }
        remaining = 1.0
        for v in parts.values():
            remaining *= 1 - min(v, 0.99)
        p = 1 - remaining
        notes = []
        if not s.hard_flag and s.memory < 0.5:
            if s.classifier is not None and s.classifier < 0.25:
                p *= 0.75
                notes.append("The AI language model reads this as a normal message, so the score was lowered.")
            if s.genuine >= 0.8:
                p *= 1 - 0.4 * s.genuine
                notes.append("Very similar to genuine messages FraudLens has seen, so the score was lowered.")
        weights = {k: -math.log(1 - min(v, 0.99)) for k, v in parts.items()}
        return Combined(probability=p, breakdown=[], notes=notes, mode="default", weights=weights)

    # ---- learned: logistic regression -------------------------------------------
    def _learned(self, s: Signals) -> Combined:
        p = self.params
        x = s.vector(p["means"])
        terms = {}
        z = p["intercept"]
        for f, xi, w, m, sd in zip(FEATURES, x, p["coefs"], [p["means"][f] for f in FEATURES],
                                   [p["scales"][f] for f in FEATURES]):
            t = w * (xi - m) / (sd or 1.0)
            terms[f] = t
            z += t
        prob = 1 / (1 + math.exp(-z))
        notes = []
        if terms.get("genuine", 0) < -0.3 or terms.get("classifier", 0) < -0.3:
            notes.append("Parts of this message look like genuine messages, which lowered the score.")
        weights = {k: max(0.0, v) for k, v in terms.items() if k in LABELS}
        return Combined(probability=prob, breakdown=[], notes=notes, mode="learned", weights=weights)

    @staticmethod
    def finalize(c: Combined, final_score: int) -> Combined:
        c.breakdown = _points(final_score, c.weights)
        return c


def fit(X, y) -> dict:
    """Fit the learned combiner. X columns follow FEATURES."""
    import numpy as np
    from sklearn.linear_model import LogisticRegression

    X = np.asarray(X, dtype=float)
    means = X.mean(axis=0)
    scales = X.std(axis=0)
    scales[scales == 0] = 1.0
    Z = (X - means) / scales
    lr = LogisticRegression(C=0.3, max_iter=1000, class_weight="balanced").fit(Z, y)
    return {
        "features": FEATURES,
        "coefs": [float(c) for c in lr.coef_[0]],
        "intercept": float(lr.intercept_[0]),
        "means": {f: float(m) for f, m in zip(FEATURES, means)},
        "scales": {f: float(s) for f, s in zip(FEATURES, scales)},
    }
