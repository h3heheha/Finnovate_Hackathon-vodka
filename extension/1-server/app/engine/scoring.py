"""Transparent risk scoring.

1. Each tactic gets the strongest weight among its signals, plus a small bonus
   for extra independent evidence (capped).
2. Some tactic pairs are far more dangerous together (e.g. "pretends to be your
   bank" + "asks for your OTP"); those add a combo signal.
3. Weights are combined like independent probabilities:
       risk = 1 - (1 - w1) * (1 - w2) * ...
   so every extra warning sign raises the score, but it never exceeds 100.
4. Trust signals (official links, "never share this code") dampen the score
   only when no hard red flag (credential/payment request, bad link) is present.

The per-tactic contributions are returned so the app can show exactly where
the score came from. Nothing is a black box.
"""
from dataclasses import dataclass

from ..knowledge.tactics import TACTICS
from .detectors.base import Signal

COMBOS: list[tuple[str, str, float, str]] = [
    ("authority", "credential_request", 0.30, "Pretends to be an organisation AND asks for your codes."),
    ("impersonation_personal", "payment_request", 0.35, "Claims to be someone you know AND asks for money."),
    ("impersonation_personal", "payment_redirection", 0.25, "Claims to be someone you know AND gives a new account."),
    ("urgency", "payment_request", 0.20, "Rushes you AND asks for money."),
    ("reward", "payment_request", 0.25, "Promises a reward AND asks you to pay first."),
    ("reward", "unusual_payment", 0.25, "Promises profits AND wants crypto or gift cards."),
    ("threat", "suspicious_link", 0.20, "Threatens you AND pushes a link."),
    ("secrecy", "payment_request", 0.20, "Asks for money AND tells you to keep it secret."),
]
HARD_FLAGS = {"credential_request", "payment_request", "payment_redirection", "unusual_payment"}
MAX_TACTIC_WEIGHT = 0.9


@dataclass
class TacticScore:
    tactic: str
    weight: float
    contribution: int
    signals: list[Signal]


@dataclass
class ScoreResult:
    score: int
    level: str
    tactics: list[TacticScore]
    combos: list[Signal]
    trust_applied: bool


def _signal_weight(sig: Signal) -> float:
    return sig.weight if sig.weight is not None else TACTICS[sig.tactic].weight


def score(signals: list[Signal], trust_notes: list[str], medium: int = 30, high: int = 60) -> ScoreResult:
    by_tactic: dict[str, list[Signal]] = {}
    for s in signals:
        if s.tactic in TACTICS:
            by_tactic.setdefault(s.tactic, []).append(s)

    weights: dict[str, float] = {}
    for tactic, sigs in by_tactic.items():
        base = max(_signal_weight(s) for s in sigs)
        distinct = len({s.evidence.lower() for s in sigs})
        bonus = min(0.1, 0.05 * (distinct - 1))
        weights[tactic] = min(MAX_TACTIC_WEIGHT, base + bonus)

    combos: list[Signal] = []
    for a, b, w, detail in COMBOS:
        if a in weights and b in weights:
            combos.append(Signal(tactic=f"{a}+{b}", evidence="", weight=w, detail=detail, source="combo"))

    all_weights = list(weights.values()) + [c.weight for c in combos]
    remaining = 1.0
    for w in all_weights:
        remaining *= (1 - w)
    raw = 1 - remaining

    trust_applied = False
    bad_link = any(_signal_weight(s) >= 0.3 for s in by_tactic.get("suspicious_link", []))
    if trust_notes and not (HARD_FLAGS & weights.keys()) and not bad_link:
        raw *= 0.5
        trust_applied = True

    final = int(round(raw * 100))
    level = "high" if final >= high else "medium" if final >= medium else "low"

    total_w = sum(all_weights) or 1.0
    tactic_scores = [
        TacticScore(t, round(w, 2), 0, by_tactic[t]) for t, w in weights.items()
    ]
    # Spread combo weight over the two tactics involved so contributions add up to the score.
    combo_share: dict[str, float] = {}
    for c in combos:
        for t in c.tactic.split("+"):
            combo_share[t] = combo_share.get(t, 0) + c.weight / 2
    for ts in tactic_scores:
        ts.contribution = int(round(final * (ts.weight + combo_share.get(ts.tactic, 0)) / total_w))
    # Fix rounding drift so the bars add up exactly to the headline score.
    drift = final - sum(ts.contribution for ts in tactic_scores)
    if tactic_scores and drift:
        top = max(tactic_scores, key=lambda x: x.contribution)
        top.contribution += drift
    tactic_scores.sort(key=lambda x: x.contribution, reverse=True)
    return ScoreResult(final, level, tactic_scores, combos, trust_applied)
