"""The FraudLens analysis pipeline.

    message ─► detectors (entities, phrases, sender) ─► redaction ─► LLM layer (optional)
            ─► rule scoring ─► ML verification (embeddings, classifier, scam memory,
               URL model, community reputation) ─► combiner ─► explanation + advice

Each stage is a small module so features can be added independently.
"""
import asyncio
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Callable

from ..core.config import Settings
from ..knowledge.tactics import TACTICS
from . import explain, redaction
from .ai import AIAnalyzer, NoAI
from .detectors import entities as entity_detector
from .detectors import phrases, sender as sender_detector
from .detectors.base import DetectionContext, Entities, Signal
from .scoring import ScoreResult, score

ENGINE_VERSION = "hybrid-0.2"
_ML_SLOTS = threading.BoundedSemaphore(2)   # at most 2 AI-model runs at once (small servers)


def _limited(fn, **kwargs):
    with _ML_SLOTS:
        return fn(**kwargs)
# Order matters: the sender check uses brands found by the entity detector.
DETECTORS = [entity_detector.detect, phrases.detect, sender_detector.detect]


def _locate(text: str, quote: str) -> tuple[int | None, int | None]:
    idx = text.lower().find(quote.lower())
    return (idx, idx + len(quote)) if idx >= 0 else (None, None)


def _dedupe(signals: list[Signal]) -> list[Signal]:
    """Drop signals of the same tactic that sit inside another one's span."""
    signals = sorted(signals, key=lambda s: (s.tactic, s.start if s.start is not None else -1,
                                             -((s.end or 0) - (s.start or 0))))
    kept: list[Signal] = []
    for s in signals:
        dup = False
        for k in kept:
            if k.tactic != s.tactic:
                continue
            if s.start is not None and k.start is not None and k.start <= s.start and s.end <= k.end:
                dup = True
                break
            if s.start is None and k.evidence.lower() == s.evidence.lower():
                dup = True
                break
        if not dup:
            kept.append(s)
    return kept


def normalise_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    return digits[3:] if digits.startswith("230") and len(digits) > 8 else digits


SENDER_NUMBER = re.compile(r"^\+?[\d\s\-().]{7,20}$")


def sender_identifier(sender: str | None) -> str | None:
    """A sender that is a phone number is remembered too, so a scam SMS also flags the number for calls."""
    from ..knowledge import loader
    if sender and SENDER_NUMBER.match(sender.strip()) and len(normalise_phone(sender)) >= 7:
        if normalise_phone(sender) in loader.protected_numbers():
            return None
        return f"tel:{normalise_phone(sender)}"
    return None


AI_SUMMARY_MAX = 400


def ai_agrees(ai_result, level: str, medium: int, high: int) -> bool:
    """The LLM only gets to word the summary / pick the category when its own estimate lands on the
    same risk level as the engine. A prompt-injected message can't make the headline say 'genuine'
    next to a high score (AI findings can still only ADD warning signs)."""
    if ai_result is None or ai_result.error or ai_result.scam_likelihood is None:
        return False
    try:
        p = float(ai_result.scam_likelihood)
    except (TypeError, ValueError):
        return False
    if not 0.0 <= p <= 1.0:
        return False
    s = p * 100
    ai_level = "high" if s >= high else "medium" if s >= medium else "low"
    return ai_level == level


def identifiers(ent: Entities) -> list[str]:
    """Things worth remembering across users: accounts, wallets, phone numbers, link domains."""
    from .detectors.entities import SHORTENERS
    from ..knowledge import loader

    ids = list(ent.accounts) + list(ent.wallets)
    protected = loader.protected_numbers()  # official bank / hotline numbers are never flagged
    ids += [f"tel:{normalise_phone(p)}" for p in ent.phone_numbers
            if len(normalise_phone(p)) >= 7 and normalise_phone(p) not in protected]
    official = loader.official_domains()
    for url, dom in zip(ent.urls, ent.domains):
        if dom in official:
            continue
        ids.append(f"url:{url.lower()}" if dom in SHORTENERS else f"dom:{dom}")
    return ids


def _rescale_tactics(result: ScoreResult, rule_points: int) -> None:
    """Share the rules' points in the final score between the tactics (so the bars still add up)."""
    base = sum(t.contribution for t in result.tactics)
    if not result.tactics or base <= 0:
        for t in result.tactics:
            t.contribution = 0
        return
    for t in result.tactics:
        t.contribution = int(round(t.contribution * rule_points / base))
    drift = rule_points - sum(t.contribution for t in result.tactics)
    if drift:
        max(result.tactics, key=lambda t: t.contribution).contribution += drift


BLOCKLIST_FLOOR = 90  # a link on Google Safe Browsing / URLhaus always means at least 90/100


def intel_signals(text: str, report) -> list[Signal]:
    """Turn threat-intel findings into highlighted warning signs (danger/warning only)."""
    out = []
    for f in report.findings:
        if f.severity == "info" or f.weight <= 0:
            continue
        start = text.find(f.target) if f.target else -1
        span = (start, start + len(f.target)) if start >= 0 else (None, None)
        out.append(Signal("threat_intel", f.target, span[0], span[1], weight=f.weight,
                          detail=f"{f.title}: {f.detail} ({f.source})", source="rule"))
    return out


def _split_intel_points(breakdown: list[dict], result: ScoreResult) -> list[dict]:
    """Show threat-intel points as their own 'Threat intelligence' line instead of inside the rules."""
    intel = next((t for t in result.tactics if t.tactic == "threat_intel"), None)
    if not intel or intel.contribution <= 0:
        return breakdown
    out = []
    for b in breakdown:
        if b["source"] == "rules":
            left = b["points"] - intel.contribution
            if left > 0:
                out.append({**b, "points": left})
        else:
            out.append(b)
    n = sum(1 for s in intel.signals)
    out.append({"source": "intel", "label": "Threat intelligence", "points": intel.contribution,
                "detail": f"{n} finding(s) from security databases"})
    return sorted(out, key=lambda b: -b["points"])


class Analyzer:
    def __init__(self, settings: Settings, ai: AIAnalyzer | None = None, ml=None,
                 reputation: Callable[[list[str]], int] | None = None, intel=None):
        self.settings = settings
        self.ai = ai or NoAI()
        self.ml = ml                      # app.ml.service.MLService or None (rules only)
        self.reputation = reputation      # store.reputation
        self.intel = intel                # app.intel.service.IntelService or None

    def _level(self, s: int) -> str:
        return "high" if s >= self.settings.high_risk_threshold else \
            "medium" if s >= self.settings.medium_risk_threshold else "low"

    async def analyze(self, text: str, *, channel: str = "sms", sender: str | None = None,
                      language: str | None = None, use_ai: bool = True, use_intel: bool = True,
                      client: str | None = None) -> dict:
        t0 = time.perf_counter()
        ctx = DetectionContext.from_text(text, sender=sender)
        lang = language or phrases.detect_language(text)

        signals: list[Signal] = []
        for detector in DETECTORS:
            signals.extend(detector(ctx))

        # Privacy first: only redacted text is embedded, stored or sent to an AI model.
        red = redaction.redact(text)

        # The AI (redacted text) and the threat-intelligence checks (links + numbers only, never the
        # text) run at the same time, so a slow provider doesn't add up with the other.
        async def run_ai():
            if use_ai and not isinstance(self.ai, NoAI):
                return await self.ai.analyze(red.text, sorted({s.tactic for s in signals}), lang)
            return None

        async def run_intel():
            if use_intel and self.intel is not None and (ctx.entities.urls or ctx.entities.phone_numbers):
                prelim = score(_dedupe(list(signals)), ctx.trust_notes)
                return await self.intel.check(ctx.entities.urls, ctx.entities.phone_numbers,
                                              check_phones=prelim.score >= 20)
            return None

        ai_result, intel_report = await asyncio.gather(run_ai(), run_intel())
        if ai_result is not None:
            for f in ai_result.findings:
                start, end = _locate(text, f.quote)
                base = TACTICS[f.tactic].weight
                signals.append(Signal(f.tactic, f.quote, start, end, weight=round(base * f.confidence, 2),
                                      detail=f.explanation, source="ai"))
        if intel_report is not None:
            signals.extend(intel_signals(text, intel_report))

        signals = _dedupe(signals)
        result = score(signals, ctx.trust_notes, self.settings.medium_risk_threshold,
                       self.settings.high_risk_threshold)
        if intel_report is not None and intel_report.blocklisted and result.score < BLOCKLIST_FLOOR:
            result.score = BLOCKLIST_FLOOR
            result.level = self._level(BLOCKLIST_FLOOR)
        rules_score = result.score
        tactic_ids = {t.tactic for t in result.tactics}
        ent = ctx.entities
        ids = identifiers(ent)
        sender_id = sender_identifier(sender)
        if sender_id and sender_id not in ids:
            ids.append(sender_id)
        if self.reputation is None:
            community = 0
        else:
            community = self.reputation(ids, client) if client else self.reputation(ids)

        # ---- ML verification layer --------------------------------------------------
        verification = {"enabled": False}
        breakdown = [{"source": "rules", "label": "Warning-sign rules", "points": rules_score,
                      "detail": f"{len(result.tactics)} warning sign(s)"}] if rules_score else []
        memory_match = None
        if self.ml is not None:
            # CPU work (the AI language model) runs in a worker thread, so a slow check on a small
            # server doesn't freeze every other request; at most 2 run at once.
            v = await asyncio.to_thread(_limited, self.ml.verify, redacted_text=red.text, rules_score=rules_score,
                                        tactics=tactic_ids, urls=ent.urls, community=community, client=client)
            combined = v["combined"]
            if intel_report is not None and intel_report.blocklisted and combined.probability < BLOCKLIST_FLOOR / 100:
                combined.probability = BLOCKLIST_FLOOR / 100
                combined.notes.append("A security database lists this link as dangerous, so the score is at least 90.")
            final = int(round(combined.probability * 100))
            combined = self.ml.combiner.finalize(combined, final)
            result.score = final
            result.level = self._level(final)
            rule_points = next((b["points"] for b in combined.breakdown if b["source"] == "rules"), 0)
            _rescale_tactics(result, rule_points)
            verification, breakdown, memory_match = self._verification_payload(v, combined, community, result)
        else:
            _rescale_tactics(result, rules_score)

        breakdown = _split_intel_points(breakdown, result)

        category = explain.categorise(text, tactic_ids, ent, result.level)
        if memory_match and memory_match["category"] in explain.CATEGORIES and memory_match["category"] != "none":
            category = memory_match["category"]
        elif result.level != "low" and category == "none":
            category = "generic"
        agrees = ai_agrees(ai_result, result.level, self.settings.medium_risk_threshold,
                           self.settings.high_risk_threshold)
        if agrees and ai_result.category in explain.CATEGORIES and result.level != "low":
            category = ai_result.category

        summary = explain.summary(result, category)
        extra = explain.verification_sentence(verification, memory_match)
        if extra:
            summary = f"{extra} {summary}" if memory_match else f"{summary} {extra}"
        if agrees and ai_result.summary and len(str(ai_result.summary)) <= AI_SUMMARY_MAX:
            summary = str(ai_result.summary)

        tactics_out = []
        for ts in result.tactics:
            meta = TACTICS[ts.tactic]
            tactics_out.append({
                "tactic": ts.tactic, "label": meta.label, "short": meta.short, "description": meta.description,
                "color": meta.color, "icon": meta.icon, "weight": ts.weight, "contribution": ts.contribution,
                "evidence": list(dict.fromkeys(s.evidence for s in ts.signals)),
                "details": list(dict.fromkeys(s.detail for s in ts.signals if s.detail)),
            })

        signals_out = [{
            "tactic": s.tactic, "label": TACTICS[s.tactic].label, "evidence": s.evidence, "start": s.start,
            "end": s.end, "weight": s.weight if s.weight is not None else TACTICS[s.tactic].weight,
            "detail": s.detail, "source": s.source,
        } for s in sorted(signals, key=lambda s: s.start if s.start is not None else 10**6)]

        advice = explain.advice(result, category, ent)
        if memory_match:
            advice.insert(0, explain.known_scam_advice(memory_match))

        return {
            "analysis_id": uuid.uuid4().hex[:12],
            "created_at": datetime.now(timezone.utc),
            "risk_score": result.score,
            "risk_level": result.level,
            "verdict": explain.verdict(result.level),
            "summary": summary,
            "category": category,
            "category_label": explain.CATEGORIES[category],
            "language": lang,
            "tactics": tactics_out,
            "signals": signals_out,
            "segments": explain.segments(text, signals),
            "advice": advice,
            "verification_reply": explain.verification_reply(category, tactic_ids),
            "score_breakdown": breakdown,
            "verification": verification,
            "intel": intel_report.public() if intel_report is not None else
                     {"enabled": bool(self.intel is not None and use_intel), "findings": [], "providers": {},
                      "expanded_links": {}, "blocklisted": False, "score": 0.0, "latency_ms": 0},
            "entities": {
                "urls": ent.urls, "domains": list(dict.fromkeys(ent.domains)),
                "phone_numbers": ent.phone_numbers, "accounts": ent.accounts, "wallets": ent.wallets,
                "amounts": ent.amounts, "brands": list(dict.fromkeys(ent.brands)),
                "official_links": ent.official_links,
            },
            "identifiers": ids,
            "redacted_text": red.text,
            "privacy": {
                "redacted_items": red.total, "redacted_types": red.counts,
                "ai_used": bool(ai_result and not ai_result.error),
                "ai_provider": self.ai.name if ai_result else "none",
                "ai_error": ai_result.error if ai_result else None,
            },
            "engine": {
                "version": ENGINE_VERSION,
                "latency_ms": int((time.perf_counter() - t0) * 1000),
                "rules_fired": len([s for s in signals if s.source == "rule"]),
                "rules_score": rules_score,
                "combos": [c.detail for c in result.combos],
                "trust_notes": ctx.trust_notes,
                "trust_applied": result.trust_applied,
            },
        }

    def _verification_payload(self, v: dict, combined, community: int, result: ScoreResult):
        ml = self.ml
        sig = v["signals"]
        found = v["found"]
        similar = []
        for item, sim in found["matches"]:
            if sim < ml.memory.calibration.low:
                continue
            d = item.public(sim)
            d["strength"] = round(ml.memory.strength(sim), 2)
            d["category_label"] = explain.CATEGORIES.get(item.category, "Suspicious request") \
                if item.label == "scam" else "Genuine message"
            similar.append(d)
        memory_match = None
        if found["best_scam"] and sig.memory >= 1.0:
            item, sim = found["best_scam"]
            memory_match = item.public(sim)
            memory_match["category_label"] = explain.CATEGORIES.get(item.category, "Suspicious request")

        details = {
            "rules": f"{len(result.tactics)} warning sign(s) found by the rule engine",
            "classifier": (f"Wording is {v['classifier']:.0%} scam-like" if v["classifier"] is not None else ""),
            "memory": (f"{found['best_scam'][1]:.0%} similar to a known scam "
                       f"({explain.CATEGORIES.get(found['best_scam'][0].category, 'scam').lower()})"
                       if found["best_scam"] else ""),
            "url": (f"Link rated {max(p for _, p in v['url_scores']):.0%} likely phishing"
                    if v["url_scores"] else ""),
            "community": (f"Seen in {community} earlier flagged message(s) (your own scans or confirmed user reports)"
                          if community else ""),
        }
        breakdown = [{**b, "detail": details.get(b["source"], "")} for b in combined.breakdown]
        verification = {
            "enabled": True,
            "mode": combined.mode,
            "embedder": ml.embedder.id,
            "model_version": ml.version,
            "classifier_probability": v["classifier"],
            "similar": similar,
            "memory_match": memory_match,
            "links": [{"url": u, "phishing_probability": round(p, 3)} for u, p in v["url_scores"]],
            "community_reports": community,
            "layers": {k: (round(getattr(sig, k), 3) if getattr(sig, k) is not None else None)
                       for k in ("rules", "classifier", "memory", "genuine", "url", "community")},
            "notes": combined.notes,
        }
        return verification, breakdown, memory_match
