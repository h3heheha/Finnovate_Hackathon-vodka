"""Threat-intelligence lookups for a single link or phone number.

Used by FraudLens Shield: the call screener checks the caller's number while the
phone is still ringing, and the app can check a link before the user taps it.
"""
from fastapi import APIRouter, Depends, HTTPException, Query

from ...engine.pipeline import normalise_phone
from ...services.store import Store
from ..deps import get_intel, get_store

router = APIRouter(prefix="/intel", tags=["Threat intelligence"])


def _level(score: float, community: int) -> str:
    if score >= 0.6 or community >= 2:
        return "high"
    if score >= 0.3 or community >= 1:
        return "medium"
    return "low"


# A warning while the phone rings must be rare and right: most unknown callers are genuine.
# Lookup services alone ("flag", "risky", foreign number, odd format) are shown as reasons but never
# raise the level; FraudLens user reports, fraud-linked numbers and VoIP / premium-rate lines do.
_CALL_WARNINGS = {"Internet (VoIP) number", "Premium-rate number"}


def _call_level(findings: list, community: int) -> str:
    fraud_linked = any(f.severity == "danger" and f.source == "IPQualityScore" for f in findings)
    danger = any(f.severity == "danger" for f in findings)
    if community >= 2 or fraud_linked or (danger and community >= 1):
        return "high"
    if community >= 1 or danger or any(f.severity == "warning" and f.title in _CALL_WARNINGS for f in findings):
        return "medium"
    return "low"


@router.get("/status", summary="Which providers are configured and today's paid-lookup usage")
async def status(intel=Depends(get_intel)) -> dict:
    return intel.status() if intel else {"enabled": False}


@router.get("/url", summary="Reputation of one link (Safe Browsing, URLhaus, domain age)")
async def check_url(url: str = Query(..., min_length=4, max_length=2000), intel=Depends(get_intel),
                    store: Store = Depends(get_store)) -> dict:
    if intel is None:
        raise HTTPException(409, "Threat intelligence is disabled")
    report = await intel.check([url], [], check_phones=False)
    return {"url": url, "risk_level": _level(report.score, 0), **report.public()}


@router.get("/phone", summary="Reputation of one phone number (Telesign / IPQS + offline number check + FraudLens reports)")
async def check_phone(number: str = Query(..., min_length=5, max_length=30), intel=Depends(get_intel),
                      store: Store = Depends(get_store)) -> dict:
    community = store.reputation([f"tel:{normalise_phone(number)}"])
    report = None
    if intel is not None:
        report = await intel.check([], [number], check_phones=True)
    score = report.score if report else 0.0
    level = _call_level(report.findings if report else [], community)
    headline = {"high": "Likely scam caller", "medium": "Be careful with this caller",
                "low": "No warning signs for this number"}[level]
    reasons = [f["title"] + ": " + f["detail"] for f in (report.public()["findings"] if report else [])]
    if community:
        reasons.insert(0, f"Appeared in {community} message(s) flagged as scams by FraudLens users.")
    return {"number": number, "risk_level": level, "headline": headline, "score": round(score, 3),
            "community_reports": community, "reasons": reasons,
            **({k: v for k, v in report.public().items() if k in ("providers", "findings", "latency_ms")}
               if report else {})}
