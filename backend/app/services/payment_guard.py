"""Pause-Before-Pay: risk check run at the moment a customer confirms a payment.

Banks would call this from their payment flow (or embed it via the SDK).
It combines what FraudLens already knows (scanned messages, community-flagged
accounts) with simple transaction heuristics.
"""
import re

from ..core.config import Settings
from ..schemas.payment import PaymentCheckRequest
from .store import Store

_SUSPICIOUS_REFERENCE = re.compile(
    r"\b(?:fee|customs|release|unlock|verification|verify|tax|prize|lottery|investment|invest|crypto|"
    r"deposit|refund|activation|clearance|frais|douane)\b", re.I)


def check_payment(req: PaymentCheckRequest, store: Store, settings: Settings) -> dict:
    reasons: list[dict] = []
    score = 0
    cur = "Rs" if req.currency.upper() in ("MUR", "RS") else req.currency

    linked = store.get_analysis(req.source_analysis_id) if req.source_analysis_id else None
    if linked and linked["risk_level"] == "high":
        score = max(score, linked["risk_score"])
        reasons.append({"severity": "danger",
                        "text": f"This payment comes from a message we rated {linked['risk_score']}/100 "
                                f"(likely scam)."})
    elif linked and linked["risk_level"] == "medium":
        score = max(score, linked["risk_score"])
        reasons.append({"severity": "warning", "text": "This payment comes from a message with warning signs."})

    flagged = store.flagged(req.payee_account)
    if flagged:
        score = max(score, 90)
        n = flagged["reports"]
        reasons.append({"severity": "danger",
                        "text": f"This account number appeared in {n} message{'s' if n > 1 else ''} "
                                f"flagged as scams."})

    if req.reference and _SUSPICIOUS_REFERENCE.search(req.reference):
        score = max(score, 45)
        reasons.append({"severity": "warning",
                        "text": f"The reference '{req.reference}' matches common scam payment reasons."})

    if not req.is_saved_payee:
        if req.amount >= settings.large_payment_threshold:
            score = max(score, 40)
            reasons.append({"severity": "warning",
                            "text": f"First payment of {cur} {req.amount:,.0f} to a new payee."})
        else:
            score = max(score, 10)
            reasons.append({"severity": "info", "text": "You haven't paid this account before."})

    has_danger = any(r["severity"] == "danger" for r in reasons)
    has_warning = any(r["severity"] == "warning" for r in reasons)
    if has_danger:
        decision, headline = "pause", "Stop. This payment looks like a scam."
    elif has_warning:
        decision, headline = "warn", "Check before you send."
    else:
        decision, headline = "allow", "No warning signs for this payment."

    safe_actions = [
        {"id": "call_bank", "title": "Call your bank",
         "detail": "Use the number on the back of your card, never one from a message."},
        {"id": "ask_trusted", "title": "Ask someone you trust",
         "detail": "Share the details with a family member or your guardian contact first."},
        {"id": "verify_payee", "title": "Verify the person",
         "detail": "Call them on a number you already had, not the one that messaged you."},
    ]
    return {
        "decision": decision,
        "risk_score": score,
        "headline": headline,
        "reasons": reasons,
        "safe_actions": safe_actions if decision != "allow" else [],
        "cooldown_seconds": settings.pause_cooldown_seconds if decision == "pause" else 0,
        "verification_message": ("Before I send this payment, I need to confirm it's really you. "
                                 "I'll call you on the number I already have."),
    }
