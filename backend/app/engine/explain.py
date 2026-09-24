"""Turns signals and scores into plain-language explanations and safe next steps."""
import re

from ..knowledge import loader
from ..knowledge.tactics import TACTICS
from .detectors.base import Entities, Signal
from .scoring import ScoreResult

CATEGORIES = {
    "bank_impersonation": "Fake bank or official message",
    "parcel_fee": "Fake delivery / customs fee",
    "family_emergency": "Family or friend impersonation",
    "investment": "Investment / crypto scam",
    "prize": "Fake prize or lottery",
    "job": "Job or task scam",
    "generic": "Suspicious request",
    "none": "No scam pattern detected",
}

_KEYWORDS = {
    "parcel_fee": r"\b(?:parcel|package|colis|delivery|livraison|customs|douane|courier|shipment|dhl|post)\b",
    "investment": r"\b(?:invest\w*|crypto\w*|trading|forex|returns?|profit|usdt|bitcoin|rendement)\b",
    "prize": r"\b(?:won|winner|prize|lottery|loto|tiraz|gagn\w*|jackpot|reward)\b",
    "job": r"\b(?:job|work from home|from home|part[- ]time|task|commission|salary|recruit\w*|hiring)\b",
}


def categorise(text: str, tactics: set[str], entities: Entities, level: str) -> str:
    if level == "low" and not (tactics & {"credential_request", "payment_request", "unusual_payment"}):
        return "none"
    if "impersonation_personal" in tactics:
        return "family_emergency"
    for cat in ("parcel_fee", "investment", "prize", "job"):
        if re.search(_KEYWORDS[cat], text, re.I):
            return cat
    if "authority" in tactics or entities.brands:
        return "bank_impersonation"
    return "generic"


def verdict(level: str) -> str:
    return {
        "high": "Likely scam: do not pay or reply",
        "medium": "Be careful: verify before you act",
        "low": "No strong warning signs",
    }[level]


def summary(result: ScoreResult, category: str) -> str:
    if not result.tactics:
        if result.level != "low":
            return ("This message doesn't use the classic tricks our rules look for, but FraudLens's AI checks "
                    "flagged it as risky.")
        return ("We didn't find common scam warning signs in this message. If it asks you to pay "
                "or share details, still verify it through a channel you already trust.")
    top = [TACTICS[t.tactic].label.lower() for t in result.tactics[:4]]
    if len(top) > 1:
        listed = ", ".join(top[:-1]) + " and " + top[-1]
    else:
        listed = top[0]
    n = len(result.tactics)
    signs = "warning sign" if n == 1 else "warning signs"
    if result.level == "low":
        return f"We found {n} minor {signs} ({listed}), but nothing that strongly suggests a scam."
    cat = CATEGORIES.get(category, "scam").lower()
    return f"This message shows {n} {signs} typical of a {cat}: {listed}."


def _advice(id_: str, title: str, detail: str, action: str | None = None, payload: dict | None = None) -> dict:
    return {"id": id_, "title": title, "detail": detail, "action": action, "payload": payload or {}}


def advice(result: ScoreResult, category: str, entities: Entities) -> list[dict]:
    tactics = {t.tactic for t in result.tactics}
    out: list[dict] = []

    if result.level == "low":
        out.append(_advice("stay_alert", "Looks OK, stay alert",
                           "If this message later asks for money or codes, check again before acting."))
        return out

    if "credential_request" in tactics:
        out.append(_advice("no_codes", "Never share your OTP, PIN or password",
                           "No bank, courier or government office will ever ask for them by message or phone."))
    if "suspicious_link" in tactics:
        link_sig = next((s for t in result.tactics if t.tactic == "suspicious_link" for s in t.signals), None)
        detail = link_sig.detail if link_sig and link_sig.detail else "The link may lead to a fake page."
        out.append(_advice("no_link", "Don't tap the link", detail + " Open your official app instead."))

    for org_id in dict.fromkeys(entities.brands):
        org = loader.organisation(org_id)
        if not org:
            continue
        how = f"call {org['phone']}" if org.get("phone") else "use the number on the back of your card or on"
        out.append(_advice(
            f"call_{org_id}", f"Contact {org['name'].split(' (')[0]} directly",
            f"Don't use any number from this message. {how.capitalize()} {org['website']}.",
            action="call_official", payload={"org_id": org_id, "website": org["website"], "phone": org.get("phone")},
        ))
        break  # one official-contact card is enough

    if "impersonation_personal" in tactics:
        out.append(_advice("verify_person", "Call them on their old number",
                           "Or ask a question only the real person would know before sending anything.",
                           action="verify_contact"))
    if tactics & {"payment_request", "payment_redirection", "unusual_payment"}:
        out.append(_advice("pause_payment", "Don't send money yet",
                           "Check the request on a number you already trust, or ask someone you trust, "
                           "before paying anything.", action="share_guardian"))
    if category == "investment" or "reward" in tactics:
        out.append(_advice("check_fsc", "Check the company is licensed",
                           "Look it up on the Financial Services Commission website before investing anything.",
                           action="open_url", payload={"url": "https://www.fscmauritius.org"}))
    if "secrecy" in tactics:
        out.append(_advice("tell_someone", "Tell someone you trust",
                           "Scammers ask for secrecy because a second opinion stops scams.",
                           action="share_guardian"))
    if result.level == "high":
        rep = loader.directory()["reporting"][0]
        out.append(_advice("report", "Report and block the sender",
                           f"Report it on {rep['name']} and block the number so it can't target others.",
                           action="open_url", payload={"url": rep["website"]}))
    return out


def verification_reply(category: str, tactics: set[str]) -> str:
    """A ready-to-send reply that puts the burden of proof back on the sender."""
    if category == "family_emergency" or "impersonation_personal" in tactics:
        return ("Before I send anything I need to be sure it's you. I'm going to call your old number "
                "now. If you can't answer, send me a voice note saying the name of our first pet.")
    if category == "investment":
        return "Please send your FSC licence number. I will check it on the FSC website before I invest anything."
    return ("I don't act on payment or security requests by message. I will contact the organisation directly "
            "using the official number I already have.")


def segments(text: str, signals: list[Signal]) -> list[dict]:
    """Split the message into runs of plain / highlighted text for the Scam X-Ray view.

    When highlights overlap, the higher-weight tactic wins that character.
    """
    owner: list[tuple[float, str] | None] = [None] * len(text)
    for s in signals:
        if s.start is None or s.end is None or s.tactic not in TACTICS:
            continue
        w = s.weight if s.weight is not None else TACTICS[s.tactic].weight
        for i in range(max(0, s.start), min(len(text), s.end)):
            cur = owner[i]
            if cur is None or w > cur[0]:
                owner[i] = (w, s.tactic)

    out: list[dict] = []
    for i, ch in enumerate(text):
        tactic = owner[i][1] if owner[i] else None
        if out and out[-1]["tactic"] == tactic:
            out[-1]["text"] += ch
        else:
            out.append({"text": ch, "tactic": tactic})
    return out


def verification_sentence(verification: dict, memory_match: dict | None) -> str:
    """One extra sentence about what the ML layers found (empty when nothing notable)."""
    if not verification.get("enabled"):
        return ""
    if memory_match:
        n = memory_match["reports"]
        kind = "" if memory_match["category"] in ("generic", "none") else \
            f" ({memory_match['category_label'].lower()})"
        if memory_match["source"] == "report":
            who = f"reported by {n} people" if n > 1 else "reported by a FraudLens user"
            return f"It matches a scam{kind} {who} ({memory_match['similarity']:.0%} similar)."
        return f"It matches a known scam{kind} ({memory_match['similarity']:.0%} similar)."
    p = verification.get("classifier_probability")
    if p is not None and p >= 0.8:
        return f"Our AI language model also finds the wording typical of scams ({p:.0%})."
    links = verification.get("links") or []
    if links and max(l["phishing_probability"] for l in links) >= 0.8:
        return "Our link model rates the link as likely phishing."
    return ""


def known_scam_advice(match: dict) -> dict:
    return _advice(
        "known_scam", "This is a known scam",
        "FraudLens has seen this scam before. Don't reply, pay or click. "
        "Delete it and block the sender.",
    )
