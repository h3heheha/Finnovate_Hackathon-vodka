"""Sender check: an organisation writing from a personal mobile number is a strong red flag.

Needs the `sender` field of the request (the name or number shown by the phone).
A brand counts as "claimed" when it appears near the start of the message
("MCB ALERT: ...", "Mauritius Post: ..."), not merely mentioned later on.
"""
import re

from ...knowledge import loader
from .base import DetectionContext, Signal

_PHONE = re.compile(r"^\+?[\d\s\-()]{7,}$")
CLAIM_WINDOW = 60  # characters from the start of the message
CLAIM_TYPES = ("bank", "regulator", "government", "courier", "payments")


def _claimed_org(lower_text: str) -> dict | None:
    head = lower_text[:CLAIM_WINDOW]
    for org in loader.organisations():
        if org["type"] not in CLAIM_TYPES:
            continue
        for kw in org["keywords"]:
            if re.search(rf"(?<![\w-]){re.escape(kw)}(?![\w-])", head):
                return org
    return None


def detect(ctx: DetectionContext) -> list[Signal]:
    sender = (ctx.sender or "").strip()
    if not sender or not _PHONE.match(sender):
        return []
    ctx.entities.phone_numbers.append(sender)
    org = _claimed_org(ctx.lower)
    if org:
        return [Signal("sender_mismatch", sender, None, None,
                       detail=f"Claims to be {org['name']} but was sent from a personal phone number ({sender}).")]
    return []
