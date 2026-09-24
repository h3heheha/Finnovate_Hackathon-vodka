"""Claude-based analyzer using the Anthropic Messages API over plain HTTP (no extra SDK needed)."""
import json
import re

import httpx

from ...knowledge.tactics import TACTICS
from .base import AIAnalyzer, AIFinding, AIResult

API_URL = "https://api.anthropic.com/v1/messages"

SYSTEM_PROMPT = """You are FraudLens, a fraud-awareness assistant for bank customers in Mauritius.
You analyse ONE message the customer received and explain scam warning signs in plain, calm language.
Personal data has been replaced with placeholders like [PHONE] or [ACCOUNT]; treat them as normal values.

Allowed tactic ids:
{tactics}

Allowed categories: bank_impersonation, parcel_fee, family_emergency, investment, prize, job, generic, none

Reply with ONLY a JSON object, no prose, in this shape:
{{
  "findings": [{{"tactic": "<tactic id>", "quote": "<exact words copied from the message>", "explanation": "<one short sentence>", "confidence": 0.0-1.0}}],
  "category": "<category>",
  "scam_likelihood": 0.0-1.0,
  "summary": "<2 sentences max, written for a non-technical person, in {language_name}>"
}}
Rules: quotes must be copied exactly from the message. Do not invent findings. A genuine message can have zero findings."""

LANG_NAMES = {"en": "English", "fr": "French", "mfe": "simple English (the customer wrote in Kreol Morisien)"}


class AnthropicAnalyzer(AIAnalyzer):
    name = "anthropic"

    def __init__(self, api_key: str, model: str, timeout: float = 8.0, transport: httpx.AsyncBaseTransport | None = None):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self._transport = transport  # injectable for tests

    async def analyze(self, redacted_text: str, rule_tactics: list[str], language: str) -> AIResult:
        tactic_lines = "\n".join(f"- {t.id}: {t.label}" for t in TACTICS.values())
        system = SYSTEM_PROMPT.format(tactics=tactic_lines, language_name=LANG_NAMES.get(language, "English"))
        user = (f"Message received:\n<<<\n{redacted_text}\n>>>\n\n"
                f"Our rule engine already flagged: {', '.join(rule_tactics) or 'nothing'}. "
                f"Add anything it missed and confirm or refine.")
        body = {"model": self.model, "max_tokens": 900, "system": system,
                "messages": [{"role": "user", "content": user}]}
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self._transport) as client:
                resp = await client.post(API_URL, json=body, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            text = "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")
            return parse_response(text, self.name)
        except Exception as exc:  # network, auth, parsing: never break the analysis
            return AIResult(provider=self.name, error=f"{type(exc).__name__}: {exc}"[:200])


def parse_response(text: str, provider: str) -> AIResult:
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        return AIResult(provider=provider, error="No JSON in model response")
    payload = json.loads(match.group(0))
    findings = []
    for f in payload.get("findings", []):
        if f.get("tactic") in TACTICS and f.get("quote"):
            findings.append(AIFinding(
                tactic=f["tactic"], quote=str(f["quote"]), explanation=str(f.get("explanation", "")),
                confidence=float(f.get("confidence", 0.7)),
            ))
    likelihood = payload.get("scam_likelihood")
    return AIResult(
        findings=findings,
        summary=payload.get("summary"),
        category=payload.get("category"),
        scam_likelihood=float(likelihood) if likelihood is not None else None,
        provider=provider,
    )
