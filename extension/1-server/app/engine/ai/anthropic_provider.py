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

    def __init__(self, api_key: str, model: str, timeout: float = 8.0, transport: httpx.AsyncBaseTransport | None = None,
                 allowance=None):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self._transport = transport  # injectable for tests
        self.allowance = allowance
        self.last_error: str | None = None

    async def selftest(self) -> tuple[bool, str]:
        r = await self.analyze("Hello, see you at dinner tonight.", [], "en")
        return (r.error is None), (r.error or f"model {self.model} answered")

    async def analyze(self, redacted_text: str, rule_tactics: list[str], language: str) -> AIResult:
        if self.allowance is not None:
            why_not = self.allowance.take()
            if why_not:
                return AIResult(provider=self.name, error=f"skipped: {why_not}")
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
            result = parse_response(text, self.name)
            self.last_error = result.error
            return result
        except Exception as exc:  # network, auth, parsing: never break the analysis
            self.last_error = f"{type(exc).__name__}: {exc}"[:200]
            return AIResult(provider=self.name, error=self.last_error)


def _unit(v, default: float) -> float:
    try:
        return min(1.0, max(0.0, float(v)))
    except (TypeError, ValueError):
        return default


def parse_response(text: str, provider: str) -> AIResult:
    """Read the model's JSON. Anything malformed is dropped, never trusted."""
    match = re.search(r"\{.*\}", text or "", re.S)
    if not match:
        return AIResult(provider=provider, error="No JSON in model response")
    try:
        payload = json.loads(match.group(0))
    except ValueError:
        return AIResult(provider=provider, error="Model reply was not valid JSON")
    if not isinstance(payload, dict):
        return AIResult(provider=provider, error="Model reply was not a JSON object")
    findings = []
    for f in payload.get("findings") or []:
        if isinstance(f, dict) and f.get("tactic") in TACTICS and f.get("quote"):
            findings.append(AIFinding(
                tactic=f["tactic"], quote=str(f["quote"])[:300], explanation=str(f.get("explanation", ""))[:300],
                confidence=_unit(f.get("confidence"), 0.7),
            ))
    likelihood = payload.get("scam_likelihood")
    summary = payload.get("summary")
    return AIResult(
        findings=findings[:8],
        summary=str(summary) if isinstance(summary, str) else None,
        category=payload.get("category") if isinstance(payload.get("category"), str) else None,
        scam_likelihood=_unit(likelihood, 0.5) if likelihood is not None else None,
        provider=provider,
    )
