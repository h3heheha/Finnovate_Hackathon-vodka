"""Free AI providers through the OpenAI-compatible chat API (plain HTTP, no SDK).

    groq    https://api.groq.com/openai/v1            free key at console.groq.com (no card)
    gemini  https://generativelanguage.googleapis.com/v1beta/openai   free key at aistudio.google.com

Same prompt and JSON answer as the Claude provider; the reply is parsed by the same parser, so the
rules keep the final say (see pipeline.ai_agrees). Any error (bad key, quota, timeout, odd reply)
just means "no AI this time": the analysis carries on with rules + ML.
"""
from __future__ import annotations

import httpx

from ...core.budget import Allowance
from ...knowledge.tactics import TACTICS
from .anthropic_provider import LANG_NAMES, SYSTEM_PROMPT, parse_response
from .base import AIAnalyzer, AIResult

PRESETS = {
    # gpt-oss models reason before answering: keep that short and out of the reply.
    "groq": {"base": "https://api.groq.com/openai/v1",
             "extra": {"reasoning_effort": "low", "include_reasoning": False,
                       "response_format": {"type": "json_object"}, "max_completion_tokens": 1500}},
    # Gemini 3 models always think a little; "low" keeps it quick.
    "gemini": {"base": "https://generativelanguage.googleapis.com/v1beta/openai",
               "extra": {"reasoning_effort": "low", "max_tokens": 2048}},
}


class OpenAICompatAnalyzer(AIAnalyzer):
    def __init__(self, name: str, api_key: str, model: str, timeout: float, allowance: Allowance,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.name = name
        self.api_key, self.model, self.timeout = api_key, model, timeout
        self.allowance = allowance
        self._transport = transport
        self.last_error: str | None = None

    async def chat(self, system: str, user: str) -> str:
        preset = PRESETS[self.name]
        body = {"model": self.model, "messages": [{"role": "system", "content": system},
                                                  {"role": "user", "content": user}],
                "temperature": 0.2, **preset["extra"]}
        async with httpx.AsyncClient(timeout=self.timeout, transport=self._transport) as client:
            r = await client.post(f"{preset['base']}/chat/completions", json=body,
                                  headers={"Authorization": f"Bearer {self.api_key}"})
        if r.status_code != 200:
            try:
                err = r.json()
                err = err[0] if isinstance(err, list) and err else err
                msg = (err.get("error") or {}).get("message") if isinstance(err, dict) else None
            except ValueError:
                msg = None
            raise RuntimeError(f"HTTP {r.status_code}: {(msg or r.text or '')[:160]}")
        choices = r.json().get("choices") or []
        content = (choices[0].get("message") or {}).get("content") if choices else None
        if not content:
            raise RuntimeError("empty reply from the model")
        return content

    async def analyze(self, redacted_text: str, rule_tactics: list[str], language: str) -> AIResult:
        why_not = self.allowance.take()
        if why_not:
            return AIResult(provider=self.name, error=f"skipped: {why_not}")
        tactic_lines = "\n".join(f"- {t.id}: {t.label}" for t in TACTICS.values())
        system = SYSTEM_PROMPT.format(tactics=tactic_lines, language_name=LANG_NAMES.get(language, "English"))
        user = (f"Message received:\n<<<\n{redacted_text}\n>>>\n\n"
                f"Our rule engine already flagged: {', '.join(rule_tactics) or 'nothing'}. "
                f"Add anything it missed and confirm or refine.")
        try:
            result = parse_response(await self.chat(system, user), self.name)
            self.last_error = result.error
            return result
        except Exception as exc:  # network, auth, quota, parsing: never break the analysis
            if isinstance(exc, (httpx.ConnectError, httpx.TimeoutException)):
                self.allowance.refund()
            self.last_error = f"{type(exc).__name__}: {exc}"[:200]
            return AIResult(provider=self.name, error=self.last_error)

    async def selftest(self) -> tuple[bool, str]:
        """One tiny request: proves the key, the model name and the free quota."""
        why_not = self.allowance.take()
        if why_not:
            return False, why_not
        try:
            reply = await self.chat('Reply with the JSON object {"ok": true} and nothing else.', "ping")
            return ("ok" in reply), f"model {self.model} answered"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"[:200]
