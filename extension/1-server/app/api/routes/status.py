"""Which outside services really work on this server (shown in the extension's Settings)."""
import time

from fastapi import APIRouter, Depends

from ...engine.ai import NoAI
from ...intel.service import selftest
from ..deps import get_analyzer, get_intel

router = APIRouter(prefix="/status", tags=["System"])

AI_SIGNUP = {"groq": "https://console.groq.com/keys", "gemini": "https://aistudio.google.com/apikey",
             "anthropic": "https://console.anthropic.com/"}
AI_ENV = {"groq": "FRAUDLENS_GROQ_API_KEY", "gemini": "FRAUDLENS_GEMINI_API_KEY",
          "anthropic": "FRAUDLENS_ANTHROPIC_API_KEY"}
_ai_cache: tuple[float, dict] | None = None
_ai_lock = None


async def _ai_entry(analyzer) -> dict:
    global _ai_lock
    if _ai_lock is None:
        import asyncio
        _ai_lock = asyncio.Lock()
    async with _ai_lock:
        return await _ai_entry_locked(analyzer)


async def _ai_entry_locked(analyzer) -> dict:
    global _ai_cache
    ai = analyzer.ai
    if isinstance(ai, NoAI):
        return {"id": "ai", "name": "AI explanations", "state": "not_set",
                "detail": "No AI key: rules + our own ML models still work. Free option: Groq.",
                "env": "FRAUDLENS_GROQ_API_KEY", "signup": AI_SIGNUP["groq"]}
    if _ai_cache and time.time() - _ai_cache[0] < 1800:
        return _ai_cache[1]
    ok, detail = await ai.selftest()
    entry = {"id": "ai", "name": f"AI explanations ({ai.name})", "state": "working" if ok else "error",
             "detail": detail, "env": AI_ENV.get(ai.name), "signup": AI_SIGNUP.get(ai.name)}
    _ai_cache = (time.time(), entry)
    return entry


@router.get("/providers", summary="Live self-test of every outside service (cached 30 minutes)")
async def providers(analyzer=Depends(get_analyzer), intel=Depends(get_intel)) -> dict:
    items = [await _ai_entry(analyzer)]
    if intel is None:
        items.append({"id": "intel", "name": "Threat intelligence", "state": "off",
                      "detail": "FRAUDLENS_INTEL_ENABLED=false on the server", "env": None, "signup": None})
    else:
        items += await selftest(intel)
    return {"checked_at": int(time.time()), "providers": items}
