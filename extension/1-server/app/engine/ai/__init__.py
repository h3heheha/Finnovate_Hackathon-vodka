from ...core.budget import Allowance
from ...core.config import Settings
from .base import AIAnalyzer, AIFinding, AIResult, NoAI


def build_analyzer(settings: Settings) -> AIAnalyzer:
    """Pick the AI provider from settings (see Settings.ai_choice). Rules-only when none is configured."""
    choice = settings.ai_choice
    allowance = Allowance(settings.ai_daily_limit, settings.ai_per_minute)
    if choice == "groq":
        from .openai_compat import OpenAICompatAnalyzer
        return OpenAICompatAnalyzer("groq", settings.groq_api_key, settings.groq_model,
                                    settings.ai_timeout_seconds, allowance)
    if choice == "gemini":
        from .openai_compat import OpenAICompatAnalyzer
        return OpenAICompatAnalyzer("gemini", settings.gemini_api_key, settings.gemini_model,
                                    settings.ai_timeout_seconds, allowance)
    if choice == "anthropic":
        from .anthropic_provider import AnthropicAnalyzer
        return AnthropicAnalyzer(settings.anthropic_api_key, settings.anthropic_model, settings.ai_timeout_seconds,
                                 allowance=allowance)
    return NoAI()


__all__ = ["AIAnalyzer", "AIFinding", "AIResult", "NoAI", "build_analyzer"]
