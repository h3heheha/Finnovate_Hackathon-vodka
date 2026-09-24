from ...core.config import Settings
from .base import AIAnalyzer, AIFinding, AIResult, NoAI


def build_analyzer(settings: Settings) -> AIAnalyzer:
    """Pick the AI provider from settings. Falls back to rules-only when not configured."""
    if settings.ai_provider == "anthropic" and settings.anthropic_api_key:
        from .anthropic_provider import AnthropicAnalyzer
        return AnthropicAnalyzer(settings.anthropic_api_key, settings.anthropic_model, settings.ai_timeout_seconds)
    return NoAI()


__all__ = ["AIAnalyzer", "AIFinding", "AIResult", "NoAI", "build_analyzer"]
