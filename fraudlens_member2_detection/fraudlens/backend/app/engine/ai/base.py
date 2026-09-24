"""Interface for the optional AI layer.

The rule engine always runs. An AI provider can add signals the rules missed
(new wording, context, sarcasm) and write a friendlier summary. Providers only
ever receive REDACTED text. To add a provider (OpenAI, Gemini, a local model),
subclass AIAnalyzer and register it in engine/ai/__init__.py.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class AIFinding:
    tactic: str
    quote: str          # exact words from the message
    explanation: str
    confidence: float = 0.7


@dataclass
class AIResult:
    findings: list[AIFinding] = field(default_factory=list)
    summary: str | None = None
    category: str | None = None
    scam_likelihood: float | None = None
    provider: str = ""
    error: str | None = None


class AIAnalyzer(ABC):
    name: str = "base"

    @abstractmethod
    async def analyze(self, redacted_text: str, rule_tactics: list[str], language: str) -> AIResult:
        ...


class NoAI(AIAnalyzer):
    name = "none"

    async def analyze(self, redacted_text: str, rule_tactics: list[str], language: str) -> AIResult:
        return AIResult(provider=self.name)
