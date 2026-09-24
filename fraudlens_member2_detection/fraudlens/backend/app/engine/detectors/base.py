"""Shared types for the detection pipeline."""
from dataclasses import dataclass, field


@dataclass
class Signal:
    """One warning sign found in a message."""

    tactic: str                 # key into knowledge.tactics.TACTICS
    evidence: str               # the exact text that triggered it
    start: int | None = None    # character offsets in the ORIGINAL message
    end: int | None = None
    weight: float | None = None  # overrides the tactic's base weight when set
    detail: str | None = None   # extra, signal-specific explanation
    source: str = "rule"        # "rule" | "ai" | "combo"


@dataclass
class Entities:
    """Things extracted from the message that other features can act on."""

    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)      # account numbers / IBANs
    wallets: list[str] = field(default_factory=list)       # crypto wallets
    amounts: list[str] = field(default_factory=list)
    brands: list[str] = field(default_factory=list)        # organisation ids mentioned
    official_links: list[str] = field(default_factory=list)  # links to verified domains


@dataclass
class DetectionContext:
    """Passed through every detector: the text plus what earlier detectors found."""

    text: str
    lower: str
    entities: Entities = field(default_factory=Entities)
    trust_notes: list[str] = field(default_factory=list)   # reasons the message looks genuine
    sender: str | None = None                               # name/number shown by the phone

    @classmethod
    def from_text(cls, text: str, sender: str | None = None) -> "DetectionContext":
        return cls(text=text, lower=text.lower(), sender=sender)
