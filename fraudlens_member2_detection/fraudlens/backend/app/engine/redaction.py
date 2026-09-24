"""Privacy layer: strips personal data before any text leaves the server for an AI model.

The rule engine runs on the original text locally; only the redacted version is
ever sent to a third-party model. Placeholders keep the meaning of the message
("[CARD]", "[ACCOUNT]") so the model can still reason about it.
"""
import re
from dataclasses import dataclass, field

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,4})?\b")),
    ("CARD", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("NIC", re.compile(r"\b[A-Z]\d{12}[A-Z0-9]\b")),        # Mauritius National Identity Card
    ("ACCOUNT", re.compile(r"(?<![\w+])\d{9,20}\b")),
    ("PHONE", re.compile(r"(?:\+\d{1,3}[\s-]?)?\b\d{3,4}[\s-]?\d{4}\b")),
    ("CODE", re.compile(r"\b\d{4,8}\b")),                    # OTPs and PINs
]


def _luhn_ok(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)][::-1]
    total = sum(d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2) for i, d in enumerate(digits))
    return len(digits) >= 13 and total % 10 == 0


@dataclass
class RedactionResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def redact(text: str) -> RedactionResult:
    counts: dict[str, int] = {}
    out = text
    for label, pattern in _PATTERNS:
        def repl(m: re.Match, label=label) -> str:
            if label == "CARD" and not _luhn_ok(m.group(0)):
                return m.group(0)
            counts[label] = counts.get(label, 0) + 1
            return f"[{label}]"
        out = pattern.sub(repl, out)
    return RedactionResult(out, counts)
