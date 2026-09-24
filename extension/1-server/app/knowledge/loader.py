"""Loads the static knowledge files (directory, samples, quiz) once."""
import json
from functools import lru_cache
from pathlib import Path

_DIR = Path(__file__).parent


def _load(name: str):
    with open(_DIR / name, encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache
def directory() -> dict:
    return _load("directory.json")


@lru_cache
def organisations() -> list[dict]:
    return directory()["organisations"]


@lru_cache
def official_domains() -> dict[str, dict]:
    """Map every official registered domain (e.g. 'mcb.mu') to its organisation."""
    return {d: org for org in organisations() for d in org["domains"]}


def organisation(org_id: str) -> dict | None:
    return next((o for o in organisations() if o["id"] == org_id), None)


@lru_cache
def samples() -> list[dict]:
    return _load("samples.json")


@lru_cache
def quiz() -> list[dict]:
    return _load("quiz.json")


@lru_cache
def protected_numbers() -> set[str]:
    """Official numbers (directory 'phone' fields + 'never_flag_numbers') in the normalised form
    used for identifiers. These are never flagged, so nobody can make a bank hotline look like a scam."""
    import re

    def norm(raw: str) -> str:
        digits = re.sub(r"\D", "", raw or "")
        return digits[3:] if digits.startswith("230") and len(digits) > 8 else digits

    d = directory()
    raw = [o.get("phone") for o in d["organisations"]] + list(d.get("never_flag_numbers", []))
    return {n for n in (norm(r) for r in raw if r) if len(n) >= 7}
