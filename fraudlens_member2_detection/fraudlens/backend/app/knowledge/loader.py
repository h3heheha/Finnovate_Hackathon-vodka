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
