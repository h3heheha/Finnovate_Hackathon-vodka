"""Dependency providers so routes stay thin and components are swappable in tests."""
import logging
from functools import lru_cache

from ..core.config import Settings, get_settings
from ..engine.ai import build_analyzer
from ..engine.pipeline import Analyzer
from ..services.store import Store, store

log = logging.getLogger("fraudlens")


@lru_cache
def get_ml():
    """The ML verification service, or None when disabled / unavailable (rules keep working)."""
    settings = get_settings()
    if not settings.ml_enabled:
        return None
    try:
        from ..ml.service import MLService
        return MLService(settings)
    except Exception as exc:  # never let a model problem take the API down
        log.exception("ML layer disabled: %s", exc)
        return None


@lru_cache
def get_intel():
    """Threat-intelligence service (Safe Browsing, URLhaus, RDAP, IPQS). None when disabled."""
    settings = get_settings()
    if not settings.intel_enabled:
        return None
    from ..intel.service import IntelService
    return IntelService(settings)


@lru_cache
def get_analyzer() -> Analyzer:
    settings = get_settings()
    return Analyzer(settings, build_analyzer(settings), ml=get_ml(), reputation=store.reputation,
                    intel=get_intel())


def get_store() -> Store:
    return store


def settings_dep() -> Settings:
    return get_settings()
