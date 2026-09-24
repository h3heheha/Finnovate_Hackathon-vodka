"""Application settings, loaded from environment variables or a .env file."""
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="FRAUDLENS_", extra="ignore")

    app_name: str = "FraudLens AI"
    version: str = "0.3.0"

    # --- Threat intelligence (external reputation checks) ---------------------------
    # Only URLs, domains and phone numbers are sent to these services, never message text.
    intel_enabled: bool = True
    intel_timeout_seconds: float = 2.5     # total budget; slow providers are skipped
    safe_browsing_key: str | None = None   # Google Safe Browsing v4 (non-commercial use)
    urlhaus_key: str | None = None         # abuse.ch Auth-Key
    ipqs_key: str | None = None            # IPQualityScore (phone reputation)
    ipqs_daily_limit: int = 30             # free plan allows 35/day; keep a margin
    ipqs_country: str = "MU"
    telesign_customer_id: str | None = None  # Telesign Intelligence (phone risk score 0-1000)
    telesign_api_key: str | None = None
    telesign_daily_limit: int = 30         # trial credits are limited; keep a margin
    telesign_base_url: str = "https://rest-ww.telesign.com"
    number_check: bool = True              # offline number facts (valid? mobile/VoIP? carrier) - free, no key
    rdap_enabled: bool = True
    expand_short_links: bool = True

    @field_validator("safe_browsing_key", "urlhaus_key", "ipqs_key", "telesign_customer_id", "telesign_api_key",
                     "anthropic_api_key", mode="before")
    @classmethod
    def _clean_key(cls, v):
        """Tolerate blank keys, stray spaces/quotes and inline "# comments" pasted into .env."""
        if v is None:
            return None
        v = str(v).strip()
        if not v or v.startswith("#"):
            return None
        v = v.split()[0].strip("\"'")
        return v or None

    # --- ML verification layer ----------------------------------------------------
    ml_enabled: bool = True
    # "auto" uses the ONNX multilingual-e5-small model when it has been downloaded
    # (python -m scripts.setup_ml), otherwise the built-in hashing embedder.
    embedder: str = "auto"                 # auto | e5 | hashing
    models_dir: Path = BACKEND_DIR / "models"
    data_dir: Path = BACKEND_DIR / "data"
    onnx_threads: int = 2
    # Number of independent reports before a reported message joins the scam memory.
    # 1 is handy for a live demo; use 2-3 in production to resist poisoning.
    # With 2+, reports AND caller reputation count *independent devices* (anti-poisoning).
    # 1 is a demo mode: every high-risk scan counts, so one phone can flag a caller on stage.
    report_confirmations: int = 2
    # Protects /admin/retrain and /admin/rollback. Empty or weak (< 16 chars) = admin endpoints disabled.
    admin_token: str = ""
    api_prefix: str = "/api/v1"
    # The app (served at /app) and FraudLens Shield don't need CORS. Add origins only for a separate web front end.
    cors_origins: list[str] = []
    # Per-device budget for costly endpoints (analyze, report, intel lookups...). 0 = off.
    rate_limit_per_minute: int = 30

    # --- AI layer -----------------------------------------------------------
    # "none" keeps the engine fully deterministic (fast, free, works offline).
    # "anthropic" adds the LLM layer on top of the rule engine.
    ai_provider: str = "none"
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-haiku-4-5-20251001"
    ai_timeout_seconds: float = 8.0

    # --- Risk thresholds ----------------------------------------------------
    medium_risk_threshold: int = 30
    high_risk_threshold: int = 60

    # --- Pause-Before-Pay ---------------------------------------------------
    pause_cooldown_seconds: int = 10
    large_payment_threshold: float = 10_000.0  # MUR, for first-time payees


@lru_cache
def get_settings() -> Settings:
    return Settings()
