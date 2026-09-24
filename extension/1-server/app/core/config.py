"""Application settings, loaded from environment variables or a .env file."""
import os
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
_WEAK_TOKENS = {"", "change-me", "changeme", "admin", "password", "secret", "token", "fraudlens"}
LOCAL_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8-sig", env_prefix="FRAUDLENS_", extra="ignore")

    app_name: str = "FraudLens AI"
    version: str = "0.4.0"

    # --- Threat intelligence (external reputation checks) ---------------------------
    # Only URLs, domains and phone numbers are sent to these services, never message text.
    intel_enabled: bool = True
    intel_timeout_seconds: float = 2.5     # total budget; slow providers are skipped
    safe_browsing_key: str | None = None   # Google Safe Browsing v4 (non-commercial use)
    safe_browsing_daily_limit: int = 8000  # Google's default quota is 10,000/day; keep a margin
    urlhaus_key: str | None = None         # abuse.ch Auth-Key
    openphish_enabled: bool = True         # OpenPhish community feed: free, no key, refreshed every 6 h
    openphish_feed_url: str = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    virustotal_key: str | None = None      # VirusTotal public API (free: 4 lookups/min, 500/day)
    virustotal_daily_limit: int = 450
    virustotal_per_minute: int = 4
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
                     "anthropic_api_key", "virustotal_key", "groq_api_key", "gemini_api_key", mode="before")
    @classmethod
    def _clean_key(cls, v):
        """Tolerate blank keys, stray spaces/quotes and inline "# comments" pasted into .env."""
        if v is None:
            return None
        v = str(v).strip()
        if not v or v.startswith("#"):
            return None
        v = v.split()[0].strip("\"'")
        if v.lower() in {"none", "null", "-", "skip", "empty", "n/a", "na", "x", "no"}:
            return None   # a placeholder typed into a dashboard that wouldn't accept an empty value
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
    report_confirmations: int = 2
    # A reported scam protects everybody once reporters from this many different networks (IP /24)
    # report it; before that it protects only the people who reported it (anti-poisoning).
    community_confirmations: int = 3
    admin_token: str = ""                  # protects /admin endpoints; weak or empty => admin is LOCKED
    api_prefix: str = "/api/v1"

    # --- Security (see SECURITY.md) -------------------------------------------------
    # Browsers: only these origins may call the API. The Chrome extension's origin is added
    # automatically from extension_id; http://localhost / 127.0.0.1 (any port) are allowed for dev tools.
    cors_origins: list[str] = []
    extension_id: str = "bnoincbnfccidpkdnfelgejnldhicimk"   # pinned by the "key" in extension/manifest.json
    # Signs install tokens (HMAC). Empty => a random secret per run (tokens renew automatically).
    install_secret: str = ""
    install_token_days: int = 30
    # True => every API call must carry a valid install token (production). False keeps the
    # mobile app and Shield working without one; they are then identified by IP address.
    require_install_token: bool = False
    # Salt for hashed account numbers / identifiers. Empty => random per run.
    hash_salt: str = ""
    # Where a high-risk *scan* flags its accounts / numbers / links:
    #   personal  = only the client that scanned it sees the flag (Pause-Before-Pay, Shield caller check)
    #   community = everyone sees it (poisonable: anyone could flag an innocent number)
    #   off       = scans never flag; only confirmed reports do
    scan_flag_scope: str = "personal"
    rate_limit_enabled: bool = True
    # requests per window, per client (install id, or IP address when there is no token)
    rate_limits: dict[str, list[int]] = {
        "analyze": [30, 60], "intel_url": [20, 60], "intel_phone": [20, 3600], "report": [10, 600],
        "register": [30, 3600], "admin": [5, 60], "payments": [30, 60], "selftest": [6, 600],
        "default": [120, 60],
    }
    # ...and for everybody together, so faked IP addresses can't farm tokens or overload a small server
    global_limits: dict[str, list[int]] = {"register": [300, 3600], "analyze": [240, 60], "intel_url": [240, 60],
                                           "intel_phone": [60, 3600], "selftest": [12, 3600]}
    # Behind a proxy (Render + Cloudflare) the visitor's address comes from a header the proxy sets
    # and visitors can't fake. auto = True-Client-IP / CF-Connecting-IP when running on Render.
    client_ip_header: str = "auto"
    demo_pages: bool = True                # serve the practice pages at /demo/

    @property
    def admin_enabled(self) -> bool:
        t = (self.admin_token or "").strip()
        return len(t) >= 24 and t.lower() not in _WEAK_TOKENS

    @property
    def allowed_origins(self) -> list[str]:
        origins = [o for o in self.cors_origins if o and o != "*"]
        if self.extension_id:
            origins.append(f"chrome-extension://{self.extension_id}")
        return list(dict.fromkeys(origins))

    # --- AI layer -----------------------------------------------------------
    # auto      = the first provider that has a key: groq, then gemini, then anthropic (else none)
    # none      = rules + ML only (fast, free, works offline)
    # groq | gemini | anthropic = that provider (needs its key)
    # The AI only ever receives REDACTED text and can add warning signs; it can't remove the rules' ones.
    ai_provider: str = "auto"
    groq_api_key: str | None = None        # free: console.groq.com (no card)
    groq_model: str = "openai/gpt-oss-20b"
    gemini_api_key: str | None = None      # free: aistudio.google.com (free-tier data may be used by Google)
    gemini_model: str = "gemini-3.1-flash-lite"
    anthropic_api_key: str | None = None   # paid
    anthropic_model: str = "claude-haiku-4-5-20251001"
    ai_timeout_seconds: float = 8.0
    ai_daily_limit: int = 800              # all users together (Groq free: 1,000/day)
    ai_per_minute: int = 20                # all users together (Groq free: 30/min)
    ai_per_client_daily: int = 100         # one browser
    ai_per_network_daily: int = 300        # one network (IP /24), e.g. a whole venue

    @property
    def ai_choice(self) -> str:
        """The provider that will actually be used."""
        keys = {"groq": self.groq_api_key, "gemini": self.gemini_api_key, "anthropic": self.anthropic_api_key}
        want = (self.ai_provider or "auto").strip().lower()
        if want == "auto":
            return next((name for name, key in keys.items() if key), "none")
        return want if keys.get(want) else "none"

    # --- Risk thresholds ----------------------------------------------------
    medium_risk_threshold: int = 30
    high_risk_threshold: int = 60

    # --- Pause-Before-Pay ---------------------------------------------------
    pause_cooldown_seconds: int = 10
    large_payment_threshold: float = 10_000.0  # MUR, for first-time payees


@lru_cache
def get_settings() -> Settings:
    # FRAUDLENS_ENV_FILE lets the Windows helpers use a keys file kept OUTSIDE the server folder
    # (so it can never be uploaded to GitHub by accident).
    return Settings(_env_file=os.environ.get("FRAUDLENS_ENV_FILE") or ".env")
