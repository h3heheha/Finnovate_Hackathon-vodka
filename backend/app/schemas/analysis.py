from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

RiskLevel = Literal["low", "medium", "high"]
Channel = Literal["sms", "whatsapp", "email", "social", "call_transcript", "other"]


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000, description="The message the customer received.")
    channel: Channel = "sms"
    sender: str | None = Field(None, max_length=120, description="Sender name or number, if known.")
    language: str | None = Field(None, description="Force 'en', 'fr' or 'mfe'. Auto-detected when empty.")
    use_ai: bool = True
    use_intel: bool = Field(True, description="Check links/numbers against threat-intelligence services.")

    model_config = {"json_schema_extra": {"examples": [{
        "text": "MCB ALERT: Your account is suspended. Verify within 2 hours: http://mcb-secure-verify.com",
        "channel": "sms",
    }]}}


class SignalOut(BaseModel):
    tactic: str
    label: str
    evidence: str
    start: int | None = None
    end: int | None = None
    weight: float
    detail: str | None = None
    source: Literal["rule", "ai", "combo"] = "rule"


class TacticOut(BaseModel):
    tactic: str
    label: str
    short: str
    description: str
    color: str
    icon: str
    weight: float
    contribution: int = Field(..., description="Points this tactic adds to the risk score.")
    evidence: list[str]
    details: list[str]


class Segment(BaseModel):
    text: str
    tactic: str | None = None


class AdviceOut(BaseModel):
    id: str
    title: str
    detail: str
    action: str | None = None
    payload: dict = {}


class EntitiesOut(BaseModel):
    urls: list[str] = []
    domains: list[str] = []
    phone_numbers: list[str] = []
    accounts: list[str] = []
    wallets: list[str] = []
    amounts: list[str] = []
    brands: list[str] = []
    official_links: list[str] = []


class PrivacyOut(BaseModel):
    redacted_items: int
    redacted_types: dict[str, int]
    ai_used: bool
    ai_provider: str
    ai_error: str | None = None
    note: str = "Personal details are removed before any text is sent to an AI model."


class EngineOut(BaseModel):
    version: str
    latency_ms: int
    rules_fired: int
    rules_score: int = 0
    combos: list[str]
    trust_notes: list[str]
    trust_applied: bool


class BreakdownItem(BaseModel):
    source: str
    label: str
    points: int
    detail: str = ""


class SimilarMessage(BaseModel):
    id: str
    label: Literal["scam", "legit"]
    similarity: float
    strength: float
    category: str
    category_label: str
    source: str
    reports: int
    preview: str


class VerificationOut(BaseModel):
    enabled: bool
    mode: str | None = None
    embedder: str | None = None
    model_version: str | None = None
    classifier_probability: float | None = None
    similar: list[SimilarMessage] = []
    memory_match: dict | None = None
    links: list[dict] = []
    community_reports: int = 0
    layers: dict = {}
    notes: list[str] = []


class IntelFinding(BaseModel):
    source: str
    kind: str
    target: str
    severity: Literal["danger", "warning", "info"]
    title: str
    detail: str
    weight: float = 0.0


class IntelOut(BaseModel):
    enabled: bool
    providers: dict[str, str] = {}
    expanded_links: dict[str, str] = {}
    findings: list[IntelFinding] = []
    blocklisted: bool = False
    score: float = 0.0
    latency_ms: int = 0


class AnalyzeResponse(BaseModel):
    analysis_id: str
    created_at: datetime
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    verdict: str
    summary: str
    category: str
    category_label: str
    language: str
    tactics: list[TacticOut]
    signals: list[SignalOut]
    segments: list[Segment]
    advice: list[AdviceOut]
    verification_reply: str
    score_breakdown: list[BreakdownItem] = Field(
        [], description="Points per verification layer; they add up to risk_score.")
    verification: VerificationOut
    intel: IntelOut
    entities: EntitiesOut
    privacy: PrivacyOut
    engine: EngineOut


class ReportRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)
    label: Literal["scam", "legit"] = "scam"
    reporter_id: str = Field(..., min_length=4, max_length=100, description="Anonymous device/install id.")
    sender: str | None = Field(None, max_length=120)
    category: str | None = None


class ReportResponse(BaseModel):
    status: Literal["pending", "confirmed", "reinforced", "rejected", "disabled"]
    message: str
    reports: int = 0
    needed: int = 0
    match: dict | None = None


class FeedbackRequest(BaseModel):
    analysis_id: str
    verdict: Literal["scam", "legit", "unsure"]
    comment: str | None = Field(None, max_length=500)
