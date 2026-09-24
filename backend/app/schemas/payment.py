from typing import Literal

from pydantic import BaseModel, Field


class PaymentCheckRequest(BaseModel):
    payee_name: str | None = Field(None, max_length=120)
    payee_account: str = Field(..., min_length=4, max_length=40)
    amount: float = Field(..., gt=0)
    currency: str = "MUR"
    reference: str | None = Field(None, max_length=140)
    is_saved_payee: bool = False
    source_analysis_id: str | None = Field(None, description="Set when the payment was started from a scanned message.")


class Reason(BaseModel):
    severity: Literal["info", "warning", "danger"]
    text: str


class SafeAction(BaseModel):
    id: str
    title: str
    detail: str


class PaymentCheckResponse(BaseModel):
    decision: Literal["allow", "warn", "pause"]
    risk_score: int
    headline: str
    reasons: list[Reason]
    safe_actions: list[SafeAction]
    cooldown_seconds: int
    verification_message: str
