import asyncio
import json

import httpx
import pytest

from app.core.config import Settings
from app.engine.ai.anthropic_provider import AnthropicAnalyzer
from app.engine.pipeline import Analyzer
from app.engine.redaction import redact
from app.knowledge import loader

analyzer = Analyzer(Settings())


def run(text: str, **kw) -> dict:
    return asyncio.run(analyzer.analyze(text, **kw))


@pytest.mark.parametrize("sample", loader.samples(), ids=lambda s: s["id"])
def test_samples_classified_correctly(sample):
    r = run(sample["text"])
    if sample["expected"] == "scam":
        assert r["risk_level"] == "high", (sample["id"], r["risk_score"])
    else:
        assert r["risk_level"] == "low", (sample["id"], r["risk_score"])


def test_segments_rebuild_original_text():
    text = loader.samples()[0]["text"]
    r = run(text)
    assert "".join(s["text"] for s in r["segments"]) == text
    assert any(s["tactic"] for s in r["segments"])


def test_contributions_add_up_to_score():
    for s in loader.samples():
        r = run(s["text"])
        assert sum(t["contribution"] for t in r["tactics"]) == r["risk_score"]


@pytest.mark.parametrize("url,expected", [
    ("http://mcb-secure-verify.com/login", True),   # brand + bait words
    ("https://rncb.mu/pay", True),                  # rn -> m homoglyph
    ("https://mcb.com/login", True),                # right name, wrong ending
    ("https://bit.ly/abc", True),                   # shortener
    ("http://192.168.4.20/bank", True),             # raw IP
    ("https://www.mcb.mu/personal", False),         # official
])
def test_link_checks(url, expected):
    r = run(f"Please check {url} for details")
    flagged = any(t["tactic"] == "suspicious_link" for t in r["tactics"])
    assert flagged is expected


def test_official_link_is_a_trust_signal():
    r = run("Your statement is ready. View it in the app or at https://www.mcb.mu")
    assert r["risk_level"] == "low"
    assert r["engine"]["trust_notes"]


def test_negated_credential_request_is_ignored():
    r = run("Never share your OTP or PIN with anyone.")
    assert not any(t["tactic"] == "credential_request" for t in r["tactics"])


def test_account_number_extracted():
    r = run("Send Rs 5000 to account 000451239876 today")
    assert "000451239876" in r["entities"]["accounts"]


def test_redaction_removes_personal_data():
    red = redact("Card 4111 1111 1111 1111, call +230 5821 4470, acct 000451239876, OTP 482913, mail a@b.mu")
    for secret in ("4111", "5821", "000451239876", "482913", "a@b.mu"):
        assert secret not in red.text
    assert red.total >= 5


def test_ai_findings_are_merged(monkeypatch):
    model_json = {"findings": [{"tactic": "urgency", "quote": "right now", "explanation": "Rush.", "confidence": 1}],
                  "category": "generic", "scam_likelihood": 0.8, "summary": "AI summary."}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert "[ACCOUNT]" in body["messages"][0]["content"]          # only redacted text is sent
        assert "000451239876" not in body["messages"][0]["content"]
        return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(model_json)}]})

    ai = AnthropicAnalyzer("test-key", "test-model", transport=httpx.MockTransport(handler))
    a = Analyzer(Settings(), ai)
    r = asyncio.run(a.analyze("Do it right now, pay into 000451239876"))
    assert r["privacy"]["ai_used"] is True
    assert r["summary"] == "AI summary."
    assert any(s["source"] == "ai" and s["evidence"] == "right now" for s in r["signals"])


def test_ai_failure_falls_back_to_rules():
    def handler(request):
        return httpx.Response(500, json={"error": "boom"})

    ai = AnthropicAnalyzer("k", "m", transport=httpx.MockTransport(handler))
    r = asyncio.run(Analyzer(Settings(), ai).analyze(loader.samples()[0]["text"]))
    assert r["risk_level"] == "high"
    assert r["privacy"]["ai_used"] is False and r["privacy"]["ai_error"]


def test_sender_mismatch_flags_bank_sms_from_mobile_number():
    text = "MCB: your card is blocked, call us back now."
    from_number = run(text, sender="+230 5821 4470")
    from_name = run(text, sender="MCB")
    assert any(t["tactic"] == "sender_mismatch" for t in from_number["tactics"])
    assert not any(t["tactic"] == "sender_mismatch" for t in from_name["tactics"])
    assert from_number["risk_score"] > from_name["risk_score"]


def test_brand_mentioned_late_is_not_a_claim():
    r = run("Hi! Hope you're well. Dinner is at 7 tonight. For the gift, please send your share to my MCB "
            "account later. Thanks", sender="+230 5934 1182")
    assert not any(t["tactic"] == "sender_mismatch" for t in r["tactics"])
