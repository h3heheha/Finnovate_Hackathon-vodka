"""Security fixes (one test per loophole). See SECURITY.md."""
import logging
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.deps import settings_dep
from app.core.config import Settings, get_settings
from app.core.security import TOKEN_HEADER, issue_token, limiter, verify_token
from app.engine.pipeline import ai_agrees, identifiers, sender_identifier
from app.engine.ai.base import AIResult
from app.engine.detectors.base import DetectionContext
from app.engine.detectors import entities as entity_detector
from app.knowledge import loader
from app.main import app
from app.ml.memory import MemoryItem

API = "/api/v1"
client = TestClient(app)
EXT_ORIGIN = f"chrome-extension://{get_settings().extension_id}"
SCAM = ("MCB ALERT: Your account has been suspended. Verify within 2 hours: "
        "http://mcb-secure-verify.com/login and reply with the OTP you receive.")


@pytest.fixture(autouse=True)
def _fresh_limits():
    limiter.reset()
    yield
    limiter.reset()
    app.dependency_overrides.clear()


def register() -> dict:
    r = client.post(f"{API}/extension/register")
    assert r.status_code == 200
    return r.json()


def auth(tok: dict) -> dict:
    return {TOKEN_HEADER: tok["token"]}


# ---- 2. admin token ------------------------------------------------------------------------
def test_admin_is_locked_while_token_is_default_or_weak():
    for weak in ("change-me", "", "short-token"):
        app.dependency_overrides[settings_dep] = lambda weak=weak: Settings(admin_token=weak)
        r = client.post(f"{API}/admin/rollback", headers={"X-Admin-Token": weak})
        assert r.status_code == 503, weak


def test_admin_needs_the_exact_strong_token():
    strong = uuid.uuid4().hex + uuid.uuid4().hex
    app.dependency_overrides[settings_dep] = lambda: Settings(admin_token=strong)
    assert client.post(f"{API}/admin/rollback", headers={"X-Admin-Token": strong[:-1] + "x"}).status_code == 401
    assert client.post(f"{API}/admin/rollback").status_code == 401
    assert client.post(f"{API}/admin/rollback", headers={"X-Admin-Token": strong}).status_code in (200, 409)


# ---- 3. keys never reach the console -------------------------------------------------------
def test_http_client_logs_are_muted():
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING


# ---- 4. identity, origin guard, CORS, rate limits ------------------------------------------
def test_install_token_is_signed_and_checked():
    s = get_settings()
    tok = issue_token(s)
    assert verify_token(tok["token"], s) == tok["install_id"]
    head, sig = tok["token"].rsplit(".", 1)
    assert verify_token(f"{head}.{'0' * len(sig)}", s) is None                  # forged signature
    assert verify_token(tok["token"].replace(tok["install_id"], "a" * 16), s) is None  # swapped id
    assert verify_token("garbage", s) is None
    ok = client.post(f"{API}/analyze", json={"text": "hello there"}, headers=auth(register()))
    assert ok.status_code == 200
    bad = client.post(f"{API}/analyze", json={"text": "hello there"}, headers={TOKEN_HEADER: "v1.x.1.y"})
    assert bad.status_code == 401 and bad.json()["detail"] == "invalid_install_token"


def test_token_can_be_required(monkeypatch):
    monkeypatch.setattr(get_settings(), "require_install_token", True)
    assert client.post(f"{API}/analyze", json={"text": "hello"}).status_code == 401
    assert client.post(f"{API}/analyze", json={"text": "hello"}, headers=auth(register())).status_code == 200


def test_web_pages_cannot_use_the_api():
    evil = client.post(f"{API}/analyze", json={"text": "hi"}, headers={"Origin": "https://evil.example"})
    assert evil.status_code == 403
    img = client.get(f"{API}/intel/url", params={"url": "https://bit.ly/x"}, headers={"Sec-Fetch-Site": "cross-site"})
    assert img.status_code == 403
    assert client.post(f"{API}/analyze", json={"text": "hi"}, headers={"Origin": EXT_ORIGIN}).status_code == 200
    assert client.post(f"{API}/analyze", json={"text": "hi"}, headers={"Origin": "http://localhost:8550"}).status_code == 200


def test_cors_only_allows_the_extension_and_localhost():
    pre = {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"}
    evil = client.options(f"{API}/analyze", headers={"Origin": "https://evil.example", **pre})
    assert "access-control-allow-origin" not in evil.headers
    ext = client.options(f"{API}/analyze", headers={"Origin": EXT_ORIGIN, **pre})
    assert ext.headers.get("access-control-allow-origin") == EXT_ORIGIN


def test_rate_limits_protect_paid_lookups(monkeypatch):
    limits = {**get_settings().rate_limits, "intel_phone": [3, 3600], "register": [2, 3600]}
    monkeypatch.setattr(get_settings(), "rate_limits", limits)
    codes = [client.get(f"{API}/intel/phone", params={"number": "+230 5999 0000"}).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    r = client.get(f"{API}/intel/phone", params={"number": "+230 5999 0000"})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
    # tokens can't be farmed to dodge the limit: registration itself is limited per IP address
    assert [client.post(f"{API}/extension/register").status_code for _ in range(3)] == [200, 200, 429]


# ---- 5. an innocent number can't be made to look like a scam for other people -----------------
def test_scan_flags_only_affect_the_client_that_scanned():
    attacker, victim = register(), register()
    number = "+230 5744 0101"
    for _ in range(2):
        r = client.post(f"{API}/analyze", json={"text": SCAM, "sender": number, "use_intel": False},
                        headers=auth(attacker))
        assert r.json()["risk_level"] == "high"
    mine = client.get(f"{API}/intel/phone", params={"number": number}, headers=auth(attacker)).json()
    theirs = client.get(f"{API}/intel/phone", params={"number": number}, headers=auth(victim)).json()
    assert mine["risk_level"] == "high"        # Pause-Before-Pay / Shield still work for the scanner
    assert theirs["community_reports"] == 0 and theirs["risk_level"] == "low"


def test_official_numbers_are_never_flagged(monkeypatch):
    monkeypatch.setattr(loader, "protected_numbers", lambda: {"52001234"})
    ctx = DetectionContext.from_text("Call MCB on +230 5200 1234 or 5811 2233 now")
    entity_detector.detect(ctx)
    ids = identifiers(ctx.entities)
    assert "tel:52001234" not in ids and "tel:58112233" in ids
    assert sender_identifier("+230 5200 1234") is None


# ---- 6. reporters are counted by the server, not by what the client claims ---------------------
def test_made_up_reporter_ids_count_as_one_person():
    text = f"Earn 9000 a week liking videos, join via our agent. Ref {uuid.uuid4().hex[:6]}"
    r1 = client.post(f"{API}/report", json={"text": text, "reporter_id": "device-A"}).json()
    r2 = client.post(f"{API}/report", json={"text": text, "reporter_id": "device-B"}).json()
    assert r1["status"] == "pending" and r2["status"] == "pending"      # same IP => same reporter
    r3 = client.post(f"{API}/report", json={"text": text}, headers=auth(register())).json()
    assert r3["status"] == "confirmed"                                    # a genuinely different install


def test_reported_previews_mask_links():
    item = MemoryItem(id="x", label="scam", text="Verify at www.mcb-help.com or http://bit.ly/abc now",
                      source="report")
    assert "mcb-help" not in item.public(1.0)["preview"] and "[LINK]" in item.public(1.0)["preview"]
    seed = MemoryItem(id="y", label="scam", text="Visit mcb.mu", source="seed")
    assert seed.public(1.0)["preview"] == "Visit mcb.mu"


# ---- 8. the AI can't overrule the score -----------------------------------------------------
def test_ai_summary_only_used_when_it_agrees():
    assert ai_agrees(AIResult(scam_likelihood=0.9, summary="x"), "high", 30, 60)
    assert not ai_agrees(AIResult(scam_likelihood=0.05, summary="Genuine MCB message"), "high", 30, 60)
    assert not ai_agrees(AIResult(scam_likelihood=None, summary="x"), "high", 30, 60)
    assert not ai_agrees(AIResult(scam_likelihood=7, summary="x"), "high", 30, 60)
    assert not ai_agrees(AIResult(scam_likelihood=0.9, error="boom"), "high", 30, 60)


# ---- 9. input limits ------------------------------------------------------------------------
def test_inputs_are_capped_or_ignored():
    for junk in ("x" * 5000, "klingon", "<script>"):
        r = client.post(f"{API}/analyze", json={"text": "hello", "language": junk})
        assert r.status_code == 200 and r.json()["language"] in ("en", "fr", "mfe")   # ignored, auto-detected
    assert client.post(f"{API}/payments/check", json={"payee_account": "12345678", "amount": 1e12}).status_code == 422
    assert client.get(f"{API}/intel/url", params={"url": "javascript:alert(1)"}).status_code == 422
    rep = client.post(f"{API}/report", json={"text": "x" * 20, "category": "<script>"}).json()
    assert rep["status"] in ("pending", "confirmed", "disabled")
