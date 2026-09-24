"""Regression tests for the security review (see SECURITY.md)."""
import uuid

from fastapi.testclient import TestClient

from app.api.security import RateLimitMiddleware, require_admin
from app.main import app
from app.services import store as store_mod

API = "/api/v1"
SCAM = ("URGENT: your account is blocked. Send your OTP and PIN now or call +230 5991 2345 "
        "to avoid closure today. Keep this private.")


def device(host: str) -> TestClient:
    return TestClient(app, client=(host, 40000))


def test_admin_endpoints_disabled_without_a_strong_token():
    c = TestClient(app)
    for token in (None, "change-me", ""):
        headers = {"X-Admin-Token": token} if token is not None else {}
        r = c.post(f"{API}/admin/rollback", headers=headers)
        assert r.status_code == 503, r.text


def test_require_admin_checks_token():
    strong = "x" * 24
    require_admin(strong, strong)
    for bad in (None, "", "y" * 24):
        try:
            require_admin(bad, strong)
        except Exception as exc:
            assert getattr(exc, "status_code", None) == 401
        else:
            raise AssertionError("bad token accepted")


def test_one_device_cannot_confirm_a_report_with_fake_reporter_ids():
    text = f"Totally genuine newsletter number {uuid.uuid4().hex}: see you at the meetup on Friday."
    c = device("10.1.1.1")
    statuses = [c.post(f"{API}/report", json={"text": text, "label": "scam", "reporter_id": uuid.uuid4().hex})
                .json()["status"] for _ in range(4)]
    assert statuses == ["pending"] * 4, statuses
    # a second, independent device confirms it
    r = device("10.1.1.2").post(f"{API}/report", json={"text": text, "label": "scam", "reporter_id": "whatever"})
    assert r.json()["status"] == "confirmed"


def test_one_device_cannot_frame_a_caller():
    c = device("10.2.2.2")
    for i in range(3):
        c.post(f"{API}/analyze", json={"text": SCAM + f" #{i}", "sender": "+230 5991 2345", "use_intel": False})
    r = c.get(f"{API}/intel/phone", params={"number": "+230 5991 2345"}).json()
    assert r["community_reports"] == 1 and r["risk_level"] == "medium"


def test_official_numbers_are_never_flagged(monkeypatch):
    monkeypatch.setattr(store_mod, "_official_phones", lambda: {"tel:2026060"})
    for host in ("10.3.3.1", "10.3.3.2", "10.3.3.3"):
        device(host).post(f"{API}/analyze", json={"text": SCAM.replace("+230 5991 2345", "+230 202 6060"),
                                                  "sender": "+230 202 6060", "use_intel": False})
    r = TestClient(app).get(f"{API}/intel/phone", params={"number": "202 6060"}).json()
    assert r["community_reports"] == 0 and r["risk_level"] == "low"


def test_forwarded_client_ip_only_trusted_from_loopback():
    from app.api.security import client_key

    class Req:
        def __init__(self, host, header):
            self.client = type("C", (), {"host": host})()
            self.headers = {"x-fraudlens-client-ip": header} if header else {}
    assert client_key(Req("127.0.0.1", "192.168.1.50")) == "192.168.1.50"
    assert client_key(Req("192.168.1.9", "1.2.3.4")) == "192.168.1.9"   # spoof attempt ignored
    assert client_key(Req("127.0.0.1", None)) == "127.0.0.1"


def test_rate_limit_blocks_bursts():
    from fastapi import FastAPI

    mini = FastAPI()
    mini.add_middleware(RateLimitMiddleware, api_prefix="/api/v1", per_minute=5)

    @mini.post("/api/v1/analyze")
    def ok():
        return {"ok": True}

    @mini.get("/api/v1/samples")
    def free():
        return []

    c = TestClient(mini, client=("10.9.9.9", 1))
    codes = [c.post("/api/v1/analyze").status_code for _ in range(8)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429] * 3
    assert all(c.get("/api/v1/samples").status_code == 200 for _ in range(10))   # cheap reads not limited
    assert TestClient(mini, client=("10.9.9.10", 1)).post("/api/v1/analyze").status_code == 200  # per device


def test_security_headers_and_no_open_cors():
    c = TestClient(app)
    r = c.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    r = c.options(f"{API}/analyze", headers={"Origin": "https://evil.example",
                                             "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in r.headers
