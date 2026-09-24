"""Threat intelligence: every provider is simulated with httpx.MockTransport (no real API calls)."""
import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from app.core.config import Settings, get_settings
from app.engine.pipeline import Analyzer
from app.intel.service import IntelService


def _date(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


class FakeInternet:
    """Answers like the real services do (formats taken from their public docs)."""

    def __init__(self, slow: bool = False, slow_directory: bool = False):
        self.calls: list[str] = []
        self.slow = slow
        self.slow_directory = slow_directory

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(f"{request.method} {request.url.host}{request.url.path}")
        host, path = request.url.host, request.url.path
        if self.slow and host == "urlhaus-api.abuse.ch":
            await asyncio.sleep(5)
        if host == "bit.ly":
            return httpx.Response(301, headers={"location": "http://evil-login.xyz/verify"})
        if host == "safebrowsing.googleapis.com":
            body = json.loads(request.content)
            matches = [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": e["url"]}}
                       for e in body["threatInfo"]["threatEntries"] if "evil" in e["url"]]
            return httpx.Response(200, json={"matches": matches} if matches else {})
        if host == "urlhaus-api.abuse.ch":
            assert request.headers.get("Auth-Key") == "uh-key"
            form = parse_qs(request.content.decode())
            if path == "/v1/url/":
                u = form["url"][0]
                if "malware" in u:
                    return httpx.Response(200, json={"query_status": "ok", "url_status": "online",
                                                     "threat": "malware_download", "tags": ["apk"]})
                return httpx.Response(200, json={"query_status": "no_results"})
            return httpx.Response(200, json={"query_status": "no_results"})
        if host == "data.iana.org":
            if self.slow_directory:
                await asyncio.sleep(1.0)  # slow venue Wi-Fi
            return httpx.Response(200, json={"services": [[["com", "xyz", "info", "shop"], ["https://rdap.test/"]]]})
        if host == "rdap.test" or "rdap" in host or host == "pubapi.registry.google":  # directory or built-in table
            domain = path.rsplit("/", 1)[-1]
            ages = {"evil-login.xyz": 2, "mcb-secure-verify.com": 3, "google.com": 9000, "fresh-shop.info": 20,
                    "cheap-deals.shop": 4}
            if domain not in ages:
                return httpx.Response(404)
            return httpx.Response(200, json={"events": [{"eventAction": "registration",
                                                         "eventDate": _date(ages[domain])}]})
        if host in ("rest-ww.telesign.com", "rest-api.telesign.com"):
            if request.headers.get("Authorization") != "Basic " + base64.b64encode(b"ts-cust:ts-key").decode():
                return httpx.Response(401, json={"status": {"code": 10000, "description": "Invalid credentials"},
                                                 "errors": [{"code": -30000, "description": "Invalid Customer ID."}]})
            assert parse_qs(request.content.decode())["account_lifecycle_event"] == ["create"]
            number = path.rsplit("/", 1)[-1]
            bad = number.endswith("4470")
            return httpx.Response(200, json={
                "status": {"code": 300, "description": "Transaction successfully completed"},
                "phone_type": {"code": "2", "description": "MOBILE"}, "carrier": {"name": "Emtel Ltd"},
                "location": {"country": {"iso2": "MU", "name": "Mauritius"}},
                "risk": {"score": 912 if bad else 115, "level": "very-high" if bad else "low",
                         "recommendation": "block" if bad else "allow"}})
        if host == "www.ipqualityscore.com":
            assert "/ipqs-key/" in path
            number = path.rsplit("/", 1)[-1]
            bad = number.endswith("4470")
            return httpx.Response(200, json={"success": True, "valid": True, "fraud_score": 95 if bad else 10,
                                             "recent_abuse": bad, "VOIP": bad, "line_type": "mobile",
                                             "carrier": "Emtel"})
        return httpx.Response(404)


def make(tmp_path: Path, fake: FakeInternet, **kw) -> tuple[IntelService, Analyzer]:
    opts = dict(safe_browsing_key="sb-key", urlhaus_key="uh-key", ipqs_key="ipqs-key", intel_enabled=True)
    opts.update(kw)
    s = Settings(data_dir=tmp_path, models_dir=tmp_path / "m", **opts)
    intel = IntelService(s, transport=httpx.MockTransport(fake))
    return intel, Analyzer(s, intel=intel)


def run(a: Analyzer, text: str, **kw) -> dict:
    return asyncio.run(a.analyze(text, **kw))


def test_short_link_unmasked_and_blocklisted(tmp_path):
    fake = FakeInternet()
    _, a = make(tmp_path, fake)
    r = run(a, "Your parcel is waiting, pay here: https://bit.ly/abc123")
    intel = r["intel"]
    assert intel["expanded_links"]["https://bit.ly/abc123"] == "http://evil-login.xyz/verify"
    assert intel["blocklisted"] is True
    assert r["risk_score"] >= 90
    assert any(t["tactic"] == "threat_intel" for t in r["tactics"])
    assert any(b["source"] == "intel" for b in r["score_breakdown"])
    assert sum(b["points"] for b in r["score_breakdown"]) == r["risk_score"]
    titles = {f["title"] for f in intel["findings"]}
    assert {"Short link unmasked", "Flagged by Google Safe Browsing", "Brand-new website"} <= titles
    # we never contacted the scam site itself, only the shortener
    assert not any("evil-login.xyz" in c for c in fake.calls if c.startswith(("GET evil", "HEAD evil")))


def test_new_domain_and_mu_domain(tmp_path):
    _, a = make(tmp_path, FakeInternet())
    r = run(a, "MCB: verify now at http://mcb-secure-verify.com/login or www.example.mu")
    titles = [f["title"] for f in r["intel"]["findings"]]
    assert "Brand-new website" in titles
    assert "Domain age unknown" in titles           # .mu has no RDAP server
    assert not r["intel"]["blocklisted"]


def test_malware_link_from_urlhaus(tmp_path):
    _, a = make(tmp_path, FakeInternet())
    r = run(a, "Install the refund app: http://refund-malware.com/app.apk")
    assert any(f["source"] == "URLhaus" and f["severity"] == "danger" for f in r["intel"]["findings"])
    assert r["risk_score"] >= 90


def test_phone_checked_only_when_suspicious_and_budgeted(tmp_path):
    fake = FakeInternet()
    intel, a = make(tmp_path, fake, ipqs_daily_limit=1)
    calm = run(a, "Hi, dinner at 7? Call me on 5821 4470")
    assert not any("ipqualityscore" in c for c in fake.calls)            # not suspicious -> no credit used
    r = run(a, "MCB: your account is blocked, call 5821 4470 immediately and give your PIN")
    assert any(f["source"] == "IPQualityScore" and f["severity"] == "danger" for f in r["intel"]["findings"])
    run(a, "MCB: your account is blocked, call 5821 4470 immediately and give your PIN")  # cached: free
    r3 = run(a, "MCB: your account is blocked, call 5999 1234 immediately and give your PIN")
    assert r3["intel"]["providers"]["IPQualityScore"] == "daily budget used"
    assert intel.cache.used_today("ipqs") == 1


def test_slow_provider_never_blocks_analysis(tmp_path):
    _, a = make(tmp_path, FakeInternet(slow=True), intel_timeout_seconds=0.5)
    import time
    t0 = time.perf_counter()
    r = run(a, "Pay the fee at http://evil-login.xyz/pay")
    assert time.perf_counter() - t0 < 2.0
    assert r["intel"]["providers"]["URLhaus"] == "timeout"
    assert r["intel"]["blocklisted"] is True                    # Safe Browsing still answered


def test_missing_keys_and_offline_are_harmless(tmp_path):
    s = Settings(data_dir=tmp_path, models_dir=tmp_path / "m", intel_enabled=True, safe_browsing_key=None,
                 urlhaus_key=None, ipqs_key=None)
    def offline(request):
        raise httpx.ConnectError("no internet")
    intel = IntelService(s, transport=httpx.MockTransport(offline))
    r = asyncio.run(Analyzer(s, intel=intel).analyze("Pay at http://evil-login.xyz/pay today"))
    prov = r["intel"]["providers"]
    assert prov["Google Safe Browsing"] == "not configured" and prov["URLhaus"] == "not configured"
    assert prov["RDAP domain age"].startswith("error")
    assert r["risk_level"] in ("medium", "high")                # rules still work


def test_phone_endpoint(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.api import deps
    from app.main import app
    intel, _ = make(tmp_path, FakeInternet())
    app.dependency_overrides[deps.get_intel] = lambda: intel
    try:
        c = TestClient(app)
        bad = c.get("/api/v1/intel/phone", params={"number": "+230 5821 4470"}).json()
        assert bad["risk_level"] == "high" and bad["reasons"]
        ok = c.get("/api/v1/intel/phone", params={"number": "+230 5251 2345"}).json()
        assert ok["risk_level"] == "low"
        u = c.get("/api/v1/intel/url", params={"url": "https://bit.ly/abc123"}).json()
        assert u["risk_level"] == "high" and u["blocklisted"]
    finally:
        app.dependency_overrides.clear()


def test_blank_or_commented_keys_count_as_not_configured():
    s = Settings(safe_browsing_key="", urlhaus_key="  # abuse.ch key", ipqs_key=' "abc123"  # mine ')
    assert s.safe_browsing_key is None
    assert s.urlhaus_key is None
    assert s.ipqs_key == "abc123"


def test_scam_sms_flags_the_sender_number_for_calls():
    from fastapi.testclient import TestClient
    from app.engine.pipeline import sender_identifier
    from app.main import app
    assert sender_identifier("+230 5821 4470") == "tel:58214470"
    assert sender_identifier("MCB") is None
    assert sender_identifier(None) is None
    client = TestClient(app)
    number = "+230 5733 1928"
    before = client.get("/api/v1/intel/phone", params={"number": number}).json()
    assert before["risk_level"] == "low"
    scam = ("MCB ALERT: Your account has been suspended. Verify within 2 hours: "
            "http://mcb-secure-verify.com/login and reply with the OTP you receive.")
    # Two independent devices (reputation counts devices, so one device can't frame a number alone).
    for host in ("10.0.0.21", "10.0.0.22"):
        device = TestClient(app, client=(host, 50000))
        r = device.post("/api/v1/analyze", json={"text": scam, "sender": number, "use_intel": False})
        assert r.json()["risk_level"] == "high"
    after = client.get("/api/v1/intel/phone", params={"number": "+23057331928"}).json()
    assert after["community_reports"] >= 2 and after["risk_level"] == "high"



def test_slow_rdap_directory_downloads_in_background(tmp_path):
    """The IANA directory may be slow on venue Wi-Fi: .com works at once from the built-in table,
    an unusual TLD times out the first time but is ready on the next check (no endless timeouts)."""
    fake = FakeInternet(slow_directory=True)
    intel, _ = make(tmp_path, fake, intel_timeout_seconds=0.4)

    async def scenario():
        r1 = await intel.check(["http://mcb-secure-verify.com/login", "http://cheap-deals.shop/x"], [])
        await asyncio.sleep(1.2)            # the directory finishes downloading in the background
        r2 = await intel.check(["http://cheap-deals.shop/x"], [])
        return r1, r2

    r1, r2 = asyncio.run(scenario())
    assert any(f.title == "Brand-new website" and "mcb-secure-verify.com" in f.target for f in r1.findings)
    assert not any("cheap-deals.shop" in f.target for f in r1.findings)  # .shop had to wait for the directory
    assert intel.cache.get("rdap:bootstrap") is not None          # ...which still got cached
    assert r2.providers["RDAP domain age"].startswith("ok")
    assert any(f.title == "Brand-new website" for f in r2.findings)


def test_warm_up_caches_directory(tmp_path):
    intel, _ = make(tmp_path, FakeInternet())
    assert asyncio.run(intel.warm_up()) is True
    assert intel.cache.get("rdap:bootstrap")["shop"] == "https://rdap.test/"



def test_telesign_score_and_offline_number_check(tmp_path):
    intel, _ = make(tmp_path, FakeInternet(), ipqs_key=None, telesign_customer_id="ts-cust",
                    telesign_api_key="ts-key")
    bad = asyncio.run(intel.check([], ["+230 5821 4470"]))
    assert bad.providers["Telesign"] == "ok" and bad.providers["Number check (offline)"] == "ok"
    t = next(f for f in bad.findings if f.source == "Telesign")
    assert t.severity == "danger" and "912/1000" in t.detail
    assert any(f.source == "Number check" and "mobile" in f.title for f in bad.findings)
    assert bad.score >= 0.6
    again = asyncio.run(intel.check([], ["+230 5821 4470"]))
    assert again.providers["Telesign"] == "ok (cached)"          # cached: no second credit used
    assert intel.cache.used_today("telesign") == 1
    good = asyncio.run(intel.check([], ["+230 5251 2345"]))
    assert next(f for f in good.findings if f.source == "Telesign").severity == "info"


def test_telesign_wrong_key_is_reported_and_not_charged(tmp_path):
    intel, _ = make(tmp_path, FakeInternet(), ipqs_key=None, telesign_customer_id="ts-cust",
                    telesign_api_key="same-as-customer-id")
    r = asyncio.run(intel.check([], ["+230 5821 4470"]))
    assert r.providers["Telesign"].startswith("error: Telesign HTTP 401")
    assert "Invalid Customer ID" in r.providers["Telesign"]
    assert intel.cache.used_today("telesign") == 0


def test_offline_number_facts_for_mauritius():
    from app.intel.providers import number_facts
    emtel = number_facts("+230 5733 1928")
    assert emtel["valid"] and emtel["type"] == "mobile" and emtel["region"] == "MU" and emtel["carrier"] == "Emtel"
    assert number_facts("58214470")["valid"]                      # local format gets +230
    assert not number_facts("+230 5999 000")["valid"]             # too short: fake caller ID
    uk = number_facts("+44 20 7946 0958")
    assert uk["region"] == "GB"


def test_number_check_findings(tmp_path):
    intel, _ = make(tmp_path, FakeInternet(), ipqs_key=None)
    fake = asyncio.run(intel.check([], ["+230 5999 000"]))
    assert any(f.title == "Not a real phone number" for f in fake.findings)
    foreign = asyncio.run(intel.check([], ["+44 20 7946 0958"]))
    assert any(f.title.startswith("Foreign number") for f in foreign.findings)
