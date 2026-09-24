"""V2: small-memory models, free APIs (OpenPhish, VirusTotal, Groq/Gemini), self-test, demo pages."""
import asyncio
import json
import time
import uuid
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_analyzer, get_intel
from app.core.budget import Allowance
from app.core.config import Settings
from app.core.security import limiter
from app.engine.ai import NoAI, build_analyzer
from app.engine.ai.base import AIAnalyzer, AIResult
from app.engine.ai.openai_compat import OpenAICompatAnalyzer
from app.engine.pipeline import Analyzer
from app.intel.service import IntelService, selftest
from app.main import app

SHIPPED = Path(__file__).resolve().parents[1] / "models"
API = "/api/v1"
client = TestClient(app)


@pytest.fixture(autouse=True)
def _fresh():
    limiter.reset()
    yield
    limiter.reset()
    app.dependency_overrides.clear()


def settings(tmp_path, **kw) -> Settings:
    base = dict(data_dir=tmp_path, intel_enabled=True, rdap_enabled=False, expand_short_links=False,
                number_check=False, safe_browsing_key=None, urlhaus_key=None, virustotal_key=None,
                openphish_enabled=True, openphish_feed_url="https://raw.githubusercontent.com/op/feed.txt")
    base.update(kw)
    return Settings(_env_file=None, **base)


# ---- models that fit in 512 MB -------------------------------------------------------------
def test_sentencepiece_tokenizer_matches_huggingface_ids():
    from app.ml.embedders import SpmTokenizer
    tok = SpmTokenizer(SHIPPED / "multilingual-e5-small")
    # reference ids produced by the original tokenizer.json (Hugging Face `tokenizers`)
    assert tok.encode("query: MCB: Your card is blocked. Verify now at http://mcb-secure-verify.com/login  ") == [
        0, 41, 1294, 12, 276, 47307, 12, 14804, 20596, 83, 46389, 297, 5, 1446, 40383, 5036, 99, 1621, 696, 39, 238,
        275, 9, 184, 57436, 9, 814, 40383, 5, 277, 64, 4867, 73, 6, 2]
    assert tok.encode("query: Mo kont MCB finn bloke, klik la vit!!! 😀") == [
        0, 41, 1294, 12, 2501, 33374, 276, 47307, 64806, 15925, 13, 4, 8600, 21, 12508, 1564, 21119, 2]
    assert tok.encode("query: Votre colis est bloqué à la douane.\nPayez Rs 95") == [
        0, 41, 1294, 12, 114324, 3365, 164, 437, 29695, 17555, 253, 21, 16216, 86, 5, 17166, 1255, 115034, 9199, 2]
    long = tok.encode("query: " + "word " * 1000)
    assert len(long) == 256 and long[0] == 0 and long[-1] == 2


def test_numpy_url_model_matches_onnx_reference():
    from app.ml.url_model import NumpyUrlModel
    m = NumpyUrlModel(SHIPPED / "phishing-url-detection" / "url_model.npz")
    got = m.predict(["http://mcb-secure-verify.com/login", "https://www.mcb.mu/", "https://bit.ly/mupost-fee",
                     "http://192.168.1.20/bank/login"])
    for g, ref in zip(got, [0.999918, 0.007914, 0.996723, 0.999981]):
        assert abs(g - ref) < 1e-5


# ---- allowances ------------------------------------------------------------------------------
def test_allowance_per_minute_and_per_day():
    a = Allowance(per_day=3, per_minute=2)
    assert a.take() is None and a.take() is None
    assert a.take() == "per-minute allowance used"
    a._minute.clear()
    assert a.take() is None
    assert a.take() == "daily allowance used"
    a.refund()
    assert a.used_today == 2


# ---- OpenPhish -------------------------------------------------------------------------------
FEED = "\n".join([
    "https://mcb-verify-account.xyz/login/index.php",
    "https://mcb-verify-account.xyz/secure/otp.php",
    "http://dawaid-sessionmints.netlify.app/",
    "https://sites.google.com/view/mcb-secure-login",
    "https://www.mcb.mu/phish-test",          # an official domain must never be condemned as a whole
    "not a url",
])


def feed_transport(status=200, body=FEED):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "raw.githubusercontent.com"
        return httpx.Response(status, text=body)
    return httpx.MockTransport(handler)


def test_openphish_exact_link_and_website(tmp_path):
    svc = IntelService(settings(tmp_path), transport=feed_transport())
    assert asyncio.run(svc.refresh_openphish())
    assert len(svc.op_urls) == 5
    r = asyncio.run(svc.check(["https://mcb-verify-account.xyz/login/index.php?id=7",
                               "https://mcb-verify-account.xyz/other",
                               "http://dawaid-sessionmints.netlify.app/other/page"], []))
    titles = {(f.target, f.title, f.severity) for f in r.findings}
    assert ("https://mcb-verify-account.xyz/login/index.php?id=7", "On a live phishing list", "danger") in titles
    assert ("https://mcb-verify-account.xyz/other", "Known phishing website", "danger") in titles   # 2 listed pages
    # one listed page on a website: a warning only (it may be shared hosting)
    assert ("http://dawaid-sessionmints.netlify.app/other/page", "Website with a phishing page", "warning") in titles
    assert r.blocklisted and r.providers["OpenPhish"] == "ok"


def test_openphish_never_condemns_shared_or_official_sites(tmp_path):
    svc = IntelService(settings(tmp_path), transport=feed_transport())
    asyncio.run(svc.refresh_openphish())
    r = asyncio.run(svc.check(["https://sites.google.com/view/school-trip", "https://www.mcb.mu/personal"], []))
    assert not [f for f in r.findings if f.source == "OpenPhish"]
    r = asyncio.run(svc.check(["https://sites.google.com/view/mcb-secure-login/"], []))
    assert [f for f in r.findings if f.source == "OpenPhish" and f.severity == "danger"]


def test_openphish_download_failure_is_reported_not_raised(tmp_path):
    svc = IntelService(settings(tmp_path), transport=feed_transport(status=503))
    assert asyncio.run(svc.refresh_openphish()) is False
    assert "503" in svc.op_error
    r = asyncio.run(svc.check(["http://x-login.xyz/"], []))
    assert r.providers["OpenPhish"] == "list not loaded yet"


# ---- VirusTotal ------------------------------------------------------------------------------
def vt_transport(calls):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "raw.githubusercontent.com":
            return httpx.Response(200, text=FEED)
        assert request.url.host == "www.virustotal.com"
        calls.append(request.url.path)
        if request.headers.get("x-apikey") != "vt-key":
            return httpx.Response(401, json={"error": {"code": "WrongCredentialsError"}})
        from app.intel.providers import vt_url_id
        if request.url.path.endswith(vt_url_id("http://evil-login.xyz/verify")):
            stats = {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 20}
        elif request.url.path.endswith(vt_url_id("http://never-seen.xyz/")):
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        else:
            stats = {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 18}
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": stats}}})
    return httpx.MockTransport(handler)


def test_virustotal_findings_cache_and_quota(tmp_path):
    calls = []
    svc = IntelService(settings(tmp_path, virustotal_key="vt-key", virustotal_per_minute=3),
                       transport=vt_transport(calls))
    r = asyncio.run(svc.check(["http://evil-login.xyz/verify", "http://never-seen.xyz/", "https://example.org/"], []))
    by = {f.target: f for f in r.findings if f.source == "VirusTotal"}
    assert by["http://evil-login.xyz/verify"].severity == "danger" and "7 of 88" in by["http://evil-login.xyz/verify"].detail
    assert by["http://never-seen.xyz/"].title == "Not scanned before"
    assert by["https://example.org/"].severity == "info"
    assert r.blocklisted
    # cached: no new calls
    asyncio.run(svc.check(["http://evil-login.xyz/verify"], []))
    assert len(calls) == 3
    # per-minute allowance used: a new link is skipped, not sent
    r = asyncio.run(svc.check(["http://brand-new.xyz/"], []))
    assert len(calls) == 3 and r.providers["VirusTotal"] == "per-minute allowance used"


def test_virustotal_bad_key_is_an_error_status(tmp_path):
    svc = IntelService(settings(tmp_path, virustotal_key="wrong"), transport=vt_transport([]))
    r = asyncio.run(svc.check(["http://x-login.xyz/"], []))
    assert "key rejected" in r.providers["VirusTotal"]


# ---- free AI (Groq / Gemini, OpenAI-compatible) -------------------------------------------------
def test_ai_choice_auto_picks_first_key(tmp_path):
    assert Settings(_env_file=None).ai_choice == "none"
    assert Settings(_env_file=None, gemini_api_key="g").ai_choice == "gemini"
    assert Settings(_env_file=None, gemini_api_key="g", groq_api_key="q").ai_choice == "groq"
    assert Settings(_env_file=None, ai_provider="gemini", groq_api_key="q").ai_choice == "none"
    assert Settings(_env_file=None, ai_provider="none", groq_api_key="q").ai_choice == "none"
    assert isinstance(build_analyzer(Settings(_env_file=None)), NoAI)
    assert build_analyzer(Settings(_env_file=None, groq_api_key="q")).name == "groq"


def groq_transport(seen, status=200, content=None):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if status != 200:
            return httpx.Response(status, json={"error": {"message": "Invalid API Key"}})
        reply = content if content is not None else json.dumps({
            "findings": [{"tactic": "urgency", "quote": "within 2 hours", "explanation": "Time pressure.",
                          "confidence": 0.9}],
            "category": "bank_impersonation", "scam_likelihood": 0.95,
            "summary": "This pretends to be your bank and rushes you."})
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": reply}}]})
    return httpx.MockTransport(handler)


def test_groq_request_shape_and_parsing():
    seen = []
    ai = OpenAICompatAnalyzer("groq", "gsk_test", "openai/gpt-oss-20b", 5, Allowance(10, 5),
                              transport=groq_transport(seen))
    r = asyncio.run(ai.analyze("MCB ALERT verify within 2 hours", ["urgency"], "en"))
    assert r.error is None and r.findings[0].tactic == "urgency" and r.category == "bank_impersonation"
    req = seen[0]
    assert str(req.url) == "https://api.groq.com/openai/v1/chat/completions"
    assert req.headers["Authorization"] == "Bearer gsk_test"
    body = json.loads(req.content)
    assert body["model"] == "openai/gpt-oss-20b" and body["include_reasoning"] is False
    assert body["response_format"] == {"type": "json_object"} and body["messages"][0]["role"] == "system"


def test_gemini_request_shape():
    seen = []
    ai = OpenAICompatAnalyzer("gemini", "AIza_test", "gemini-3.1-flash-lite", 5, Allowance(10, 5),
                              transport=groq_transport(seen))
    asyncio.run(ai.analyze("hello", [], "fr"))
    assert str(seen[0].url) == "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    body = json.loads(seen[0].content)
    assert "include_reasoning" not in body and body["reasoning_effort"] == "low"


def test_ai_errors_and_allowance_never_break_analysis():
    bad = OpenAICompatAnalyzer("groq", "bad", "m", 5, Allowance(10, 5), transport=groq_transport([], status=401))
    r = asyncio.run(bad.analyze("x", [], "en"))
    assert r.findings == [] and "401" in r.error and "Invalid API Key" in r.error
    junk = OpenAICompatAnalyzer("groq", "k", "m", 5, Allowance(10, 5), transport=groq_transport([], content="no json"))
    assert asyncio.run(junk.analyze("x", [], "en")).error == "No JSON in model response"
    seen = []
    tight = OpenAICompatAnalyzer("groq", "k", "m", 5, Allowance(1, 5), transport=groq_transport(seen))
    asyncio.run(tight.analyze("x", [], "en"))
    r = asyncio.run(tight.analyze("x", [], "en"))
    assert r.error == "skipped: daily allowance used" and len(seen) == 1


def test_ai_and_intel_run_at_the_same_time(tmp_path):
    class SlowAI(AIAnalyzer):
        name = "slow"

        async def analyze(self, text, tactics, lang):
            await asyncio.sleep(0.4)
            return AIResult(provider=self.name)

    class SlowIntel:
        async def check(self, urls, phones, check_phones=True):
            await asyncio.sleep(0.4)
            from app.intel.service import IntelReport
            return IntelReport()

    a = Analyzer(Settings(_env_file=None), SlowAI(), ml=None, intel=SlowIntel())
    t0 = time.perf_counter()
    r = asyncio.run(a.analyze("MCB ALERT: verify at http://mcb-secure-verify.com/login now"))
    assert time.perf_counter() - t0 < 0.7
    assert r["privacy"]["ai_provider"] == "slow"


# ---- self-test endpoint ------------------------------------------------------------------------
def selftest_transport():
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "safebrowsing.googleapis.com":
            if request.url.params.get("key") != "sb-key":
                return httpx.Response(400, json={"error": {"message": "API key not valid."}})
            body = json.loads(request.content)
            return httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING",
                                                          "threat": {"url": body["threatInfo"]["threatEntries"][0]["url"]}}]})
        if host == "urlhaus-api.abuse.ch":
            return httpx.Response(401, json={"query_status": "unknown_auth_key"})
        if host == "raw.githubusercontent.com":
            return httpx.Response(200, text=FEED)
        if host == "rdap.verisign.com":
            return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"}]})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def test_selftest_reports_each_service(tmp_path):
    svc = IntelService(settings(tmp_path, safe_browsing_key="sb-key", urlhaus_key="bad", rdap_enabled=True,
                                number_check=True), transport=selftest_transport())
    out = {e["id"]: e for e in asyncio.run(selftest(svc))}
    assert out["safe_browsing"]["state"] == "working"
    assert out["urlhaus"]["state"] == "error" and "401" in out["urlhaus"]["detail"]
    assert out["openphish"]["state"] == "working" and "5 phishing links" in out["openphish"]["detail"]
    assert out["virustotal"]["state"] == "not_set" and out["virustotal"]["env"] == "FRAUDLENS_VIRUSTOTAL_KEY"
    assert out["virustotal"]["signup"].startswith("https://")
    assert out["rdap"]["state"] == "working"
    assert out["number_check"]["state"] == "working"
    assert out["telesign"]["state"] == "not_set"
    # never leaks a key value
    assert "sb-key" not in json.dumps(out)
    # cached for everybody: a second call makes no new requests
    svc._transport = httpx.MockTransport(lambda r: (_ for _ in ()).throw(AssertionError("no new calls")))
    asyncio.run(selftest(svc))


def test_selftest_endpoint_is_rate_limited(tmp_path):
    svc = IntelService(settings(tmp_path), transport=selftest_transport())
    app.dependency_overrides[get_intel] = lambda: svc
    app.dependency_overrides[get_analyzer] = lambda: Analyzer(Settings(_env_file=None), NoAI())
    r = client.get(f"{API}/status/providers")
    assert r.status_code == 200
    ids = [e["id"] for e in r.json()["providers"]]
    assert ids[0] == "ai" and "openphish" in ids
    assert r.json()["providers"][0]["state"] == "not_set"
    codes = [client.get(f"{API}/status/providers").status_code for _ in range(8)]
    assert 429 in codes


# ---- demo pages, home page, headers ------------------------------------------------------------
def test_demo_pages_and_security_headers():
    r = client.get("/demo/")
    assert r.status_code == 200 and "practice pages" in r.text.lower()
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
    inbox = client.get("/demo/inbox.html").text
    assert inbox.count("data-fl-message") == 8 and "localhost" not in inbox
    assert "login.html#as=mcb-secure-verify.com" in inbox
    assert client.get("/demo/login.html").status_code == 200
    assert client.get("/demo/attacks.html").status_code == 200
    assert client.get("/demo/../main.py").status_code == 404
    home = client.get("/")
    assert home.status_code == 200 and "The server is running" in home.text
    h = client.get("/health").json()
    assert h["demo_pages"] is True and "install_token_required" in h


def test_global_register_cap(monkeypatch):
    from app.core.config import get_settings
    s = get_settings()
    monkeypatch.setitem(s.global_limits, "register", [3, 3600])
    monkeypatch.setitem(s.rate_limits, "register", [100, 3600])
    codes = [client.post(f"{API}/extension/register").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]


# ---- review fixes: poisoning, spoofed addresses, AI caps ------------------------------------------
def test_genuine_reports_never_hide_a_scam(tmp_path):
    from app.ml.service import MLService
    data = tmp_path / "data"
    (data / "seed").mkdir(parents=True)
    from app.core.config import get_settings
    (data / "seed" / "curated_messages.csv").write_bytes((get_settings().data_dir / "seed" / "curated_messages.csv").read_bytes())
    s = Settings(_env_file=None, data_dir=data, models_dir=tmp_path / "models", embedder="hashing",
                 report_confirmations=1, community_confirmations=3)
    ml = MLService(s)
    a = Analyzer(s, ml=ml)
    prize = "Congratulations! You won Rs 500,000 in the MCB lucky draw. Pay Rs 1,500 processing fee to claim today."
    before = asyncio.run(a.analyze(prize))["risk_score"]
    size = len(ml.memory.items)
    for i in range(5):
        r = ml.report(prize, "legit", f"attacker-{i}", "none", f"10.0.{i}.0/24")
        assert r["status"] in ("noted", "rejected")
    assert len(ml.memory.items) == size                       # memory unchanged
    assert asyncio.run(a.analyze(prize))["risk_score"] == before


def test_one_script_with_many_tokens_cannot_poison_everyone():
    """Reports from one network count once for 'everyone', however many install tokens it uses."""
    from app.api.deps import get_ml
    text = f"Pay the Rs 200 delivery fee for parcel {uuid.uuid4().hex[:6]} at the post office counter 7 today"
    for _ in range(4):
        tok = client.post(f"{API}/extension/register").json()
        r = client.post(f"{API}/report", json={"text": text}, headers={"X-FraudLens-Install": tok["token"]}).json()
    assert r["status"] in ("confirmed", "reinforced")
    ml = get_ml()
    item = next(i for i in ml.memory.items if i.source == "report" and "delivery fee" in i.text)
    assert len(item.reporter_nets) == 1 and not ml.memory.is_community(item)


def test_client_ip_uses_cloudflare_header_only_on_render(monkeypatch):
    from starlette.requests import Request as R
    from app.core.security import client_ip, client_net
    scope = {"type": "http", "headers": [(b"true-client-ip", b"41.212.9.8"), (b"x-forwarded-for", b"1.2.3.4")],
             "client": ("10.1.1.1", 5555), "method": "GET", "path": "/"}
    monkeypatch.delenv("RENDER", raising=False)
    assert client_ip(R(scope)) == "10.1.1.1"                 # not on Render: headers are ignored
    monkeypatch.setenv("RENDER", "true")
    assert client_ip(R(scope)) == "41.212.9.8"               # on Render: Cloudflare's header
    scope["headers"] = [(b"true-client-ip", b"not-an-ip"), (b"x-forwarded-for", b"1.2.3.4")]
    assert client_ip(R(scope)) == "10.1.1.1"                 # garbage is ignored, X-Forwarded-For never trusted
    assert client_net("41.212.9.8") == "41.212.9.0/24"


def test_ai_is_capped_per_browser(monkeypatch):
    import app.api.routes.analyze as route
    from app.core.budget import PerKeyAllowance
    monkeypatch.setattr(route, "_ai_per_client", PerKeyAllowance(2))
    monkeypatch.setattr(route, "_ai_per_network", PerKeyAllowance(100))

    class Req:
        headers, client, state = {}, type("C", (), {"host": "10.9.9.9"})(), type("S", (), {"client_key": "ext:abc"})()
    s = Settings(_env_file=None)
    assert route.ai_allowed(Req, s) and route.ai_allowed(Req, s) and not route.ai_allowed(Req, s)
