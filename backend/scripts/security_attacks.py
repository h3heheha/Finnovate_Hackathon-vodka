"""Attack battery against a LOCAL FraudLens server. Usage: python -m scripts.security_attacks [http://127.0.0.1:8000]"""
import json
import sys
import time
import uuid

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
API = BASE + "/api/v1"
c = httpx.Client(timeout=60)
results = []


def rec(name, vuln, detail=""):
    results.append((name, vuln, detail))
    print(("VULN " if vuln else "PASS ") + name + (f"  [{detail}]" if detail else ""))


# 1. Admin endpoints with the default token
r = c.post(API + "/admin/rollback", headers={"X-Admin-Token": "change-me"})
rec("admin endpoints reject the default 'change-me' token", r.status_code not in (401, 403, 503),
    f"HTTP {r.status_code}: {r.text[:80]}")
r = c.post(API + "/admin/retrain")
rec("admin endpoints reject a missing token", r.status_code not in (401, 403, 503), f"HTTP {r.status_code}")

# 2. Report poisoning: one attacker, many fake reporter ids -> a GENUINE bank OTP becomes a "confirmed scam"
genuine = "MCB: Your OTP for the online payment of Rs 3,410.00 at WINNERS is 771204. Never share this code."
before = c.post(API + "/analyze", json={"text": genuine, "sender": "MCB", "use_intel": False}).json()["risk_score"]
statuses = [c.post(API + "/report", json={"text": genuine, "label": "scam", "reporter_id": uuid.uuid4().hex,
                                         "sender": "MCB"}).json()["status"] for _ in range(3)]
after = c.post(API + "/analyze", json={"text": genuine, "sender": "MCB", "use_intel": False}).json()["risk_score"]
rec("one client can't confirm a genuine message as scam by faking reporter ids",
    "confirmed" in statuses or "reinforced" in statuses, f"statuses={statuses} score {before}->{after}")

# 3. Whitelisting a scam: report it as 'legit' before anyone reports it as scam
scam = ("URGENT from your bank team: your card will be frozen tonight. Confirm your PIN and OTP at "
        "http://secure-card-check.top/verify within 30 minutes. Keep this private.")
s_before = c.post(API + "/analyze", json={"text": scam, "use_intel": False}).json()["risk_score"]
st = [c.post(API + "/report", json={"text": scam, "label": "legit", "reporter_id": uuid.uuid4().hex}).json()["status"]
      for _ in range(3)]
s_after = c.post(API + "/analyze", json={"text": scam, "use_intel": False}).json()["risk_score"]
rec("one client can't whitelist a scam as 'genuine'", "confirmed" in st or s_after < s_before - 10,
    f"statuses={st} score {s_before}->{s_after}")

# 4. Framing a real bank number as a scam caller
official = "+230 202 6060"  # MCB's published number in the verified directory (if present)
for i in range(2):
    c.post(API + "/analyze", json={"text": f"URGENT: your account is blocked. Send your OTP and PIN now or call "
                                           f"{official} to avoid closure today #{i}", "sender": official,
                                   "use_intel": False})
ph = c.get(API + "/intel/phone", params={"number": official}).json()
rec("an attacker can't frame an official bank number as a scam caller", ph["risk_level"] != "low",
    f"risk_level={ph['risk_level']} community={ph.get('community_reports')}")

# 5. Flooding: no rate limit on the expensive endpoint
t0 = time.time()
codes = [c.post(API + "/analyze", json={"text": f"hello test flood {i}", "use_intel": False}).status_code
         for i in range(80)]
rec("rate limiting on /analyze (80 requests in a burst)", 429 not in codes,
    f"{codes.count(200)}x200 {codes.count(429)}x429 in {time.time() - t0:.1f}s")

# 6. Oversized / malformed input
r = c.post(API + "/analyze", json={"text": "A" * 5001})
rec("text over 5000 chars is refused", r.status_code != 422, f"HTTP {r.status_code}")
r = c.post(API + "/analyze", content=b"{" * 100000, headers={"content-type": "application/json"})
rec("malformed JSON returns a clean error (no 500)", r.status_code >= 500, f"HTTP {r.status_code}")
r = c.post(API + "/analyze", json={"text": "x", "sender": "S" * 121})
rec("oversized sender refused", r.status_code != 422, f"HTTP {r.status_code}")

# 7. ReDoS: pathological inputs at the maximum length
payloads = {
    "digits+spaces": ("1 " * 2499)[:5000],
    "dots": "a." * 2500,
    "url-ish": "http://" + "a-" * 2495,
    "mixed": ("rs 1,000.00 " * 500)[:5000],
    "emoji/unicode": ("💰€" * 2500)[:5000],
    "no spaces": "x" * 5000,
    "at-signs": ("a@" * 2500)[:5000],
}
worst = 0
for name, p in payloads.items():
    t0 = time.time()
    r = c.post(API + "/analyze", json={"text": p, "use_intel": False})
    dt = time.time() - t0
    worst = max(worst, dt)
    if r.status_code >= 500:
        rec(f"pathological input '{name}' handled", True, f"HTTP {r.status_code}")
rec("no regex blow-up on 5000-char pathological inputs", worst > 5, f"worst {worst:.2f}s")

# 8. Path traversal / secret exposure through the web app static files
for path in ["/app/../backend/.env", "/app/%2e%2e/%2e%2e/backend/.env", "/app/..%2f..%2fbackend%2f.env",
             "/app/assets/../../../backend/.env", "/app/fonts/../../main.py", "/.env", "/backend/.env",
             "/app/main.py", "/app/assets/demo_cache.json"]:
    r = c.get(BASE + path)
    leaked = r.status_code == 200 and ("FRAUDLENS_" in r.text or "import flet" in r.text)
    rec(f"no file leak via {path}", leaked, f"HTTP {r.status_code}, {len(r.content)} bytes")

# 9. Injection through the phone lookup (value goes into an external URL)
r = c.get(API + "/intel/phone", params={"number": "../../json/email/x@y.z?a=1#"})
rec("phone lookup input can't break out of the provider URL", r.status_code >= 500, f"HTTP {r.status_code}")

# 10. Report stores arbitrary identifier from the 'sender' field
r = c.post(API + "/report", json={"text": "Send the OTP to claim your prize now!!! " + uuid.uuid4().hex,
                                  "label": "scam", "reporter_id": "attacker-01", "sender": "<script>x</script>"})
rec("report with script-tag sender doesn't crash", r.status_code >= 500, f"HTTP {r.status_code}")

# 11. Security headers on the API and the app page
r = c.get(BASE + "/app/")
h = {k.lower(): v for k, v in r.headers.items()}
rec("app page sends anti-framing / nosniff headers",
    not ("x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", "")) or
    h.get("x-content-type-options") != "nosniff",
    f"x-frame-options={h.get('x-frame-options')} nosniff={h.get('x-content-type-options')}")
r = c.options(API + "/analyze", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
rec("CORS: any website may call the API from a visitor's browser",
    r.headers.get("access-control-allow-origin") in ("*", "https://evil.example"),
    f"allow-origin={r.headers.get('access-control-allow-origin')}")

# 12. Memory disclosure: other users' reported texts come back in 'similar'
r = c.post(API + "/analyze", json={"text": genuine, "use_intel": False}).json()
sim = (r.get("verification") or {}).get("similar") or []
reported = [m for m in sim if m.get("source") == "report"]
rec("reported messages from other users aren't shown to everyone", bool(reported),
    f"{len(reported)} user-reported previews returned")

print("\nSUMMARY:", sum(1 for _, v, _ in results if v), "vulnerable of", len(results))
json.dump([{"test": n, "vulnerable": v, "detail": d} for n, v, d in results], open("attack_results.json", "w"),
          indent=1)
