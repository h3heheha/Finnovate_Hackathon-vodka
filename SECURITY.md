# FraudLens security review

**Date:** 24 Sep 2026
**Scope:** the backend API, the web app served at `/app`, and the native FraudLens Android app (including Shield).
**Method:** code review, plus a 24-case attack script run against a local server before and after the fixes, a dependency CVE scan (`pip-audit`: no known vulnerabilities), and the test suite (61 passed, 1 skipped; this includes the new `tests/test_security.py`).

## Found and fixed

| # | Severity | Issue | Proof before the fix | Fix |
|---|---|---|---|---|
| 1 | **High** | Admin endpoints accepted the default token `change-me` | `POST /admin/rollback` with `change-me` rolled the live model back to an older version. After that, a genuine bank OTP scored 93/100. | Admin endpoints are **disabled** unless `FRAUDLENS_ADMIN_TOKEN` has 16+ characters. The comparison is constant-time. `.env` now leaves it empty. |
| 2 | **High** | Report poisoning: one client could invent `reporter_id`s | 3 reports with random ids → a genuine OTP was "confirmed scam" and its score went up. A scam could be "whitelisted" the same way. | Independent reporters are counted **per device (IP)**, not per self-declared id. The in-app web client forwards the browser's IP in a header that is trusted from loopback only. |
| 3 | **High** | Anyone could frame a phone number (e.g. a bank's) as a "scam caller" | Two scans mentioning the number → `/intel/phone` said **high**. Shield would warn during a real bank call. | Numbers in the verified directory are **never flagged**. In normal mode (`REPORT_CONFIRMATIONS≥2`), caller reputation counts **independent devices**, so one attacker counts once. |
| 4 | Medium | No rate limiting: CPU exhaustion, and paid IPQS lookups could be burned | 80 analyze calls in 1 s were all accepted. | 30 weighted requests per minute per device on analyze, report, feedback, payments, intel and admin (`FRAUDLENS_RATE_LIMIT_PER_MINUTE`). Returns 429; the app shows a friendly message. |
| 5 | Medium | CORS `*`: any website could drive the API from a visitor's browser on the same network | `Access-Control-Allow-Origin: *` | CORS is off by default. Neither the app (server-side) nor Shield (native) needs it. |
| 6 | Medium | Real API keys in `backend/.env` and `.env.example`, which are inside the shared zip | Safe Browsing, URLhaus and IPQS keys were in plain text. | **Kept for now by team decision** (needed for the demo). Create new keys after the hackathon and don't share the zip publicly. |
| 7 | Low | Missing security headers | No `nosniff`, no anti-framing. | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`. |
| 8 | Low | `/report` stored the raw `sender` as a phone identifier (not normalised, any text) | `<script>` or free text could be stored as `tel:…` | Uses the same `sender_identifier()` rule as `/analyze`: only real phone numbers, normalised. |

## Checked and fine
- **Input limits:** text is capped at 5000 characters and sender at 120, and malformed JSON returns 422. No 500 errors under fuzzing.
- **ReDoS:** seven pathological 5000-character inputs each finished in under 0.2 s.
- **Path traversal on `/app`:** eight variants (`..`, `%2e%2e`, `%2f`) returned 404 or the app page. No file leaked, including `.env` and `main.py`.
- **SSRF through short-link unmasking:** only exact shortener hosts are contacted, and the final destination never is. Userinfo, port and `#` tricks don't match a shortener.
- **Injection into provider URLs:** phone numbers are reduced to digits before being sent to IPQS or Telesign.
- **Dependencies:** `pip-audit` found no known CVEs in `requirements.txt`.
- **FraudLens Android app:**
  - The app is fully native (no WebView). Shared text is only read, capped at 5000 characters and sent to your own server; links in results open in the phone's browser only when you tap them. Only the main screen is exported (for the launcher and Share); the result screen is not.
  - Services are protected by `BIND_NOTIFICATION_LISTENER_SERVICE` and `BIND_SCREENING_SERVICE`, and the detail screen isn't exported.
  - PendingIntents are `FLAG_IMMUTABLE`, and `allowBackup` is false.
  - It asks for no SMS, call-log or phone-state permissions, and message text is never written to logs.

## Accepted risks (fine for a demo, fix before real users)
- **Plain HTTP on the local network.** Suspicious messages go from Shield to the laptop unencrypted, and someone on the same Wi-Fi could read or fake verdicts. Use your own phone hotspot for the demo. In production, deploy behind HTTPS and remove `usesCleartextTraffic`.
- **Demo mode (`REPORT_CONFIRMATIONS=1`) turns anti-poisoning off.** One report confirms a scam, and one device can flag a caller. This is what makes the live demo work. Use 2 or more anywhere else.
- **"Closest known messages" shows previews** of confirmed reported scams to everyone. They are redacted (numbers, cards, emails, OTPs), but names can remain.
- **No authentication:** anyone on the network can use the API, within the rate limits.
- **The web app keeps a server session per open browser tab.** Many tabs cost server memory.
- **Official phone numbers:** now filled in `backend/app/knowledge/directory.json` from each organisation's own website (24 Sep 2026, with the source link per entry): MCB, SBM, Absa, MauBank, Bank of Mauritius (including its scam hotline), FSC, MRA, Mauritius Post and DHL. PayPal publishes no Mauritius phone line. Fix 3 protects all of these numbers; a live test flagging them 3 times left each one at "low".

## Re-run the checks
Attack script, against a running local server. Start the server with `FRAUDLENS_RATE_LIMIT_PER_MINUTE=0` so every check gets past the rate limiter:
```bat
cd backend
python -m scripts.security_attacks http://127.0.0.1:8000
```
Unit tests:
```bat
cd backend
python -m pytest -q
```
