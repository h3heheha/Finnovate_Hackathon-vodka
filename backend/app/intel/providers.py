"""External reputation providers. Each function does ONE network call and returns plain data.

Caching, time limits and error handling live in service.py, so these stay simple.
Only URLs, domains and phone numbers are ever sent, never message text.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urljoin

import httpx

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
# Registry RDAP servers for the most common TLDs, so domain age works even before (or without)
# the IANA directory download. The directory, once fetched, takes precedence.
RDAP_BUILTIN = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "info": "https://rdap.identitydigital.services/rdap/",
    "xyz": "https://rdap.centralnic.com/xyz/",
    "online": "https://rdap.centralnic.com/online/",
    "site": "https://rdap.centralnic.com/site/",
    "app": "https://pubapi.registry.google/rdap/",
    "dev": "https://pubapi.registry.google/rdap/",
}
IPQS_PHONE = "https://www.ipqualityscore.com/api/json/phone/{key}/{number}"
TELESIGN_FALLBACK_BASE = "https://rest-api.telesign.com"

THREAT_LABELS = {
    "SOCIAL_ENGINEERING": "phishing / fake website",
    "MALWARE": "malware",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "harmful app",
}


class ProviderError(Exception):
    pass


# ---- Google Safe Browsing ---------------------------------------------------------------
async def safe_browsing(client: httpx.AsyncClient, key: str, urls: list[str]) -> dict[str, dict]:
    body = {
        "client": {"clientId": "fraudlens", "clientVersion": "0.3.0"},
        "threatInfo": {
            "threatTypes": list(THREAT_LABELS),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    r = await client.post(SAFE_BROWSING_URL, params={"key": key}, json=body)
    if r.status_code != 200:
        try:
            msg = r.json().get("error", {}).get("message") or r.text[:120]
        except ValueError:
            msg = r.text[:120]
        raise ProviderError(f"Safe Browsing HTTP {r.status_code}: {msg}")
    out: dict[str, dict] = {}
    for m in r.json().get("matches", []):
        url = m.get("threat", {}).get("url")
        if url:
            out[url] = {"threat": m.get("threatType"), "label": THREAT_LABELS.get(m.get("threatType"), "unsafe")}
    return out


# ---- URLhaus (abuse.ch) -------------------------------------------------------------------
def _urlhaus_check(data: dict) -> None:
    status = data.get("query_status")
    if status not in ("ok", "no_results", "is_host"):
        raise ProviderError(f"URLhaus: {status}")


async def urlhaus_url(client: httpx.AsyncClient, key: str, url: str) -> dict:
    r = await client.post(URLHAUS_URL, data={"url": url}, headers={"Auth-Key": key})
    if r.status_code != 200:
        raise ProviderError(f"URLhaus HTTP {r.status_code}")
    d = r.json()
    _urlhaus_check(d)
    listed = d.get("query_status") == "ok"
    return {"listed": listed, "status": d.get("url_status"), "threat": d.get("threat"),
            "tags": d.get("tags") or []}


async def urlhaus_host(client: httpx.AsyncClient, key: str, host: str) -> dict:
    r = await client.post(URLHAUS_HOST, data={"host": host}, headers={"Auth-Key": key})
    if r.status_code != 200:
        raise ProviderError(f"URLhaus HTTP {r.status_code}")
    d = r.json()
    _urlhaus_check(d)
    count = int(d.get("url_count") or 0) if d.get("query_status") == "ok" else 0
    return {"listed": count > 0, "url_count": count}


# ---- RDAP (domain age) ---------------------------------------------------------------------
async def rdap_bootstrap(client: httpx.AsyncClient) -> dict[str, str]:
    r = await client.get(RDAP_BOOTSTRAP)
    if r.status_code != 200:
        raise ProviderError(f"RDAP bootstrap HTTP {r.status_code}")
    mapping: dict[str, str] = {}
    for tlds, servers in r.json().get("services", []):
        if servers:
            for tld in tlds:
                mapping[tld.lower()] = servers[0]
    return mapping


async def rdap_domain(client: httpx.AsyncClient, base: str, domain: str) -> dict:
    r = await client.get(urljoin(base if base.endswith("/") else base + "/", f"domain/{domain}"),
                         headers={"Accept": "application/rdap+json"}, follow_redirects=True)
    if r.status_code == 404:
        return {"supported": True, "found": False}
    if r.status_code != 200:
        raise ProviderError(f"RDAP HTTP {r.status_code}")
    d = r.json()
    registered = next((e.get("eventDate") for e in d.get("events", [])
                       if e.get("eventAction") == "registration"), None)
    age_days = None
    if registered:
        try:
            dt = datetime.fromisoformat(registered.replace("Z", "+00:00"))
            age_days = max(0, (datetime.now(timezone.utc) - dt).days)
        except ValueError:
            pass
    registrar = None
    for ent in d.get("entities", []):
        if "registrar" in (ent.get("roles") or []):
            vcard = ent.get("vcardArray", [None, []])[1]
            registrar = next((v[3] for v in vcard if v and v[0] == "fn"), None)
    return {"supported": True, "found": True, "registered": registered, "age_days": age_days,
            "registrar": registrar}


# ---- IPQualityScore phone reputation ---------------------------------------------------------
def e164(number: str, default_cc: str = "230") -> str:
    digits = re.sub(r"\D", "", number)
    if number.strip().startswith("+") or len(digits) > 8:
        return digits
    return default_cc + digits  # local Mauritian number (7-8 digits)


async def ipqs_phone(client: httpx.AsyncClient, key: str, number: str, country: str) -> dict:
    r = await client.get(IPQS_PHONE.format(key=key, number=number), params={"country[]": country})
    if r.status_code != 200:
        raise ProviderError(f"IPQS HTTP {r.status_code}")
    d = r.json()
    if not d.get("success"):
        raise ProviderError(f"IPQS: {d.get('message', 'failed')}"[:160])
    keep = ("valid", "fraud_score", "recent_abuse", "VOIP", "prepaid", "risky", "active", "line_type",
            "carrier", "country", "spammer")
    return {k: d.get(k) for k in keep}


# ---- Telesign Intelligence (phone risk score) ---------------------------------------------------
async def telesign_score(client: httpx.AsyncClient, base_url: str, customer_id: str, api_key: str,
                         number: str) -> dict:
    """POST /v1/score/{number}: risk score 0-1000 + allow / flag / block recommendation."""
    bases = list(dict.fromkeys([base_url.rstrip("/"), TELESIGN_FALLBACK_BASE]))
    r = None
    for i, base in enumerate(bases):
        try:
            r = await client.post(f"{base}/v1/score/{number}", auth=(customer_id, api_key),
                                  data={"account_lifecycle_event": "create"})
            break
        except httpx.ConnectError:
            if i == len(bases) - 1:
                raise
    try:
        d = r.json()
    except ValueError:
        d = {}
    risk = d.get("risk") or {}
    if r.status_code >= 400 or not risk:
        errs = d.get("errors") or []
        msg = (errs[0].get("description") if errs else None) or (d.get("status") or {}).get("description") \
            or r.text[:120]
        raise ProviderError(f"Telesign HTTP {r.status_code}: {msg}")
    return {"score": risk.get("score"), "level": risk.get("level"), "recommendation": risk.get("recommendation"),
            "phone_type": (d.get("phone_type") or {}).get("description"),
            "carrier": (d.get("carrier") or {}).get("name"),
            "country": ((d.get("location") or {}).get("country") or {}).get("name")}


# ---- Offline number facts (Google libphonenumber data, no network, no key) -------------------------
CARRIER_NAMES = {"Cellplus": "my.t (Cellplus)", "MTML": "MTML (Chili)"}


def number_facts(number: str, default_cc: str = "230") -> dict:
    """Is this a real number range? Mobile, fixed line, VoIP, premium? Which network and country?"""
    import phonenumbers
    from phonenumbers import PhoneNumberType as T, carrier, geocoder
    try:
        n = phonenumbers.parse("+" + e164(number, default_cc), None)
    except phonenumbers.NumberParseException:
        return {"valid": False, "country": None, "region": None, "type": "unknown", "carrier": None}
    types = {T.MOBILE: "mobile", T.FIXED_LINE: "fixed line", T.FIXED_LINE_OR_MOBILE: "mobile or fixed line",
             T.VOIP: "internet (VoIP)", T.TOLL_FREE: "toll-free", T.PREMIUM_RATE: "premium-rate",
             T.SHARED_COST: "shared-cost", T.PERSONAL_NUMBER: "personal forwarding", T.PAGER: "pager",
             T.UAN: "company number", T.VOICEMAIL: "voicemail"}
    name = carrier.name_for_number(n, "en") or None
    return {"valid": phonenumbers.is_valid_number(n),
            "region": phonenumbers.region_code_for_number(n),
            "country": geocoder.country_name_for_number(n, "en") or None,
            "type": types.get(phonenumbers.number_type(n), "unknown"),
            "carrier": CARRIER_NAMES.get(name, name)}


# ---- Short-link expansion ---------------------------------------------------------------------
async def expand_short_link(client: httpx.AsyncClient, url: str, shorteners: set[str], max_hops: int = 3) -> str:
    """Follow redirects ONLY while the next hop is still a URL shortener.

    We never contact the final destination (which could tip off the scammer):
    we read the `Location` header the shortener gives us and stop there.
    """
    current = url if url.lower().startswith(("http://", "https://")) else f"http://{url}"
    for _ in range(max_hops):
        host = re.sub(r"^https?://", "", current, flags=re.I).split("/")[0].lower()
        if host.startswith("www."):
            host = host[4:]
        if host not in shorteners:
            break
        r = await client.head(current, follow_redirects=False)
        if r.status_code not in (301, 302, 303, 307, 308) or "location" not in r.headers:
            r = await client.get(current, follow_redirects=False)  # some shorteners reject HEAD
            if r.status_code not in (301, 302, 303, 307, 308) or "location" not in r.headers:
                break
        current = urljoin(current, r.headers["location"])
    return current
