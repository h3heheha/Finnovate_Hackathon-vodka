"""Check that every threat-intelligence provider works with YOUR keys (needs internet).

    python -m scripts.check_intel              # uses 1 Telesign + 1 IPQS credit (if configured)
    python -m scripts.check_intel --no-paid    # free: skips Telesign and IPQS
    python -m scripts.check_intel --no-ipqs    # skip only IPQS

Uses official test values where they exist:
  * Google's Safe Browsing test URL is ALWAYS flagged as phishing.
  * URLhaus is queried for example.com (should answer "not listed", which proves the key works).
  * RDAP looks up google.com (registered in 1997).
"""
import argparse
import asyncio

from app.core.config import get_settings
from app.intel.service import IntelService

SB_TEST = "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/SOCIAL_ENGINEERING/URL/"


def line(ok: bool, name: str, msg: str) -> None:
    print(f"  {'OK  ' if ok else 'FAIL'}  {name:24} {msg}")


async def main(ipqs: bool, telesign: bool) -> None:
    s = get_settings()
    svc = IntelService(s)
    print("Configured:", {k: v for k, v in svc.status().items()})
    if s.rdap_enabled:
        print("  ...   downloading the RDAP directory (once, up to 20 s)")
        ok = await svc.warm_up()
        line(ok, "RDAP directory", "cached for 7 days" if ok else
             "download failed; .com/.net/.org still work from the built-in table")
    svc.cache.set(f"sb:{SB_TEST}", None, 0)  # make sure we really call the APIs

    r = await svc.check([SB_TEST], [], check_phones=False)
    hit = any(f.source == "Google Safe Browsing" for f in r.findings)
    line(hit, "Google Safe Browsing", "test URL flagged" if hit else f"not flagged: {r.providers}")

    r = await svc.check(["http://example.com/"], [], check_phones=False)
    st = r.providers.get("URLhaus", "?")
    line(st.startswith("ok"), "URLhaus", f"status: {st}")

    r = await svc.check(["https://www.google.com/"], [], check_phones=False)
    st = r.providers.get("RDAP domain age", "?")
    age = next((f.detail for f in r.findings if f.source == "RDAP"), "")
    line(st.startswith("ok"), "RDAP domain age", f"{st} · {age}")

    r = await svc.check(["https://bit.ly/3example"], [], check_phones=False)
    st = r.providers.get("Short-link expansion", "not needed")
    line(not st.startswith("error"), "Short-link expansion", f"status: {st} {r.expanded or ''}")

    from app.intel.providers import number_facts
    try:
        f = number_facts("+230 5733 1928")
        line(f["valid"], "Number check (offline)", f"+230 5733 1928 -> {f['type']} · {f['carrier']} · {f['country']}")
    except ImportError:
        line(False, "Number check (offline)", "run: pip install phonenumbers")

    if telesign and s.telesign_customer_id and s.telesign_api_key:
        r = await svc.check([], ["+230 5250 0000"], check_phones=True)
        st = r.providers.get("Telesign", "?")
        det = next((f.detail for f in r.findings if f.source == "Telesign"), "")
        line(st.startswith("ok"), "Telesign", f"{st} · {det}")
        print(f"  Telesign lookups used today: {svc.cache.used_today('telesign')}/{s.telesign_daily_limit}")
    elif telesign:
        print("  skip  Telesign                 (FRAUDLENS_TELESIGN_CUSTOMER_ID / _API_KEY not set)")
    else:
        print("  skip  Telesign                 (--no-paid)")

    if ipqs and s.ipqs_key:
        r = await svc.check([], ["+230 5250 0000"], check_phones=True)
        st = r.providers.get("IPQualityScore", "?")
        det = next((f.detail for f in r.findings if f.source == "IPQualityScore"), "")
        line(st.startswith("ok"), "IPQualityScore", f"{st} · {det}")
        print(f"  IPQS credits used today: {svc.cache.used_today('ipqs')}/{s.ipqs_daily_limit}")
    elif ipqs:
        print("  skip  IPQualityScore           (no key)")
    else:
        print("  skip  IPQualityScore           (--no-ipqs / --no-paid)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-ipqs", action="store_true", help="skip IPQualityScore")
    ap.add_argument("--no-paid", action="store_true", help="skip Telesign and IPQualityScore (no credits used)")
    a = ap.parse_args()
    asyncio.run(main(ipqs=not (a.no_ipqs or a.no_paid), telesign=not a.no_paid))
