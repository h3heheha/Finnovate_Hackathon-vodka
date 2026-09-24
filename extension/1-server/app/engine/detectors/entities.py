"""Entity detector: links, lookalike domains, brands, phone numbers, accounts, wallets, amounts.

These are deterministic checks that an LLM is bad at (exact string distance,
domain structure) and they give the app concrete things to act on, such as
the account number used by the Pause-Before-Pay check.
"""
import ipaddress
import re

import tldextract
from rapidfuzz.distance import Levenshtein

from ...knowledge import loader
from .base import DetectionContext, Signal

FLAGS = re.IGNORECASE | re.UNICODE

# Offline extractor: uses the bundled public-suffix snapshot, no network call.
_extract = tldextract.TLDExtract(suffix_list_urls=())

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "ow.ly", "tiny.cc",
    "buff.ly", "rebrand.ly", "s.id", "t.co", "goo.gl", "v.gd", "shorte.st", "bl.ink", "lnkd.in",
}
RISKY_TLDS = {
    "xyz", "top", "click", "live", "icu", "buzz", "online", "site", "info", "shop", "rest", "link",
    "cam", "monster", "support", "help", "gq", "tk", "ml", "cf", "ga", "work", "loan", "vip",
}
# Words scammers add to a brand name to build convincing domains.
BAIT_WORDS = ("secure", "verify", "verification", "login", "update", "account", "support", "service",
              "confirm", "online", "banking", "alert", "unlock", "refund", "pay", "portal", "help")

_URL_RE = re.compile(
    r"(?:(?:https?://|www\.)[^\s<>\"'()]+)"
    r"|(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|mu|info|xyz|top|click|live|online|"
    r"site|io|co|ly|gd|me|app|shop|icu|buzz|link|support|help|vip|tk|ml|cc|at|in|id|uk)"
    r"(?:/[^\s<>\"'()]*)?",
    FLAGS,
)
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,4})?\b")
_WALLET_RE = re.compile(r"\b(?:0x[a-fA-F0-9]{40}|T[1-9A-HJ-NP-Za-km-z]{33}|bc1[a-z0-9]{25,59}|"
                        r"[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_AMOUNT_RE = re.compile(
    r"(?:\b(?:rs\.?|mur|usd|eur|usdt)\s?\d[\d,]*(?:\.\d+)?|[€$£]\s?\d[\d,]*(?:\.\d+)?|"
    r"\b\d[\d,]*(?:\.\d+)?\s?(?:rs|mur|rupees?|roupies?|usd|eur|usdt)\b)",
    FLAGS,
)
_NUMBER_RE = re.compile(r"(?<![\w.,])\+?\d[\d \-]{5,22}\d(?![\w.,]*\d)")
_HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("@", "a")]


def _normalise(label: str) -> str:
    out = label.lower()
    for a, b in _HOMOGLYPHS:
        out = out.replace(a, b)
    return out


def _overlaps(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < e and end > s for s, e in spans)


def _registered_domain(host: str) -> tuple[str, str, str]:
    ext = _extract(host)
    return ext.domain.lower(), ext.suffix.lower(), ext.subdomain.lower()


def _host_of(url: str) -> str:
    host = re.sub(r"^(?:https?://)", "", url, flags=re.I)
    host = host.split("/")[0].split("?")[0].split("#")[0]
    if "@" in host:  # user@host trick
        host = host.split("@")[-1]
    return host.split(":")[0].rstrip(".").lower()


def _check_domain(url: str, start: int, end: int, ctx: DetectionContext) -> list[Signal]:
    signals: list[Signal] = []
    host = _host_of(url)
    domain, suffix, subdomain = _registered_domain(host)
    registered = f"{domain}.{suffix}" if suffix else domain
    ctx.entities.domains.append(registered)
    official = loader.official_domains()

    def add(detail: str, weight: float):
        signals.append(Signal("suspicious_link", url, start, end, weight=weight, detail=detail))

    if "@" in url.split("//")[-1].split("/")[0]:
        add("The link hides its real destination after an '@' sign.", 0.5)

    try:
        ipaddress.ip_address(host)
        add("The link points to a raw IP address instead of a company website.", 0.5)
        return signals
    except ValueError:
        pass

    if registered in official:
        ctx.entities.official_links.append(url)
        ctx.trust_notes.append(f"Contains a link to the official {official[registered]['name']} website.")
        return signals

    if host in SHORTENERS or registered in SHORTENERS:
        add("Shortened link: you can't see where it really goes.", 0.35)
        return signals

    if host.startswith("xn--") or ".xn--" in host:
        add("The address uses look-alike foreign characters (punycode).", 0.6)

    # Brand impersonation: official brand name inside an unofficial domain.
    full = f"{subdomain}.{domain}" if subdomain else domain
    for org in loader.organisations():
        for off in org["domains"]:
            off_label = off.split(".")[0]
            norm = _normalise(domain)
            if len(off_label) >= 3 and (off_label in re.split(r"[-.]", full) or
                                        (off_label in full and any(w in full for w in BAIT_WORDS))):
                add(f"Uses the name '{off_label.upper()}' but is not the official site ({off}).", 0.6)
                ctx.entities.brands.append(org["id"])
                return signals
            if norm != domain and norm == off_label:
                add(f"Look-alike spelling of the official site {off}.", 0.65)
                ctx.entities.brands.append(org["id"])
                return signals
            max_edits = 1 if len(off_label) <= 5 else 2
            if len(off_label) >= 4 and 0 < Levenshtein.distance(norm, off_label) <= max_edits:
                add(f"Almost the same as the official site {off}, but not quite.", 0.6)
                ctx.entities.brands.append(org["id"])
                return signals
            if domain == off_label and registered != off:
                add(f"Right name, wrong ending: the official site is {off}, not {registered}.", 0.55)
                ctx.entities.brands.append(org["id"])
                return signals

    if suffix.split(".")[-1] in RISKY_TLDS:
        add(f"Uses a '.{suffix}' address, common in throwaway scam sites.", 0.3)
    if url.lower().startswith("http://"):
        add("The link is not secure (http, no padlock).", 0.1)
    if not signals:
        # Unknown domain in a message is a mild signal on its own.
        add("Contains a link to an unverified website.", 0.12)
    return signals


def detect(ctx: DetectionContext) -> list[Signal]:
    signals: list[Signal] = []
    text = ctx.text
    taken: list[tuple[int, int]] = []

    # Links ------------------------------------------------------------
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?)")
        if re.fullmatch(r"[\d.]+", url):  # e.g. "1,250.00" false positive guard
            continue
        end = m.start() + len(url)
        ctx.entities.urls.append(url)
        taken.append((m.start(), end))
        signals.extend(_check_domain(url, m.start(), end, ctx))

    # Brands mentioned in the text -> authority signal ---------------------
    lower = ctx.lower
    for org in loader.organisations():
        for kw in org["keywords"]:
            for m in re.finditer(rf"(?<![\w-]){re.escape(kw)}(?![\w-])", lower):
                if _overlaps(m.start(), m.end(), taken):
                    continue
                if org["id"] not in ctx.entities.brands:
                    ctx.entities.brands.append(org["id"])
                signals.append(Signal("authority", text[m.start():m.end()], m.start(), m.end(),
                                      detail=f"Mentions {org['name']} to look trustworthy."))

    # Crypto wallets ---------------------------------------------------
    for m in _WALLET_RE.finditer(text):
        if _overlaps(m.start(), m.end(), taken):
            continue
        ctx.entities.wallets.append(m.group(0))
        taken.append((m.start(), m.end()))
        signals.append(Signal("unusual_payment", m.group(0), m.start(), m.end(), weight=0.5,
                              detail="A crypto wallet address: payments to it can't be reversed."))

    # IBANs ----------------------------------------------------------
    for m in _IBAN_RE.finditer(text):
        if _overlaps(m.start(), m.end(), taken):
            continue
        ctx.entities.accounts.append(re.sub(r"\s", "", m.group(0)))
        taken.append((m.start(), m.end()))

    # Amounts ----------------------------------------------------------
    for m in _AMOUNT_RE.finditer(text):
        if _overlaps(m.start(), m.end(), taken):
            continue
        ctx.entities.amounts.append(m.group(0).strip())
        taken.append((m.start(), m.end()))

    # Phone numbers vs account numbers ------------------------------------
    for m in _NUMBER_RE.finditer(text):
        if _overlaps(m.start(), m.end(), taken):
            continue
        raw = m.group(0).strip()
        digits = re.sub(r"\D", "", raw)
        if raw.startswith("+") or 7 <= len(digits) <= 8 or (len(digits) in (10, 11) and digits.startswith("230")):
            ctx.entities.phone_numbers.append(raw)
        elif 9 <= len(digits) <= 20:
            ctx.entities.accounts.append(digits)
            signals.append(Signal("payment_redirection", raw, m.start(), m.end(), weight=0.2,
                                  detail="An account number sent by message: verify it before paying."))
        taken.append((m.start(), m.end()))

    return signals
