"""IntelService: runs every reputation check in parallel within a strict time budget.

    links ─► expand short links (shortener hops only) ─┬► Google Safe Browsing
                                                       ├► URLhaus (URL + host)
                                                       └► RDAP domain age
    phone numbers ─► IPQS phone reputation (only for suspicious messages, daily budget)

Results are cached in SQLite. Any provider that errors, is not configured or is too
slow is simply marked as such; the analysis never waits longer than the budget.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import httpx
import tldextract

from ..core.config import Settings
from ..knowledge import loader
from . import providers as P
from .cache import IntelCache

log = logging.getLogger("fraudlens.intel")
_extract = tldextract.TLDExtract(suffix_list_urls=())

TTL = {"sb": 6 * 3600, "uh": 12 * 3600, "rdap": 7 * 86400, "boot": 7 * 86400, "ipqs": 7 * 86400, "ts": 7 * 86400,
       "exp": 7 * 86400}
MAX_URLS = 3
MAX_PHONES = 2


@dataclass
class Finding:
    source: str        # "Google Safe Browsing", "URLhaus", "RDAP", "IPQualityScore", "FraudLens"
    kind: str          # url | domain | phone | link
    target: str        # the link / number exactly as it appeared in the message
    severity: str      # danger | warning | info
    title: str
    detail: str
    weight: float = 0.0  # 0..1 contribution to risk (0 for info)

    def public(self) -> dict:
        return {k: v for k, v in asdict(self).items()}


@dataclass
class IntelReport:
    enabled: bool = True
    findings: list[Finding] = field(default_factory=list)
    providers: dict[str, str] = field(default_factory=dict)
    expanded: dict[str, str] = field(default_factory=dict)
    latency_ms: int = 0

    @property
    def blocklisted(self) -> bool:
        return any(f.severity == "danger" and f.source in ("Google Safe Browsing", "URLhaus") for f in self.findings)

    @property
    def score(self) -> float:
        remaining = 1.0
        for f in self.findings:
            remaining *= 1 - min(f.weight, 0.99)
        return 1 - remaining

    def public(self) -> dict:
        return {"enabled": self.enabled, "providers": self.providers, "expanded_links": self.expanded,
                "findings": [f.public() for f in self.findings], "blocklisted": self.blocklisted,
                "score": round(self.score, 3), "latency_ms": self.latency_ms}


def _host(url: str) -> str:
    h = url.split("://", 1)[-1].split("/")[0].split("?")[0].split("@")[-1].split(":")[0].lower()
    return h[4:] if h.startswith("www.") else h


def _registered(host: str) -> tuple[str, str]:
    ext = _extract(host)
    return (f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain).lower(), ext.suffix.lower()


class IntelService:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self.s = settings
        self.cache = IntelCache(settings.data_dir / "cache" / "intel.sqlite")
        self._transport = transport  # injectable for tests
        from ..engine.detectors.entities import SHORTENERS
        self.shorteners = set(SHORTENERS)
        self._boot_task: asyncio.Task | None = None

    # ---- RDAP directory (downloaded once, in the background, never inside the 2.5 s budget) ----------
    async def warm_up(self) -> bool:
        """Fetch the IANA RDAP directory if it isn't cached yet. Safe to call many times."""
        if not self.s.rdap_enabled or self.cache.get("rdap:bootstrap") is not None:
            return True
        if self._boot_task is None or self._boot_task.done():
            self._boot_task = asyncio.create_task(self._fetch_bootstrap())
        try:
            return await asyncio.shield(self._boot_task)
        except asyncio.CancelledError:
            raise
        except Exception:
            return False

    async def _fetch_bootstrap(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=20, transport=self._transport) as client:
                boot = await P.rdap_bootstrap(client)
            self.cache.set("rdap:bootstrap", boot, TTL["boot"])
            log.info("RDAP directory cached (%d TLDs)", len(boot))
            return True
        except Exception as exc:  # the built-in table still covers .com/.net/.org...
            log.warning("RDAP directory download failed: %s", exc)
            return False

    # ---- status -------------------------------------------------------------------------------
    def status(self) -> dict:
        s = self.s
        return {
            "enabled": s.intel_enabled,
            "safe_browsing": bool(s.safe_browsing_key),
            "urlhaus": bool(s.urlhaus_key),
            "ipqs": bool(s.ipqs_key),
            "ipqs_used_today": self.cache.used_today("ipqs"),
            "ipqs_daily_limit": s.ipqs_daily_limit,
            "telesign": bool(s.telesign_customer_id and s.telesign_api_key),
            "telesign_used_today": self.cache.used_today("telesign"),
            "telesign_daily_limit": s.telesign_daily_limit,
            "number_check": s.number_check,
            "rdap": s.rdap_enabled,
            "short_link_expansion": s.expand_short_links,
        }

    # ---- main entry point -----------------------------------------------------------------------
    async def check(self, urls: list[str], phones: list[str], *, check_phones: bool = True) -> IntelReport:
        report = IntelReport(enabled=self.s.intel_enabled)
        if not self.s.intel_enabled or (not urls and not phones):
            return report
        t0 = time.perf_counter()
        official = loader.official_domains()
        urls = [u for u in dict.fromkeys(urls) if _registered(_host(u))[0] not in official][:MAX_URLS]
        phones = list(dict.fromkeys(phones))[:MAX_PHONES] if check_phones else []
        deadline = t0 + self.s.intel_timeout_seconds

        async with httpx.AsyncClient(timeout=self.s.intel_timeout_seconds, transport=self._transport,
                                     headers={"User-Agent": "FraudLens/0.3 (scam-awareness hackathon)"}) as client:
            # Stage 1: expand short links (max ~40% of the budget)
            targets = {u: u for u in urls}  # checked URL -> original URL in the message
            if self.s.expand_short_links:
                short = [u for u in urls if _registered(_host(u))[0] in self.shorteners or _host(u) in self.shorteners]
                if short:
                    res = await self._run({u: self._expand(client, u) for u in short},
                                          min(deadline, t0 + 0.4 * self.s.intel_timeout_seconds), report, "expand")
                    for u, final in res.items():
                        if final and final != u and _host(final) not in self.shorteners:
                            report.expanded[u] = final
                            targets[final] = u
                            report.findings.append(Finding("FraudLens", "link", u, "info", "Short link unmasked",
                                                           f"This short link actually leads to {final}"))

            # Stage 2: everything else in parallel
            jobs = {}
            every = list(targets)                       # short links too: blocklists know them
            real_sites = [t for t in every if not (_host(t) in self.shorteners or
                                                   _registered(_host(t))[0] in self.shorteners)]
            if every and self.s.safe_browsing_key:
                jobs["sb"] = self._safe_browsing(client, every)
            elif every:
                report.providers["Google Safe Browsing"] = "not configured"
            if self.s.urlhaus_key:
                for t in every:
                    jobs[f"uh:url:{t}"] = self._urlhaus_url(client, t)
                for h in dict.fromkeys(_host(t) for t in real_sites):
                    jobs[f"uh:host:{h}"] = self._urlhaus_host(client, h)
            elif every:
                report.providers["URLhaus"] = "not configured"
            if self.s.rdap_enabled:
                for d in dict.fromkeys(_registered(_host(t))[0] for t in real_sites):
                    jobs[f"rdap:{d}"] = self._rdap(client, d)
            if phones and self.s.ipqs_key:
                for p in phones:
                    jobs[f"ipqs:{p}"] = self._ipqs(client, p)
            if phones and self.s.telesign_customer_id and self.s.telesign_api_key:
                for p in phones:
                    jobs[f"ts:{p}"] = self._telesign(client, p)
            elif phones:
                report.providers["Telesign"] = "not configured"

            results = await self._run(jobs, deadline, report, None)

        if phones and self.s.number_check:
            self._number_check(phones, report)
        self._to_findings(results, targets, report)
        report.latency_ms = int((time.perf_counter() - t0) * 1000)
        return report

    # ---- orchestration ------------------------------------------------------------------------
    async def _run(self, jobs: dict, deadline: float, report: IntelReport, label: str | None) -> dict:
        if not jobs:
            return {}
        tasks = {asyncio.create_task(coro): key for key, coro in jobs.items()}
        done, pending = await asyncio.wait(tasks, timeout=max(0.05, deadline - time.perf_counter()))
        for t in pending:
            t.cancel()
            report.providers[self._provider(tasks[t], label)] = "timeout"
        out = {}
        for t in done:
            key = tasks[t]
            name = self._provider(key, label)
            exc = t.exception()
            if exc is not None:
                log.warning("intel %s failed: %s", key, exc)
                report.providers[name] = f"error: {str(exc)[:80]}"
                continue
            value, status = t.result()
            out[key] = value
            if report.providers.get(name) not in ("ok",):
                report.providers[name] = status
        return out

    @staticmethod
    def _provider(key: str, label: str | None) -> str:
        if label == "expand":
            return "Short-link expansion"
        return {"sb": "Google Safe Browsing", "uh": "URLhaus", "rdap": "RDAP domain age",
                "ipqs": "IPQualityScore", "ts": "Telesign"}[key.split(":")[0]]

    # ---- cached provider calls (each returns (value, status)) ----------------------------------------
    async def _cached(self, key: str, ttl: int, fetch):
        hit = self.cache.get(key)
        if hit is not None:
            return hit, "ok (cached)"
        value = await fetch()
        self.cache.set(key, value, ttl)
        return value, "ok"

    async def _expand(self, client, url):
        return await self._cached(f"exp:{url}", TTL["exp"],
                                  lambda: P.expand_short_link(client, url, self.shorteners))

    async def _safe_browsing(self, client, urls):
        cached = {u: self.cache.get(f"sb:{u}") for u in urls}
        todo = [u for u, v in cached.items() if v is None]
        if todo:
            fresh = await P.safe_browsing(client, self.s.safe_browsing_key, todo)
            for u in todo:
                cached[u] = fresh.get(u, {})
                self.cache.set(f"sb:{u}", cached[u], TTL["sb"])
        return cached, "ok" if todo else "ok (cached)"

    async def _urlhaus_url(self, client, url):
        return await self._cached(f"uh:url:{url}", TTL["uh"], lambda: P.urlhaus_url(client, self.s.urlhaus_key, url))

    async def _urlhaus_host(self, client, host):
        return await self._cached(f"uh:host:{host}", TTL["uh"],
                                  lambda: P.urlhaus_host(client, self.s.urlhaus_key, host))

    async def _rdap(self, client, domain):
        async def fetch():
            tld = domain.rsplit(".", 1)[-1]
            boot = self.cache.get("rdap:bootstrap")
            if boot is None and tld not in P.RDAP_BUILTIN:
                # Unusual TLD: wait for the directory. If the budget runs out first, the download
                # carries on in the background, so the next check is fast.
                await self.warm_up()
                boot = self.cache.get("rdap:bootstrap")
            elif boot is None:
                self._start_warm_up()
            boot = boot or {}
            base = boot.get(domain.split(".", 1)[-1]) or boot.get(tld) or P.RDAP_BUILTIN.get(tld)
            if not base:
                return {"supported": False, "tld": tld}
            return await P.rdap_domain(client, base, domain)
        return await self._cached(f"rdap:{domain}", TTL["rdap"], fetch)

    def _start_warm_up(self) -> None:
        if self.s.rdap_enabled and (self._boot_task is None or self._boot_task.done()):
            self._boot_task = asyncio.create_task(self._fetch_bootstrap())

    async def _ipqs(self, client, phone):
        number = P.e164(phone)
        hit = self.cache.get(f"ipqs:{number}")
        if hit is not None:
            return hit, "ok (cached)"
        if not self.cache.take("ipqs", self.s.ipqs_daily_limit):
            return {"skipped": "daily budget used"}, "daily budget used"
        try:
            value = await P.ipqs_phone(client, self.s.ipqs_key, number, self.s.ipqs_country)
        except (httpx.HTTPError, OSError, P.ProviderError):
            self.cache.refund("ipqs")  # network trouble or refused query: don't charge the daily budget
            raise
        self.cache.set(f"ipqs:{number}", value, TTL["ipqs"])
        return value, "ok"

    async def _telesign(self, client, phone):
        number = P.e164(phone)
        hit = self.cache.get(f"ts:{number}")
        if hit is not None:
            return hit, "ok (cached)"
        if not self.cache.take("telesign", self.s.telesign_daily_limit):
            return {"skipped": "daily budget used"}, "daily budget used"
        try:
            value = await P.telesign_score(client, self.s.telesign_base_url, self.s.telesign_customer_id,
                                           self.s.telesign_api_key, number)
        except (httpx.HTTPError, OSError, P.ProviderError):
            self.cache.refund("telesign")
            raise
        self.cache.set(f"ts:{number}", value, TTL["ts"])
        return value, "ok"

    def _number_check(self, phones: list[str], report: IntelReport) -> None:
        """Offline facts about each number: can't time out, costs nothing."""
        try:
            for p in phones:
                report.findings.extend(self._number_finding(p, P.number_facts(p)))
            report.providers["Number check (offline)"] = "ok"
        except ImportError:
            report.providers["Number check (offline)"] = "not installed (pip install phonenumbers)"

    def _number_finding(self, phone: str, v: dict) -> list[Finding]:
        home = self.s.ipqs_country.upper()
        where = v.get("country") or "unknown country"
        if not v.get("valid"):
            return [Finding("Number check", "phone", phone, "warning", "Not a real phone number",
                            "This number doesn't match any number range in use. Scammers often fake caller IDs.",
                            0.3)]
        kind = v.get("type") or "unknown"
        net = f" · {v['carrier']}" if v.get("carrier") else ""
        if kind == "internet (VoIP)":
            return [Finding("Number check", "phone", phone, "warning", "Internet (VoIP) number",
                            f"{where} internet number{net}. These are cheap and anonymous; banks call from "
                            "their official lines.", 0.3)]
        if kind == "premium-rate":
            return [Finding("Number check", "phone", phone, "warning", "Premium-rate number",
                            f"Calling this {where} number back costs extra money.", 0.4)]
        if v.get("region") and v["region"] != home:
            return [Finding("Number check", "phone", phone, "warning", f"Foreign number ({where})",
                            f"{kind.capitalize()} number from {where}{net}. A local bank or shop won't contact "
                            "you from abroad.", 0.15)]
        return [Finding("Number check", "phone", phone, "info", f"{where} {kind} number",
                        f"Real {kind} number{net}. This only confirms the number exists, not who owns it.")]

    # ---- results -> plain-language findings -------------------------------------------------------
    def _to_findings(self, results: dict, targets: dict[str, str], report: IntelReport) -> None:
        F = report.findings
        for url, hit in (results.get("sb") or {}).items():
            if hit:
                F.append(Finding("Google Safe Browsing", "url", targets.get(url, url), "danger",
                                 "Flagged by Google Safe Browsing",
                                 f"Google lists this link as {hit.get('label', 'unsafe')}.", 0.95))
        for key, val in results.items():
            kind, _, rest = key.partition(":")
            if kind == "uh" and rest.startswith("url:") and val.get("listed"):
                t = rest[4:]
                F.append(Finding("URLhaus", "url", targets.get(t, t), "danger", "Known malware link",
                                 f"URLhaus lists this address as {val.get('threat') or 'malicious'}"
                                 f" (status: {val.get('status') or 'unknown'}).", 0.9))
            elif kind == "uh" and rest.startswith("host:") and val.get("listed"):
                host = rest[5:]
                orig = next((o for t, o in targets.items() if _host(t) == host), host)
                F.append(Finding("URLhaus", "domain", orig, "danger", "Website used for malware",
                                 f"This website has hosted {val['url_count']} malware link(s) (URLhaus).", 0.85))
            elif kind == "rdap":
                domain = rest
                orig = next((o for t, o in targets.items() if _registered(_host(t))[0] == domain), domain)
                F.extend(self._rdap_finding(domain, orig, val))
            elif kind == "ipqs":
                F.extend(self._ipqs_finding(rest, val))
            elif kind == "ts":
                F.extend(self._telesign_finding(rest, val))
        order = {"danger": 0, "warning": 1, "info": 2}
        F.sort(key=lambda f: (order[f.severity], -f.weight))

    @staticmethod
    def _rdap_finding(domain: str, orig: str, v: dict) -> list[Finding]:
        if not v.get("supported"):
            return [Finding("RDAP", "domain", orig, "info", "Domain age unknown",
                            f".{v.get('tld', '')} domains don't publish registration dates.")]
        if not v.get("found"):
            return [Finding("RDAP", "domain", orig, "warning", "Website not registered",
                            f"{domain} doesn't appear in the domain registry.", 0.3)]
        age = v.get("age_days")
        if age is None:
            return []
        if age < 7:
            return [Finding("RDAP", "domain", orig, "danger", "Brand-new website",
                            f"{domain} was registered only {age} day(s) ago.", 0.7)]
        if age < 30:
            return [Finding("RDAP", "domain", orig, "warning", "Very new website",
                            f"{domain} was registered {age} days ago.", 0.45)]
        if age < 180:
            return [Finding("RDAP", "domain", orig, "warning", "Young website",
                            f"{domain} was registered {age} days ago.", 0.2)]
        years = age // 365
        when = f"{years} year(s)" if years else f"{age} days"
        return [Finding("RDAP", "domain", orig, "info", "Established website",
                        f"{domain} has existed for {when}.")]

    @staticmethod
    def _telesign_finding(phone: str, v: dict) -> list[Finding]:
        if v.get("skipped"):
            return []
        score, level = v.get("score"), (v.get("level") or "unknown").replace("-", " ")
        rec = (v.get("recommendation") or "").lower()
        about = " · ".join(x for x in (v.get("phone_type"), v.get("carrier")) if x)
        detail = f"Risk score {score}/1000 ({level})" + (f" · {about}" if about else "") + "."
        if rec == "block":
            return [Finding("Telesign", "phone", phone, "danger", "High-risk number", detail, 0.6)]
        if rec == "flag":
            return [Finding("Telesign", "phone", phone, "warning", "Number flagged as risky", detail, 0.35)]
        return [Finding("Telesign", "phone", phone, "info", "No risk signals (Telesign)", detail)]

    @staticmethod
    def _ipqs_finding(phone: str, v: dict) -> list[Finding]:
        if v.get("skipped"):
            return []
        fs = int(v.get("fraud_score") or 0)
        extras = [x for x, on in (("recent abuse", v.get("recent_abuse")), ("VoIP", v.get("VOIP")),
                                  ("known spammer", v.get("spammer"))) if on]
        tail = f" ({', '.join(extras)})" if extras else ""
        if fs >= 85 or v.get("recent_abuse") or v.get("spammer"):
            return [Finding("IPQualityScore", "phone", phone, "danger", "Number linked to fraud",
                            f"Fraud score {fs}/100{tail}.", 0.6)]
        if v.get("VOIP"):
            return [Finding("IPQualityScore", "phone", phone, "warning", "Internet (VoIP) number",
                            f"Virtual numbers are easy for scammers to create. Fraud score {fs}/100.", 0.35)]
        if v.get("valid") is False:
            return [Finding("IPQualityScore", "phone", phone, "warning", "Number doesn't exist",
                            "This number isn't a valid, active phone line.", 0.2)]
        if fs >= 60:
            return [Finding("IPQualityScore", "phone", phone, "warning", "Risky number",
                            f"Fraud score {fs}/100{tail}.", 0.3)]
        carrier = v.get("carrier") or "unknown carrier"
        return [Finding("IPQualityScore", "phone", phone, "info", "No fraud history",
                        f"{(v.get('line_type') or 'Phone').capitalize()} line on {carrier}. Fraud score {fs}/100.")]
