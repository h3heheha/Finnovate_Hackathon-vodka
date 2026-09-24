"""IntelService: runs every reputation check in parallel within a strict time budget.

    links ─► expand short links (shortener hops only) ─┬► Google Safe Browsing
                                                       ├► URLhaus (URL + host)
                                                       ├► VirusTotal (70+ security vendors)
                                                       ├► OpenPhish live phishing list (kept in memory)
                                                       └► RDAP domain age
    phone numbers ─► offline number check, Telesign / IPQS (only for suspicious messages, daily budget)

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

from ..core.budget import Allowance
from ..core.config import Settings
from ..knowledge import loader
from . import providers as P
from .cache import IntelCache

log = logging.getLogger("fraudlens.intel")
_extract = tldextract.TLDExtract(suffix_list_urls=())

TTL = {"sb": 6 * 3600, "uh": 12 * 3600, "rdap": 7 * 86400, "boot": 7 * 86400, "ipqs": 7 * 86400, "ts": 7 * 86400,
       "exp": 7 * 86400, "vt": 6 * 3600}
OPENPHISH_REFRESH = 6 * 3600
# Sites where one address hosts many different people's pages: an OpenPhish entry there only
# condemns that exact page, never the whole site.
SHARED_HOSTS = {
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "script.google.com",
    "storage.googleapis.com", "firebasestorage.googleapis.com", "forms.office.com", "onedrive.live.com",
    "1drv.ms", "sharepoint.com", "github.com", "gist.github.com", "raw.githubusercontent.com", "gitlab.com",
    "bitbucket.org", "dropbox.com", "dl.dropboxusercontent.com", "t.me", "telegra.ph", "linktr.ee",
    "ipfs.io", "cloudflare-ipfs.com", "s3.amazonaws.com", "notion.so", "canva.com", "www.canva.com",
    "wa.me", "api.whatsapp.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "backblazeb2.com", "amazonaws.com", "googleapis.com", "blob.core.windows.net", "windows.net",
    "digitaloceanspaces.com", "wasabisys.com", "lnk.ink", "bitly.cx", "cutt.ly", "shorturl.at", "tinyurl.com",
    "is.gd", "rebrand.ly", "t.co", "goo.gl", "ow.ly", "bit.ly",
}
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
        return any(f.severity == "danger" and f.source in ("Google Safe Browsing", "URLhaus", "OpenPhish", "VirusTotal")
                   for f in self.findings)

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
        self.sb_allowance = Allowance(settings.safe_browsing_daily_limit)
        self.vt_allowance = Allowance(settings.virustotal_daily_limit, settings.virustotal_per_minute)
        self.op_urls: set[str] = set()
        self.op_hosts: dict[str, int] = {}   # website -> number of listed phishing pages
        self.op_loaded_at: float | None = None
        self.op_error: str | None = None
        self.last: dict[str, dict] = {}   # provider -> {"status", "at"} from real checks (for the self-test)
        self._selftest_cache: tuple[float, list] | None = None
        self._selftest_lock = asyncio.Lock()

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
            "openphish": bool(s.openphish_enabled and self.op_loaded_at),
            "openphish_links": len(self.op_urls),
            "virustotal": bool(s.virustotal_key),
            "virustotal_used_today": self.vt_allowance.used_today,
        }

    # ---- OpenPhish live feed ------------------------------------------------------------------
    @staticmethod
    def _op_key(url: str) -> str:
        """Scheme-less, lower-case host + path without the trailing slash, query or fragment."""
        rest = url.split("://", 1)[-1].split("#")[0].split("?")[0]
        host, _, path = rest.partition("/")
        host = host.split("@")[-1].split(":")[0].lower()
        if host.startswith("www."):
            host = host[4:]
        return f"{host}/{path}".rstrip("/")

    async def refresh_openphish(self) -> bool:
        if not self.s.openphish_enabled:
            return False
        try:
            async with httpx.AsyncClient(timeout=20, transport=self._transport,
                                         headers={"User-Agent": "FraudLens/0.4 (scam-awareness hackathon)"}) as c:
                feed = await P.openphish_feed(c, self.s.openphish_feed_url)
        except Exception as exc:
            self.op_error = str(exc)[:120]
            log.warning("OpenPhish feed download failed: %s", exc)
            return False
        official = loader.official_domains()
        urls, hosts = set(), {}
        for u in feed:
            key = self._op_key(u)
            urls.add(key)
            host = key.split("/", 1)[0]
            reg = _registered(host)[0]
            if host and host not in SHARED_HOSTS and reg not in SHARED_HOSTS and reg not in official \
                    and host not in self.shorteners and reg not in self.shorteners:
                hosts[host] = hosts.get(host, 0) + 1
        self.op_urls, self.op_hosts = urls, hosts
        self.op_loaded_at, self.op_error = time.time(), None
        log.info("OpenPhish feed loaded: %d phishing links", len(urls))
        return True

    async def openphish_loop(self) -> None:
        """Keep the list fresh in the background (the feed itself updates every 12 hours)."""
        while True:
            ok = await self.refresh_openphish()
            await asyncio.sleep(OPENPHISH_REFRESH if ok else 600)

    def _openphish(self, targets: dict[str, str], report: "IntelReport") -> None:
        if not self.s.openphish_enabled:
            return
        if not self.op_loaded_at:
            report.providers["OpenPhish"] = "list not loaded yet"
            return
        for t, orig in targets.items():
            key = self._op_key(t)
            if key in self.op_urls:
                report.findings.append(Finding("OpenPhish", "url", orig, "danger", "On a live phishing list",
                                               "OpenPhish lists this exact link as an active phishing page.", 0.9))
            elif self.op_hosts.get(key.split("/", 1)[0], 0) >= 2:
                report.findings.append(Finding("OpenPhish", "domain", orig, "danger", "Known phishing website",
                                               "OpenPhish lists several pages on this website as active phishing.", 0.8))
            elif key.split("/", 1)[0] in self.op_hosts:
                # one listed page: the website may be shared hosting, so warn instead of condemning it
                report.findings.append(Finding("OpenPhish", "domain", orig, "warning", "Website with a phishing page",
                                               "OpenPhish lists another page on this website as active phishing.", 0.45))
        report.providers["OpenPhish"] = "ok"

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
            if every and self.s.virustotal_key:
                for t in every:
                    jobs[f"vt:{t}"] = self._virustotal(client, t)
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
        if urls:
            self._openphish(targets, report)
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
        for name, status in report.providers.items():
            self.last[name] = {"status": status, "at": time.time()}
        return out

    @staticmethod
    def _provider(key: str, label: str | None) -> str:
        if label == "expand":
            return "Short-link expansion"
        return {"sb": "Google Safe Browsing", "uh": "URLhaus", "rdap": "RDAP domain age",
                "ipqs": "IPQualityScore", "ts": "Telesign", "vt": "VirusTotal"}[key.split(":")[0]]

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
            why_not = self.sb_allowance.take()
            if why_not:
                return {u: v or {} for u, v in cached.items()}, why_not
            try:
                fresh = await P.safe_browsing(client, self.s.safe_browsing_key, todo)
            except (httpx.ConnectError, httpx.TimeoutException):
                self.sb_allowance.refund()
                raise
            for u in todo:
                cached[u] = fresh.get(u, {})
                self.cache.set(f"sb:{u}", cached[u], TTL["sb"])
        return cached, "ok" if todo else "ok (cached)"

    async def _virustotal(self, client, url):
        hit = self.cache.get(f"vt:{url}")
        if hit is not None:
            return hit, "ok (cached)"
        why_not = self.vt_allowance.take()
        if why_not:
            return {"skipped": why_not}, why_not
        try:
            value = await P.virustotal_url(client, self.s.virustotal_key, url)
        except (httpx.ConnectError, httpx.TimeoutException):
            self.vt_allowance.refund()
            raise
        self.cache.set(f"vt:{url}", value, TTL["vt"])
        return value, "ok"

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
            elif kind == "vt":
                F.extend(self._vt_finding(targets.get(rest, rest), val))
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
    def _vt_finding(url: str, v: dict) -> list[Finding]:
        if v.get("skipped"):
            return []
        if not v.get("known"):
            return [Finding("VirusTotal", "url", url, "info", "Not scanned before",
                            "VirusTotal has no scan of this exact link yet.")]
        bad, sus = v.get("malicious", 0), v.get("suspicious", 0)
        total = bad + sus + v.get("harmless", 0) + v.get("undetected", 0)
        if bad >= 2:
            return [Finding("VirusTotal", "url", url, "danger", f"Flagged by {bad} security vendors",
                            f"{bad} of {total} security vendors on VirusTotal mark this link as malicious.", 0.85)]
        if bad == 1 or sus >= 2:
            return [Finding("VirusTotal", "url", url, "warning", "Flagged by a security vendor",
                            f"{bad} malicious and {sus} suspicious verdicts out of {total} on VirusTotal.", 0.35)]
        return [Finding("VirusTotal", "url", url, "info", "No vendor flags it",
                        f"None of {total} security vendors on VirusTotal flag this link (not a guarantee).")]

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


# ---- self-test: which services really work with the keys on this server? -------------------------
SB_TEST_URL = "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/SOCIAL_ENGINEERING/URL/"
SIGNUP = {
    "safe_browsing": "https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com",
    "urlhaus": "https://auth.abuse.ch/",
    "virustotal": "https://www.virustotal.com/gui/join-us",
    "telesign": "https://portal.telesign.com/signup",
    "ipqs": "https://www.ipqualityscore.com/create-account",
}


def _entry(id_: str, name: str, state: str, detail: str, env: str | None = None) -> dict:
    return {"id": id_, "name": name, "state": state, "detail": detail, "env": env, "signup": SIGNUP.get(id_)}


async def _selftest(svc: IntelService) -> list[dict]:
    s = svc.s
    out: list[dict] = []
    timeout = httpx.Timeout(8.0)

    async def one(fn):
        try:
            return await fn()
        except Exception as exc:  # report, never raise
            return exc

    async with httpx.AsyncClient(timeout=timeout, transport=svc._transport,
                                 headers={"User-Agent": "FraudLens/0.4 (self-test)"}) as client:
        async def sb():
            why_not = svc.sb_allowance.take()
            if why_not:
                raise P.ProviderError(f"not tested: {why_not}")
            return await P.safe_browsing(client, s.safe_browsing_key, [SB_TEST_URL])

        async def uh():
            return await P.urlhaus_host(client, s.urlhaus_key, "example.com")

        async def vt():
            why_not = svc.vt_allowance.take()
            if why_not:
                raise P.ProviderError(f"not tested: {why_not}")
            return await P.virustotal_url(client, s.virustotal_key, "https://www.google.com/")

        async def rdap():
            return await P.rdap_domain(client, P.RDAP_BUILTIN["com"], "google.com")

        jobs = {}
        if s.safe_browsing_key:
            jobs["sb"] = one(sb)
        if s.urlhaus_key:
            jobs["uh"] = one(uh)
        if s.virustotal_key:
            jobs["vt"] = one(vt)
        if s.rdap_enabled:
            jobs["rdap"] = one(rdap)
        if s.openphish_enabled and not svc.op_loaded_at:
            jobs["op"] = one(svc.refresh_openphish)
        names = list(jobs)
        values = dict(zip(names, await asyncio.gather(*jobs.values())))

    def err(v) -> str:
        return f"{type(v).__name__}: {v}"[:160] if str(v) else type(v).__name__

    if not s.intel_enabled:
        return [_entry("intel", "Threat intelligence", "off", "FRAUDLENS_INTEL_ENABLED=false on the server")]

    v = values.get("sb")
    if not s.safe_browsing_key:
        out.append(_entry("safe_browsing", "Google Safe Browsing", "not_set", "No key", "FRAUDLENS_SAFE_BROWSING_KEY"))
    elif isinstance(v, Exception):
        out.append(_entry("safe_browsing", "Google Safe Browsing", "error", err(v), "FRAUDLENS_SAFE_BROWSING_KEY"))
    else:
        ok = SB_TEST_URL in v
        out.append(_entry("safe_browsing", "Google Safe Browsing", "working" if ok else "error",
                          "Google's test phishing link was flagged" if ok else "Answered, but didn't flag Google's test link",
                          "FRAUDLENS_SAFE_BROWSING_KEY"))

    v = values.get("uh")
    if not s.urlhaus_key:
        out.append(_entry("urlhaus", "URLhaus (abuse.ch)", "not_set", "No key", "FRAUDLENS_URLHAUS_KEY"))
    elif isinstance(v, Exception):
        out.append(_entry("urlhaus", "URLhaus (abuse.ch)", "error", err(v), "FRAUDLENS_URLHAUS_KEY"))
    else:
        out.append(_entry("urlhaus", "URLhaus (abuse.ch)", "working", "Key accepted", "FRAUDLENS_URLHAUS_KEY"))

    if not s.openphish_enabled:
        out.append(_entry("openphish", "OpenPhish live phishing list", "off", "Switched off"))
    elif svc.op_loaded_at:
        mins = int((time.time() - svc.op_loaded_at) // 60)
        out.append(_entry("openphish", "OpenPhish live phishing list", "working",
                          f"{len(svc.op_urls)} phishing links, downloaded {mins} min ago (no key needed)"))
    else:
        out.append(_entry("openphish", "OpenPhish live phishing list", "error", svc.op_error or "not downloaded yet"))

    v = values.get("vt")
    if not s.virustotal_key:
        out.append(_entry("virustotal", "VirusTotal", "not_set", "No key (optional, free)", "FRAUDLENS_VIRUSTOTAL_KEY"))
    elif isinstance(v, Exception):
        out.append(_entry("virustotal", "VirusTotal", "error", err(v), "FRAUDLENS_VIRUSTOTAL_KEY"))
    else:
        out.append(_entry("virustotal", "VirusTotal", "working",
                          f"Key accepted · {svc.vt_allowance.used_today}/{s.virustotal_daily_limit} lookups used today",
                          "FRAUDLENS_VIRUSTOTAL_KEY"))

    v = values.get("rdap")
    if not s.rdap_enabled:
        out.append(_entry("rdap", "Domain age (RDAP)", "off", "Switched off"))
    elif isinstance(v, Exception):
        out.append(_entry("rdap", "Domain age (RDAP)", "error", err(v)))
    else:
        out.append(_entry("rdap", "Domain age (RDAP)", "working", "google.com looked up (no key needed)"))

    if s.number_check:
        try:
            f = P.number_facts("+230 5733 1928")
            out.append(_entry("number_check", "Phone number check (offline)", "working",
                              f"+230 5733 1928 is a {f['type']} number" + (f" on {f['carrier']}" if f.get("carrier") else "")))
        except Exception as exc:
            out.append(_entry("number_check", "Phone number check (offline)", "error", err(exc)))

    for id_, name, env, configured, used, limit in (
            ("telesign", "Telesign (phone risk, trial)", "FRAUDLENS_TELESIGN_API_KEY",
             bool(s.telesign_customer_id and s.telesign_api_key), svc.cache.used_today("telesign"), s.telesign_daily_limit),
            ("ipqs", "IPQualityScore (phone risk)", "FRAUDLENS_IPQS_KEY", bool(s.ipqs_key),
             svc.cache.used_today("ipqs"), s.ipqs_daily_limit)):
        label = "Telesign" if id_ == "telesign" else "IPQualityScore"
        if not configured:
            out.append(_entry(id_, name, "not_set", "No key (optional)", env))
            continue
        last = svc.last.get(label)
        if last and str(last["status"]).startswith("ok"):
            out.append(_entry(id_, name, "working", f"Last real check worked · {used}/{limit} used today", env))
        elif last:
            out.append(_entry(id_, name, "error", f"Last real check: {last['status']}", env))
        else:
            out.append(_entry(id_, name, "untested",
                              "Key set. Not tested here because every test uses a paid credit; "
                              "it runs on the first suspicious message with a phone number.", env))
    return out


async def selftest(svc: IntelService, max_age: float = 1800) -> list[dict]:
    """Cached for 30 minutes for everybody (a new deploy / key change restarts the server and clears it),
    and never run twice at once, so repeated clicks can't burn the free quotas."""
    async with svc._selftest_lock:
        now = time.time()
        if svc._selftest_cache and now - svc._selftest_cache[0] < max_age:
            return svc._selftest_cache[1]
        result = await _selftest(svc)
        svc._selftest_cache = (now, result)
        return result
