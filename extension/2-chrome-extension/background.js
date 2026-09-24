/* FraudLens Guard: service worker.
 *
 * The ONLY part of the extension that talks to the FraudLens server. It:
 *  - validates every message (type, shape, who sent it) and drops anything else;
 *  - runs the local prefilter / look-alike check again (content scripts are never trusted);
 *  - never fetches a URL a page gives it: all requests go to the FraudLens server's fixed paths;
 *  - keeps per-tab verdicts in chrome.storage.session (memory only, gone when Chrome closes);
 *  - shows the true verdict in the toolbar badge and side panel, which web pages can't fake;
 *  - fails safe: an error is "Couldn't verify", never "Safe".
 */
importScripts("lib/prefilter.js", "lib/lookalike.js", "lib/validate.js", "lib/api.js");

const EXT_ID = chrome.runtime.id;
const PANEL_PREFIX = chrome.runtime.getURL("sidepanel/");
const TAINT_MINUTES = 30;
const SEEN_MINUTES = 10;
const MAX_ITEMS_PER_TAB = 10;
const KEEPALIVE_MINUTES = 10;   // free cloud servers sleep after ~15 minutes without visitors

// Sites the user can switch on (optional permissions). The practice pages on the connected
// FraudLens server (<server>/demo/) are always checked: they come with the server permission.
const SITES = {
  gmail: { label: "Gmail", origins: ["https://mail.google.com/*"], scanner: true },
  outlook: { label: "Outlook", origins: ["https://outlook.live.com/*", "https://outlook.office.com/*"], scanner: true },
  whatsapp: { label: "WhatsApp Web", origins: ["https://web.whatsapp.com/*"], scanner: true },
  everywhere: { label: "Protect every site (look-alike warnings + Pause-Before-Pay)", origins: ["<all_urls>"], guard: true },
  local: { label: "Test pages on this computer (localhost)", origins: ["http://localhost/*", "http://*.localhost/*"], scanner: true, guard: true },
};

// ---- small helpers ---------------------------------------------------------------------------
const now = () => Date.now();
const LEVEL_RANK = { error: 1, low: 0, medium: 2, high: 3, tamper: 3 };

function hostOf(url) {
  try {
    const u = new URL(url);
    return /^https?:$/.test(u.protocol) ? u.hostname.toLowerCase().replace(/^www\./, "") : null;
  } catch (_) {
    return null;
  }
}

// Every read-modify-write of session state runs one at a time (several messages are often
// scanned at once; without this queue, results would overwrite each other).
let _queue = Promise.resolve();
function serial(fn) {
  const run = _queue.then(fn, fn);
  _queue = run.catch(() => {});
  return run;
}

async function sessionGet(key, fallback) {
  const v = (await chrome.storage.session.get(key))[key];
  return v === undefined ? fallback : v;
}

let _dirRefresh = null;
function refreshDirectory() {
  if (_dirRefresh) return _dirRefresh;
  _dirRefresh = (async () => {
    const r = await FLApi.directory({ wake: false });
    if (r.ok && r.data && Array.isArray(r.data.organisations)) {
      await chrome.storage.local.set({ directory: r.data, directoryAt: now() });
    }
  })().catch(() => {}).finally(() => { _dirRefresh = null; });
  return _dirRefresh;
}

/** The verified directory. Never waits for the server (it may be asleep): the saved copy or the one
 *  shipped with the extension is used at once, and a fresh copy is fetched in the background. */
async function serverDirectory() {
  const { directory: cached, directoryAt } = await chrome.storage.local.get(["directory", "directoryAt"]);
  if (!(cached && directoryAt && now() - directoryAt < 24 * 3600e3)) refreshDirectory();
  if (cached) return cached;
  const res = await fetch(chrome.runtime.getURL("data/directory.json"));
  return res.json();
}

let _brands = null;
/** Verified directory (banks, post, MRA… from the server) + the global brands scammers imitate most. */
async function directory() {
  const dir = await serverDirectory();
  if (!_brands) {
    try { _brands = (await (await fetch(chrome.runtime.getURL("data/brands.json"))).json()).organisations || []; } catch (_) { _brands = []; }
  }
  const ids = new Set((dir.organisations || []).map((o) => o.id));
  return { ...dir, organisations: [...(dir.organisations || []), ..._brands.filter((b) => !ids.has(b.id))] };
}

/** What is sent to the security databases: the address without ?query or #fragment (they can hold tokens). */
function shareableUrl(url) {
  try { const u = new URL(url); return `${u.origin}${u.pathname}`.slice(0, 2000); } catch (_) { return null; }
}

/** Practice pages on the connected server may pretend to live at a scam address:
 *  <server>/demo/login.html#as=mcb-secure-verify.com is checked as if it were http://mcb-secure-verify.com/login.html.
 *  Honoured ONLY on the connected server's own /demo/ pages, and it can only ADD warnings, never remove one. */
async function practiceTarget(url) {
  let u;
  try { u = new URL(url); } catch (_) { return { url, own: false, simulated: null }; }
  const base = await FLApi.apiBase();
  const own = !!base && u.origin === base;
  if (!own) return { url, own: false, simulated: null };
  const m = /^#as=([a-z0-9][a-z0-9.-]{1,78}[a-z0-9])$/i.exec(u.hash);
  if (!m || !u.pathname.startsWith("/demo/") || !m[1].includes(".") || m[1].includes("..")) {
    return { url, own: true, simulated: null };
  }
  const host = m[1].toLowerCase();
  return { url: `http://${host}/${u.pathname.slice("/demo/".length)}`, own: true, simulated: host };
}

let _cooldown = null;
/** Pause-Before-Pay countdown (seconds). Never waits for the server: 10 until the server has told us. */
async function cooldownSeconds() {
  if (_cooldown) return _cooldown;
  FLApi.health().then((h) => {
    if (h.ok && Number.isInteger(h.data.pause_cooldown_seconds)) _cooldown = h.data.pause_cooldown_seconds;
  }).catch(() => {});
  return 10;
}

// ---- per-tab state, badge ------------------------------------------------------------------------
async function tabState(tabId) {
  return sessionGet(`tab:${tabId}`, { items: [], focus: null, tamper: false });
}

function pushItem(tabId, item) {
  return serial(() => _pushItem(tabId, item));
}

async function _pushItem(tabId, item) {
  const st = await tabState(tabId);
  item.id = item.id || `${item.kind}-${now()}-${Math.random().toString(16).slice(2, 6)}`;
  item.at = now();
  st.items = [item, ...st.items.filter((i) => i.id !== item.id)].slice(0, MAX_ITEMS_PER_TAB);
  st.focus = item.id;
  await chrome.storage.session.set({ [`tab:${tabId}`]: st });
  await updateBadge(tabId, st);
  return item;
}

async function updateBadge(tabId, st) {
  st = st || (await tabState(tabId));
  let worst = null;
  for (const i of st.items) if (!worst || (LEVEL_RANK[i.level] || 0) > (LEVEL_RANK[worst] || 0)) worst = i.level;
  if (st.tamper) worst = "tamper";
  const look = {
    high: ["!", "#C62828", "FraudLens: likely scam on this page"],
    tamper: ["!", "#C62828", "FraudLens: this page tried to hide a warning"],
    medium: ["?", "#E65100", "FraudLens: warning signs on this page"],
    error: ["?", "#616161", "FraudLens: couldn't verify (this does NOT mean safe)"],
  }[worst];
  try {
    await chrome.action.setBadgeText({ tabId, text: look ? look[0] : "" });
    if (look) await chrome.action.setBadgeBackgroundColor({ tabId, color: look[1] });
    await chrome.action.setTitle({ tabId, title: look ? look[2] : "FraudLens: open the verdict panel" });
  } catch (_) { /* tab closed */ }
}

function taint(hosts, analysisId, score) {
  return serial(() => _taint(hosts, analysisId, score));
}

async function _taint(hosts, analysisId, score) {
  const map = await sessionGet("tainted", {});
  const until = now() + TAINT_MINUTES * 60e3;
  const dir = await directory();
  for (const h of hosts) {
    if (!h) continue;
    // A scam message often links to the REAL bank too: never mark an official site.
    if (!h.startsWith("practice:") && FLLookalike.check(h, dir).official) continue;
    const prev = map[h];
    // Never replace "from a message rated 95/100" with a weaker reason: keep the strongest, extend the time.
    if (prev && prev.until > now() && (prev.score || 0) >= (score || 0)) prev.until = until;
    else map[h] = { analysisId, score, until };
  }
  for (const [h, v] of Object.entries(map)) if (v.until < now()) delete map[h];
  await chrome.storage.session.set({ tainted: map });
}

async function taintedEntry(host) {
  const map = await sessionGet("tainted", {});
  const e = map[host];
  return e && e.until > now() ? e : null;
}

// ---- dynamic content scripts (only on sites the user switched on) ----------------------------------
async function granted() {
  const out = {};
  for (const [key, site] of Object.entries(SITES)) {
    out[key] = await chrome.permissions.contains({ origins: site.origins });
  }
  return out;
}

/** Match pattern for the practice pages on the connected server (null when not connected / not allowed). */
async function practiceMatches() {
  const base = await FLApi.apiBase();
  if (!base) return [];
  const ok = await chrome.permissions.contains({ origins: [`${base}/*`] });
  return ok ? [`${base}/demo/*`] : [];
}

// Several events can ask for this at once (install, permission added, settings saved): run one at a time,
// otherwise two runs register the same script ID and Chrome refuses ("Duplicate script ID").
let _syncQueue = Promise.resolve();
function syncContentScripts() {
  const run = _syncQueue.then(_syncContentScripts, _syncContentScripts);
  _syncQueue = run.catch(() => {});
  return run;
}

async function _syncContentScripts() {
  const g = await granted();
  const practice = await practiceMatches();
  const scannerMatches = [...Object.entries(SITES).filter(([k, s]) => s.scanner && g[k]).flatMap(([, s]) => s.origins),
    ...practice];
  const guardMatches = g.everywhere ? ["<all_urls>"] : [...(g.local ? SITES.local.origins : []), ...practice];
  const existing = await chrome.scripting.getRegisteredContentScripts();
  if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: existing.map((s) => s.id) });
  const scripts = [];
  if (scannerMatches.length) {
    scripts.push({ id: "fl-scanner", matches: [...new Set(scannerMatches)], runAt: "document_idle", persistAcrossSessions: true,
      js: ["lib/prefilter.js", "content/ui.js", "content/scanner.js"] });
  }
  if (guardMatches.length) {
    scripts.push({ id: "fl-guard", matches: [...new Set(guardMatches)], runAt: "document_idle", persistAcrossSessions: true,
      js: ["content/ui.js", "content/guard.js"] });
  }
  if (scripts.length) await chrome.scripting.registerContentScripts(scripts);
  return { ...g, practice: practice.length > 0 };
}

// ---- the checks ----------------------------------------------------------------------------------
function compactMessage(data) {
  return {
    level: data.risk_level, score: data.risk_score, verdict: data.verdict, summary: data.summary,
    analysisId: data.analysis_id,
    tactics: (data.tactics || []).slice(0, 3).map((t) => t.label),
  };
}

async function offlineCopy(text) {
  try {
    const res = await fetch(chrome.runtime.getURL("data/demo_cache.json"));
    const cache = await res.json();
    const key = Object.keys(cache.analyses || {}).find((k) => FLPrefilter.normalise(k) === FLPrefilter.normalise(text));
    return key ? cache.analyses[key] : null;
  } catch (_) {
    return null;
  }
}

async function checkMessage(tabId, text, sender, channel, source) {
  text = FLPrefilter.normalise(text);
  if (source === "auto" && !FLPrefilter.check(text).send) return { level: "skip" };
  const h = FLPrefilter.hash(text + "|" + (sender || ""));
  const seen = await sessionGet("seen", {});
  const hit = source === "auto" && seen[h] && seen[h].until > now() ? seen[h] : null;
  if (hit) {
    // Only successful verdicts are remembered; show them in this tab's panel again.
    await pushItem(tabId, { kind: "message", level: hit.data.risk_level, data: hit.data, text, sender, offline: hit.offline, source });
    return { ...compactMessage(hit.data), offline: hit.offline };
  }

  let r = await FLApi.analyze(text, sender, channel);
  let offline = false;
  if (!r.ok && (r.error === "offline" || r.error === "timeout")) {
    const cached = await offlineCopy(text);
    if (cached) { r = { ok: true, data: cached }; offline = true; }
  }
  if (!r.ok) {
    // Failures are NEVER cached: the next reload asks the server again.
    await pushItem(tabId, { kind: "error", level: "error", error: r.error, text, sender });
    return { level: "error", error: r.error };
  }
  const d = r.data;
  await pushItem(tabId, { kind: "message", level: d.risk_level, data: d, text, sender, offline, source });
  if (d.risk_level === "high") {
    const hosts = [...(d.entities?.urls || []), ...Object.values(d.intel?.expanded_links || {})].map(hostOf);
    await taint(hosts, d.analysis_id, d.risk_score);
  }
  if (source === "auto" && !offline) {
    await serial(async () => {
      const seenNow = await sessionGet("seen", {});
      seenNow[h] = { until: now() + SEEN_MINUTES * 60e3, data: d, offline };
      const keys = Object.keys(seenNow);
      if (keys.length > 100) for (const k of keys.slice(0, keys.length - 100)) delete seenNow[k];
      await chrome.storage.session.set({ seen: seenNow });
    });
  }
  return { ...compactMessage(d), offline };
}

async function checkLink(tabId, url) {
  const t = await practiceTarget(url);
  const host = hostOf(t.url);
  if (!host) return { level: "error", error: "not_a_web_link" };
  const look = FLLookalike.check(t.url, await directory());
  const st = await tabState(tabId);
  const fromFlagged = st.items.some((i) => i.kind === "message" && i.level === "high");

  if (t.own) {
    // A practice link: judged on its pretend address only, no security-database lookups.
    let level = "low";
    if (t.simulated) level = look.suspicious ? (look.org ? "high" : "medium") : look.risky ? "medium" : "low";
    if (t.simulated) {
      await pushItem(tabId, { kind: "link", level, url: t.url, practice: true, lookalike: look });
      // stored apart from the real website of that name: a practice page never affects real sites
      if (level !== "low" || fromFlagged) await taint([`practice:${host}`], null, 0);
    }
    return { level, reasons: look.reasons.slice(0, 4), practice: !!t.simulated };
  }

  const r = await FLApi.checkUrl(shareableUrl(url) || url);
  if (!r.ok) {
    const item = { kind: "link", level: look.suspicious ? "medium" : "error", url, lookalike: look, error: r.error };
    await pushItem(tabId, item);
    return { level: item.level, error: r.error, reasons: look.reasons };
  }
  const d = r.data;
  let level = d.risk_level;
  if (look.suspicious && level === "low") level = "medium";
  await pushItem(tabId, { kind: "link", level, url, data: d, lookalike: look });
  if (level !== "low" || fromFlagged) {
    const expanded = Object.values(d.expanded_links || {}).map(hostOf);
    await taint([host, ...expanded], null, Math.round((d.score || 0) * 100));
  }
  const reasons = [...look.reasons, ...(d.findings || []).filter((f) => f.severity !== "info").map((f) => `${f.title}: ${f.detail}`)];
  return { level, reasons: reasons.slice(0, 4), expanded: d.expanded_links || {} };
}

const _pageChecks = new Map(); // "tabId|url" -> promise (navigation check + guard script share one check)

function checkPage(tabId, pageUrl) {
  const key = `${tabId}|${pageUrl}`;
  const hit = _pageChecks.get(key);
  if (hit && now() - hit.at < 15000) return hit.promise;
  const promise = _checkPage(tabId, pageUrl);
  _pageChecks.set(key, { at: now(), promise });
  if (_pageChecks.size > 200) _pageChecks.delete(_pageChecks.keys().next().value);
  return promise;
}

async function _checkPage(tabId, pageUrl) {
  const t = await practiceTarget(pageUrl);
  const host = hostOf(t.url);
  if (!host || (t.own && !t.simulated)) return { warn: false, pause: false };
  // Practice pages keep their own records ("practice:<name>"), so they can never change how the
  // real website of that name is treated.
  const key = t.simulated ? `practice:${host}` : host;
  const released = (await sessionGet("released", {}))[key];
  // strongest reason wins: "from a message rated 100/100" beats "from a link FraudLens warned about"
  const tainted = [await taintedEntry(key), t.simulated ? await taintedEntry(host) : null]
    .filter(Boolean).sort((a, b) => (b.score || 0) - (a.score || 0))[0] || null;
  const look = FLLookalike.check(t.url, await directory());
  if (look.official && !tainted) return { warn: false, pause: false, official: true };

  let level = "low";
  const reasons = [];
  if (tainted) {
    level = "high";
    reasons.push(tainted.score
      ? `You reached this page from a message FraudLens rated ${tainted.score}/100 (likely scam).`
      : "You reached this page from a link FraudLens warned you about.");
  }
  if (look.suspicious) {
    reasons.push(...look.reasons);
    // imitating a real bank / brand = high; phishing signals alone = "be careful"
    if (level === "low") level = look.org ? "high" : "medium";
  } else if (t.simulated && look.risky && level === "low") {
    level = "medium";
    reasons.push(...look.reasons);
  }
  // Only suspicious-looking addresses are sent to the security databases (never normal browsing).
  const askServer = !t.simulated && (look.suspicious || look.risky);

  if (level === "low") {
    if (!askServer) return { warn: false, pause: false };
    // Only the security databases could make this page a warning. Ask quickly, without waiting
    // for a sleeping server.
    const r = await FLApi.checkUrl(shareableUrl(pageUrl), { wake: false });
    if (!r.ok || r.data.risk_level === "low") return { warn: false, pause: false };
    level = r.data.risk_level === "high" ? "high" : "medium";
    reasons.push(...look.reasons, ...findingsText(r.data));
  }

  const item = await pushItem(tabId, { kind: "page", level, url: t.url, host, reasons, tainted,
    practice: !!t.simulated, releaseKey: key });
  // The local verdict is enough to warn and pause NOW; database findings are added when they arrive.
  if (askServer && !item.checked) enrichPage(tabId, item, pageUrl);
  const pause = !(released && released.until > now());
  return { warn: true, level, reasons: reasons.slice(0, 4), pause, cooldown: await cooldownSeconds(),
    practice: t.simulated || null };
}

function findingsText(d) {
  return (d.findings || []).filter((f) => f.severity !== "info").map((f) => `${f.title}: ${f.detail}`);
}

async function enrichPage(tabId, item, pageUrl) {
  const r = await FLApi.checkUrl(shareableUrl(pageUrl));
  if (!r.ok) return;
  await serial(async () => {
    const st = await tabState(tabId);
    const cur = st.items.find((i) => i.id === item.id);
    if (!cur) return;   // the tab moved on
    cur.checked = true;
    cur.reasons = [...new Set([...cur.reasons, ...findingsText(r.data)])];
    if (r.data.risk_level === "high") cur.level = "high";
    await chrome.storage.session.set({ [`tab:${tabId}`]: st });
    await updateBadge(tabId, st);
  });
}

// ---- context menus (user gestures: the side panel may open immediately) --------------------------
function createMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: "fl-check-text", title: "Check with FraudLens", contexts: ["selection"] });
    chrome.contextMenus.create({ id: "fl-check-link", title: "Check this link with FraudLens", contexts: ["link"] });
    chrome.contextMenus.create({ id: "fl-report", title: "Report as scam to FraudLens", contexts: ["selection"] });
  });
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (!tab || !Number.isInteger(tab.id) || tab.id < 0) return;
  chrome.sidePanel.open({ tabId: tab.id }).catch(() => {});
  if (info.menuItemId === "fl-check-text" && info.selectionText) {
    checkMessage(tab.id, info.selectionText.slice(0, 5000), null, "other", "manual");
  } else if (info.menuItemId === "fl-check-link" && info.linkUrl) {
    checkLink(tab.id, info.linkUrl);
  } else if (info.menuItemId === "fl-report" && info.selectionText) {
    FLApi.report(info.selectionText.slice(0, 5000), "scam", null).then((r) =>
      pushItem(tab.id, { kind: "notice", level: "low", text: r.ok ? r.data.message : "Couldn't send the report. Check the FraudLens server." }));
  }
});

// ---- messages (validated) --------------------------------------------------------------------------
const HANDLERS = {
  async SCAN_TEXT(m, s) { return checkMessage(s.tab.id, m.text, m.sender, m.channel, "auto"); },
  async CHECK_LINK(m, s) { return checkLink(s.tab.id, m.url); },
  async PAGE_CHECK(m, s) { return checkPage(s.tab.id, s.url || s.tab.url); },   // URL from Chrome, not the page
  async TAMPER(m, s) {
    await serial(async () => {
      const st = await tabState(s.tab.id);
      if (st.tamper) return;
      st.tamper = true;
      await chrome.storage.session.set({ [`tab:${s.tab.id}`]: st });
      await _pushItem(s.tab.id, { kind: "tamper", level: "high", what: m.what, url: s.url });
    });
    return { ok: true };
  },
  OPEN_PANEL(m, s) {
    // Open first, synchronously, while Chrome still counts the click as the user's action.
    const opening = chrome.sidePanel.open({ tabId: s.tab.id }).then(() => true, () => false);
    // Then point the panel at the message / page whose "See why" was clicked.
    const focusing = serial(async () => {
      const st = await tabState(s.tab.id);
      const ref = m.ref || "latest";
      const item = ref === "page" ? st.items.find((i) => i.kind === "page" || i.kind === "tamper")
        : ref === "error" ? st.items.find((i) => i.kind === "error")
          : ref === "latest" ? st.items[0]
            : st.items.find((i) => i.data && i.data.analysis_id === ref);
      if (item) {
        st.focus = item.id;
        await chrome.storage.session.set({ [`tab:${s.tab.id}`]: st });
      }
    });
    return Promise.all([opening, focusing]).then(([opened]) => ({ opened }));
  },
  async REPORT(m) {
    const r = await FLApi.report(m.text, m.label, m.sender);
    return r.ok ? { ok: true, status: r.data.status, message: r.data.message }
      : { ok: false, message: "Couldn't send the report. Check the FraudLens server." };
  },
  async PAUSE_SHOWN(m, s) {
    // The page is paused (card / password field). Only the side panel can let the user continue:
    // a scam page can draw over anything inside the page, but not over Chrome's side panel.
    const t = await practiceTarget(s.url || s.tab.url);
    const host = hostOf(t.url);
    if (!host) return { ok: false };
    const cooldown = await cooldownSeconds();
    await serial(async () => {
      const st = await tabState(s.tab.id);
      if (!st.paused) {
        st.paused = { key: t.simulated ? `practice:${host}` : host, since: now(), cooldown };
        await chrome.storage.session.set({ [`tab:${s.tab.id}`]: st });
      }
    });
    return { ok: true };
  },
  async RELEASE_PAUSE(m) {
    const released = await serial(async () => {
      const st = await tabState(m.tabId);
      const p = st.paused;
      if (!p || now() - p.since < p.cooldown * 1000) return false;   // no skipping the countdown
      const rel = await sessionGet("released", {});
      rel[p.key] = { until: now() + 10 * 60e3 };
      await chrome.storage.session.set({ released: rel });
      st.paused = null;
      await chrome.storage.session.set({ [`tab:${m.tabId}`]: st });
      return true;
    });
    if (released) await chrome.tabs.sendMessage(m.tabId, { type: "FL_RELEASE" }).catch(() => {});
    return { ok: released };
  },
  async PANEL_STATE(m) { return tabState(m.tabId); },
  async PANEL_CHECK_TEXT(m) { return checkMessage(m.tabId, m.text, null, "other", "manual"); },
  async FEEDBACK(m) { return FLApi.feedback(m.analysisId, m.verdict); },
  async GET_SETTINGS() {
    const { install, keepAwake } = await chrome.storage.local.get(["install", "keepAwake"]);
    const { serverState } = await chrome.storage.session.get("serverState");
    const base = await FLApi.apiBase();
    return { apiBase: base, granted: await granted(), practice: (await practiceMatches()).length > 0,
      installId: install ? install.id : null, keepAwake: keepAwake !== false, serverState: serverState || null,
      sites: Object.fromEntries(Object.entries(SITES).map(([k, v]) => [k, { label: v.label, origins: v.origins }])) };
  },
  async SAVE_SETTINGS(m) {
    if (m.keepAwake !== undefined) await chrome.storage.local.set({ keepAwake: m.keepAwake });
    if (m.apiBase !== undefined) {
      const base = FLApi.normaliseInput(m.apiBase);
      if (!base) return { ok: false, error: "That isn't a server address. Paste the https://… address of your FraudLens server." };
      const old = await FLApi.apiBase();
      if (base !== old) {  // new server: new identity, fresh verdicts
        await chrome.storage.local.remove(["install", "directory", "directoryAt"]);
        await chrome.storage.session.remove(["seen", "serverState"]);
        _cooldown = null;
      }
      await chrome.storage.local.set({ apiBase: base });
    }
    return { ok: true, apiBase: await FLApi.apiBase(), granted: await syncContentScripts() };
  },
  async TEST_CONNECTION(m) {
    const h = await FLApi.health({ allowWake: !!m.wake });
    if (!h.ok) return h;
    // Prove the saved ID still works (the server may have restarted); re-register if it doesn't.
    const probe = await FLApi.directory();
    let registered = probe.ok;
    if (!registered) {
      await chrome.storage.local.remove("install");
      registered = !!(await FLApi.register());
    }
    await chrome.storage.session.remove("seen");
    await syncContentScripts();
    return { ok: true, data: h.data, registered, apiBase: await FLApi.apiBase() };
  },
  async CHECK_SERVICES() {
    return FLApi.providers();
  },
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const err = FLValidate.check(msg, sender, EXT_ID, PANEL_PREFIX);
  if (err) {
    sendResponse({ ok: false, error: "rejected" });
    return false;
  }
  HANDLERS[msg.type](msg, sender).then(sendResponse, () => sendResponse({ level: "error", error: "internal" }));
  return true; // async response
});

// No web page may talk to the extension (no externally_connectable); drop anything external anyway.
chrome.runtime.onMessageExternal.addListener((_m, _s, sendResponse) => sendResponse({ ok: false }));

// ---- lifecycle -------------------------------------------------------------------------------------
function startKeepAlive() {
  chrome.alarms.create("fl-keepalive", { periodInMinutes: KEEPALIVE_MINUTES });
}

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== "fl-keepalive") return;
  const { keepAwake } = await chrome.storage.local.get("keepAwake");
  const base = await FLApi.apiBase();
  // One tiny /health visit every 10 minutes while Chrome is open keeps a free cloud server awake.
  if (keepAwake !== false && base && base.startsWith("https://")) FLApi.health().catch(() => {});
});

chrome.runtime.onInstalled.addListener(async (details) => {
  createMenus();
  await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
  await syncContentScripts();
  startKeepAlive();
  if (details.reason === "install") chrome.tabs.create({ url: chrome.runtime.getURL("sidepanel/welcome.html") });
});
chrome.runtime.onStartup.addListener(() => { syncContentScripts(); startKeepAlive(); });
chrome.permissions.onAdded.addListener(() => { syncContentScripts(); });
chrome.permissions.onRemoved.addListener(() => { syncContentScripts(); });

// A new page in a tab starts with a clean verdict.
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status === "loading") {
    await serial(() => chrome.storage.session.remove(`tab:${tabId}`));
    await updateBadge(tabId, { items: [], tamper: false });
  }
  // With "Protect every site" on, Chrome tells us the address of every page the tab opens, even one
  // that never loads (a scam site already taken down shows Chrome's own error page, where no
  // extension can draw). The verdict then goes to the toolbar badge and side panel.
  if (info.status !== "loading") return;
  const url = info.url || (tab && tab.url);
  if (url && /^https?:/i.test(url)) checkPage(tabId, url).catch(() => {});
});
chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(`tab:${tabId}`));
