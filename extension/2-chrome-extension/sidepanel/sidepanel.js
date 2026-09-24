/* FraudLens side panel: the TRUE verdict (web pages can't draw here).
 * Everything is rendered with textContent: nothing from a message or the server is treated as HTML.
 */
"use strict";

const $ = (id) => document.getElementById(id);
let tabId = null;
let state = null;
let focusId = null;

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of children) if (c !== null && c !== undefined && c !== false) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
}

const send = (msg) => chrome.runtime.sendMessage(msg).catch(() => null);
const safeClass = (s) => String(s || "").replace(/[^a-z_]/gi, "");
const LEVEL_TEXT = { high: "Likely scam", medium: "Be careful", low: "No warning signs found", error: "Couldn't verify", tamper: "Page tampering" };
const ERROR_TEXT = {
  offline: "The FraudLens server can't be reached (a free server may still be waking up: wait a minute, then try again).",
  timeout: "The FraudLens server took too long to answer (a free server may still be waking up).",
  not_configured: "FraudLens isn't connected to its server yet: paste your server's address at the top of this panel.",
  rate_limited: "Too many checks in a short time. Wait a minute and try again.",
  not_a_web_link: "That isn't a web link.",
  not_registered: "The server didn't accept this browser's FraudLens ID. Open Settings and click Test connection to register again.",
  http_403: "The server refused the request (wrong address or origin).",
  http_409: "Security-database checks are switched off on the server.",
};

// ---- rendering -----------------------------------------------------------------------------------
function header(level, title, score) {
  return el("div", { class: "top" },
    el("span", { class: "pill" }, LEVEL_TEXT[level] || level),
    score !== undefined ? el("span", { class: "score" }, String(score), el("small", {}, "/100")) : null,
  );
}

function xray(data) {
  const labels = Object.fromEntries((data.tactics || []).map((t) => [t.tactic, t.label]));
  const box = el("div", { class: "xray" });
  for (const seg of data.segments || []) {
    if (seg.tactic) box.append(el("mark", { class: `t-${safeClass(seg.tactic)}`, title: labels[seg.tactic] || seg.tactic }, seg.text));
    else box.append(document.createTextNode(seg.text));
  }
  return box;
}

function breakdown(data) {
  const items = data.score_breakdown || [];
  if (!items.length) return null;
  const total = Math.max(1, ...items.map((b) => b.points));
  return el("div", {}, el("div", { class: "sec" }, "How the score was built"),
    ...items.map((b) => el("div", { class: "bar" },
      el("span", {}, b.label, b.detail ? el("span", { class: "hint" }, " · " + b.detail) : null),
      el("span", { class: "pts" }, `+${b.points}`),
      el("div", { class: "track" }, el("div", { class: "fill", style: `width:${Math.round((b.points / total) * 100)}%` })))));
}

function findings(list, expanded) {
  const rows = (list || []).map((f) => el("div", { class: `finding ${safeClass(f.severity)}` },
    el("b", {}, f.title), el("div", { class: "hint" }, `${f.detail}${f.source ? " (" + f.source + ")" : ""}`)));
  for (const [from, to] of Object.entries(expanded || {})) rows.push(el("div", { class: "finding warning" },
    el("b", {}, "Short link unmasked"), el("div", { class: "hint" }, `${from} → ${to}`)));
  return rows.length ? el("div", {}, el("div", { class: "sec" }, "Security databases"), ...rows) : null;
}

// One answer per checked message: "Is this a scam?" Yes / No. Both buttons lock after the first
// click, so nobody can send the server two opposite answers for the same message. The answer is sent
// as a report (teaches the scam memory) and, when the verdict came from the live server, as feedback
// on that verdict (right / wrong).
const answered = new Map(); // item id -> message shown after answering (kept while the panel is open)

function reportButtons(item) {
  const out = el("div", { class: "msg" });
  const flagged = item.level === "high" || item.level === "medium";
  const id = item.id || (item.data && item.data.analysis_id);
  const choices = flagged
    ? [["Yes, it's a scam", "scam", true], ["No, it's genuine", "legit", false]]
    : [["Correct, it's genuine", "legit", true], ["No, it's a scam", "scam", false]];

  const buttons = choices.map(([label, answer, agrees]) => el("button", {
    class: agrees ? "primary" : "",
    onclick: async () => {
      buttons.forEach((b) => { b.disabled = true; });
      out.textContent = "Sending…";
      const r = await send({ type: "REPORT", text: item.text, label: answer, sender: item.sender || null });
      if (item.data && item.data.analysis_id && !item.offline) {
        await send({ type: "FEEDBACK", analysisId: item.data.analysis_id, verdict: answer });
      }
      const msg = r && r.message ? r.message : "Couldn't reach the FraudLens server. Try again later.";
      out.textContent = agrees ? msg : `${msg} Thanks for correcting FraudLens.`;
      if (r && r.message) answered.set(id, out.textContent);
      else buttons.forEach((b) => { b.disabled = false; }); // failed: allow a retry
    },
  }, label));

  if (answered.has(id)) {
    buttons.forEach((b) => { b.disabled = true; });
    out.textContent = answered.get(id);
  }
  return el("div", {}, el("div", { class: "sec" }, "Help FraudLens learn: is this message a scam?"),
    el("div", { class: "actions" }, ...buttons), out);
}

function renderMessage(item) {
  const d = item.data;
  const card = el("div", { class: `card verdict lvl-${safeClass(d.risk_level)}` },
    header(d.risk_level, d.verdict, d.risk_score),
    el("div", { class: "title" }, d.verdict),
    el("div", {}, d.summary),
    item.offline ? el("div", { class: "warn-note" }, "Offline copy of a demo result (the server couldn't be reached).") : null,
    el("div", { class: "sec" }, "Scam X-Ray"), xray(d),
    breakdown(d),
    (d.tactics || []).length ? el("div", {}, el("div", { class: "sec" }, "Warning signs"),
      ...d.tactics.map((t) => el("div", { class: "tactic" }, el("b", {}, `${t.label} (+${t.contribution})`),
        el("div", { class: "hint" }, t.description)))) : null,
    findings(d.intel && d.intel.findings, d.intel && d.intel.expanded_links),
    (d.advice || []).length ? el("div", {}, el("div", { class: "sec" }, "What to do"),
      el("ul", { class: "advice" }, ...d.advice.map((a) => el("li", {}, el("b", {}, a.title), " ", a.detail)))) : null,
    d.risk_level === "low" ? el("div", { class: "warn-note" }, "No warning signs isn't a guarantee. If in doubt, call the sender on a number you already have.") : null,
    reportButtons(item));
  return card;
}

function renderLink(item) {
  const d = item.data || {};
  const lvl = item.level;
  const reasons = [...((item.lookalike && item.lookalike.reasons) || [])];
  return el("div", { class: `card verdict lvl-${safeClass(lvl)}` },
    header(lvl),
    el("div", { class: "title" }, lvl === "error" ? "FraudLens couldn't check this link" : "Link check"),
    el("div", { class: "xray" }, item.url),
    item.practice ? el("div", { class: "warn-note" }, "Practice link: it really opens a FraudLens practice page that pretends to be at this address.") : null,
    reasons.length ? el("ul", {}, ...reasons.map((r) => el("li", {}, r))) : null,
    item.error ? el("div", { class: "warn-note" }, `${ERROR_TEXT[item.error] || "The check failed."} This does NOT mean the link is safe.`) : null,
    findings(d.findings, d.expanded_links),
    lvl === "low" ? el("div", { class: "warn-note" }, "No warning signs isn't a guarantee: type your bank's address yourself instead of using links.") : null);
}

/** The ONLY place where a paused page can be continued: the page itself can't draw over this panel. */
function releaseBox() {
  const p = state && state.paused;
  if (!p || tabId === null) return null;
  const out = el("div", { class: "msg" });
  const btn = el("button", { disabled: "", onclick: async () => {
    btn.disabled = true;
    const r = await send({ type: "RELEASE_PAUSE", tabId });
    out.textContent = r && r.ok ? "OK. FraudLens won't pause this page again for 10 minutes."
      : "Not yet: wait for the countdown to finish.";
    if (!(r && r.ok)) btn.disabled = false;
  } }, "I checked with my bank: continue on this page");
  const wait = p.since + p.cooldown * 1000 - Date.now();
  if (wait <= 0) btn.removeAttribute("disabled");
  else setTimeout(() => btn.removeAttribute("disabled"), wait + 200);
  return el("div", { class: "release" }, el("div", { class: "sec" }, "This page is paused"),
    el("div", { class: "hint" }, "FraudLens stopped you before you typed into this page. Only continue if you have checked with your bank on a number you already trust."),
    btn, out);
}

function renderPage(item) {
  return el("div", { class: `card verdict lvl-${safeClass(item.level)}` },
    header(item.level),
    el("div", { class: "title" }, item.level === "high" ? "This page may be a scam" : "Check this website carefully"),
    el("div", { class: "xray" }, item.host),
    item.practice ? el("div", { class: "warn-note" }, "Practice page: this FraudLens page pretends to be at the address above.") : null,
    el("ul", {}, ...(item.reasons || []).map((r) => el("li", {}, r))),
    releaseBox() || el("div", { class: "warn-note" }, "Pause-Before-Pay is on for this page: FraudLens will stop you before you type card details, passwords or codes."));
}

function renderItem(item) {
  if (item.kind === "message") return renderMessage(item);
  if (item.kind === "link") return renderLink(item);
  if (item.kind === "page") return renderPage(item);
  if (item.kind === "tamper") return el("div", { class: "card verdict lvl-tamper" }, header("tamper"),
    el("div", { class: "title" }, "This page tried to hide a FraudLens warning"),
    el("div", {}, "Treat it as a scam. FraudLens never shows a green \"safe\" box inside a website, so one you see there is fake."),
    releaseBox());
  if (item.kind === "notice") return el("div", { class: "card" }, item.text);
  return el("div", { class: "card verdict lvl-error" }, header("error"),
    el("div", { class: "title" }, "FraudLens couldn't verify this"),
    el("div", {}, ERROR_TEXT[item.error] || "Something went wrong."),
    el("div", { class: "warn-note" }, "This does NOT mean it is safe. Don't click links or pay until you've checked another way."));
}

function render() {
  const box = $("result");
  const nav = $("history");
  const items = (state && state.items) || [];
  if (!items.length) {
    nav.hidden = true;
    box.replaceChildren(el("div", { class: "empty" },
      el("p", {}, el("strong", {}, "Nothing checked on this page yet.")),
      el("p", {}, "Select text and right-click \"Check with FraudLens\", right-click a link, or paste a message below."),
      el("p", {}, "Try it on the practice pages: Settings & privacy → Practice pages.")));
    return;
  }
  const current = items.find((i) => i.id === focusId) || items.find((i) => i.id === state.focus) || items[0];
  box.replaceChildren(renderItem(current));
  nav.hidden = items.length < 2;
  nav.replaceChildren(...items.map((i, n) => el("button", {
    "aria-current": String(i.id === current.id),
    onclick: () => { focusId = i.id; render(); },
  }, `${n + 1}. ${LEVEL_TEXT[i.level] || i.level}`)));
}

async function loadTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  tabId = tab && Number.isInteger(tab.id) ? tab.id : null;
  focusId = null;
  state = tabId === null ? null : (await chrome.storage.session.get(`tab:${tabId}`))[`tab:${tabId}`] || null;
  render();
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && tabId !== null && changes[`tab:${tabId}`]) {
    const before = state && state.focus;
    state = changes[`tab:${tabId}`].newValue || null;
    focusId = null;
    render();
    if (state && state.focus !== before) window.scrollTo({ top: 0, behavior: "smooth" }); // "See why": jump to it
  }
});
chrome.tabs.onActivated.addListener(loadTab);

// ---- manual check ----------------------------------------------------------------------------------
$("checkBtn").addEventListener("click", async () => {
  const text = $("paste").value.trim().slice(0, 5000);
  if (!text || tabId === null) return;
  $("checkBtn").disabled = true;
  $("checkBtn").textContent = "Checking…";
  await send({ type: "PANEL_CHECK_TEXT", text, tabId });
  $("checkBtn").disabled = false;
  $("checkBtn").textContent = "Check";
});

// ---- connection status + settings -------------------------------------------------------------------
let apiBase = null;
const STATE_TEXT = { ok: "Connected", waking: "Waking up…", offline: "Can't reach server", not_configured: "Not connected" };

function showState(state) {
  const st = state && state.state ? state.state : (apiBase ? "ok" : "not_configured");
  $("conn").className = `conn ${st === "ok" ? "ok" : st === "waking" ? "waking" : ""}`;
  $("connText").textContent = STATE_TEXT[st] || "";
  $("conn").title = st === "waking" ? "The free server is starting (up to a minute)" : STATE_TEXT[st] || "";
  $("connectCard").hidden = !!apiBase && st !== "not_configured";
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes.serverState) showState(changes.serverState.newValue);
});

async function loadSettings() {
  const s = await send({ type: "GET_SETTINGS" });
  if (!s) return;
  apiBase = s.apiBase;
  $("apiBase").value = s.apiBase || "";
  $("keepAwake").checked = s.keepAwake;
  $("practiceBtn").disabled = !s.apiBase;
  $("install").textContent = s.installId ? `Install ID: ${s.installId.slice(0, 6)}… (signed by the server)` : "Not registered yet.";
  showState(s.serverState);
  const sites = $("sites");
  sites.replaceChildren(...Object.entries(s.sites).map(([key, site]) => {
    const box = el("input", { type: "checkbox", id: `site-${key}` });
    box.checked = !!s.granted[key];
    box.addEventListener("change", async () => {
      const perm = { origins: site.origins };
      const ok = box.checked ? await chrome.permissions.request(perm) : await chrome.permissions.remove(perm);
      if (!ok) box.checked = !box.checked;
      await send({ type: "SAVE_SETTINGS" });
    });
    return el("label", { class: "site", for: `site-${key}` }, box, el("span", {}, site.label));
  }));
}

function connectFrom(input, out, button) {
  button.disabled = true;
  out.className = "out";
  out.textContent = "Asking Chrome for permission…";
  FLConnect.connect(input.value, (msg) => { out.textContent = msg; }).then(async (r) => {
    button.disabled = false;
    out.className = `out ${r.ok ? "good" : "bad"}`;
    out.textContent = r.ok ? `✓ ${r.message}` : r.message;
    await loadSettings();
    if (r.ok) {
      showTest(r);
      FLConnect.renderServices($("services"), await send({ type: "CHECK_SERVICES" }));
    }
  });
}

$("connectBtn").addEventListener("click", () => connectFrom($("connectInput"), $("connectOut"), $("connectBtn")));
$("saveApi").addEventListener("click", () => connectFrom($("apiBase"), $("testOut"), $("saveApi")));

function showTest(r) {
  const ok = r && r.ok;
  if (ok) {
    const i = r.data.intel || {};
    const on = i.enabled ? [["Safe Browsing", i.safe_browsing], ["URLhaus", i.urlhaus], ["OpenPhish", i.openphish],
      ["VirusTotal", i.virustotal], ["Telesign", i.telesign], ["IPQS", i.ipqs], ["domain age", i.rdap],
      ["short links", i.short_link_expansion]].filter(([, v]) => v).map(([n]) => n) : [];
    $("testOut").className = "out good";
    $("testOut").textContent = `✓ Connected (v${r.data.version}) · AI: ${r.data.ai_provider} · security databases: ${on.join(", ") || "off"}${r.registered ? " · registered" : ""}`;
  } else {
    $("testOut").className = "out bad";
    $("testOut").textContent = r && r.error === "not_configured"
      ? "Not connected yet: paste your server's address above and click Connect."
      : "Can't reach the FraudLens server. If it's a free Render server that was asleep, wait a minute and click Test connection again.";
  }
}

$("testBtn").addEventListener("click", async () => {
  $("testBtn").disabled = true;
  $("testOut").className = "out";
  $("testOut").textContent = "Testing… (waking the server up if it was asleep, up to a minute)";
  showTest(await send({ type: "TEST_CONNECTION", wake: true }));
  $("testBtn").disabled = false;
  loadSettings();
});

$("servicesBtn").addEventListener("click", async () => {
  $("servicesBtn").disabled = true;
  $("services").replaceChildren(el("div", { class: "hint" }, "Testing every service on the server…"));
  FLConnect.renderServices($("services"), await send({ type: "CHECK_SERVICES" }));
  $("servicesBtn").disabled = false;
});

$("keepAwake").addEventListener("change", () => send({ type: "SAVE_SETTINGS", keepAwake: $("keepAwake").checked }));

$("practiceBtn").addEventListener("click", () => {
  if (apiBase) chrome.tabs.create({ url: `${apiBase}/demo/` });
});

loadTab();
loadSettings().then(async () => {
  if (apiBase) {
    const r = await send({ type: "TEST_CONNECTION", wake: true });
    if (r && r.ok) showTest(r);
  }
});
