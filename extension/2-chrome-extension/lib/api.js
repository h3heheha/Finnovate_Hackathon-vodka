/* FraudLens server client (service worker only).
 * - Talks ONLY to the FraudLens server the user connected, on fixed paths.
 * - The server must be HTTPS (the free cloud server) or http://127.0.0.1 / localhost (this computer).
 * - Identity = a signed install token from /extension/register, kept in chrome.storage.local.
 * - No API keys live here: every provider key stays on the server.
 * - Free cloud servers sleep when nobody uses them. A timeout or "can't reach" first WAKES the
 *   server (up to ~2 minutes, showing "waking up" in the panel) and then retries once.
 * - Errors come back as {ok:false, error} so callers can show "Couldn't verify", never "Safe".
 */
(function (root) {
  "use strict";

  const PREFIX = "/api/v1";
  const TIMEOUT_MS = 25000;       // a full analysis with live security-database checks can take a few seconds
  const WAKE_TRY_MS = 15000;      // one /health attempt while the server is starting
  const WAKE_TOTAL_MS = 120000;   // give a sleeping free server this long to start (Render: ~1 minute)
  const WAKE_RETRY_AFTER_MS = 60000; // after a failed wake, answer "couldn't verify" at once for a minute

  function isAllowedBase(url) {
    try {
      const u = new URL(url);
      if (u.username || u.password || u.search || u.hash) return false;
      if (u.pathname !== "/" && u.pathname !== "") return false;
      if (u.protocol === "https:") return true;
      return u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost");
    } catch (_) {
      return false;
    }
  }

  /** "fraudlens-x.onrender.com/" or "https://fraudlens-x.onrender.com/health" -> "https://fraudlens-x.onrender.com" */
  function normaliseInput(text) {
    let t = String(text || "").trim();
    if (!t) return null;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) {
      t = (/^(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/i.test(t) ? "http://" : "https://") + t;
    }
    try {
      const u = new URL(t);
      const base = `${u.protocol}//${u.host}`;
      return isAllowedBase(base) ? base : null;
    } catch (_) {
      return null;
    }
  }

  function cleanBase(url) {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  }

  /** The connected server, or null when the user hasn't connected one yet. */
  async function apiBase() {
    const { apiBase } = await chrome.storage.local.get("apiBase");
    return apiBase && isAllowedBase(apiBase) ? cleanBase(apiBase) : null;
  }

  async function setState(state, detail) {
    try { await chrome.storage.session.set({ serverState: { state, detail: detail || null, at: Date.now() } }); } catch (_) { /* ignore */ }
  }

  async function timedFetch(url, init, ms) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), ms);
    try {
      return await fetch(url, { ...init, signal: ctrl.signal, credentials: "omit", cache: "no-store", redirect: "error" });
    } finally {
      clearTimeout(timer);
    }
  }

  async function fetchJson(method, path, { query, body, token, timeoutMs } = {}) {
    const base = await apiBase();
    if (!base) return { status: 0, data: null, error: "not_configured" };
    const url = new URL(base + PREFIX + path);
    for (const [k, v] of Object.entries(query || {})) url.searchParams.set(k, String(v));
    try {
      const res = await timedFetch(url.toString(), {
        method,
        headers: { "Content-Type": "application/json", ...(token ? { "X-FraudLens-Install": token } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      }, timeoutMs || TIMEOUT_MS);
      let data = null;
      try { data = await res.json(); } catch (_) { /* non-JSON (e.g. the host's "starting" page) */ }
      return { status: res.status, data };
    } catch (e) {
      return { status: 0, data: null, error: e && e.name === "AbortError" ? "timeout" : "offline" };
    }
  }

  // ---- waking a sleeping free server ------------------------------------------------------------
  let _waking = null;
  let _wakeFailedAt = 0;

  /** Resolves true once /health answers (one shared attempt for everybody), false after ~2 minutes. */
  function wake({ force = false } = {}) {
    if (_waking) return _waking;
    if (!force && Date.now() - _wakeFailedAt < WAKE_RETRY_AFTER_MS) return Promise.resolve(false);
    _waking = (async () => {
      const base = await apiBase();
      if (!base) { await setState("not_configured"); return false; }
      const t0 = Date.now();
      await setState("waking");
      while (Date.now() - t0 < WAKE_TOTAL_MS) {
        try {
          const res = await timedFetch(base + "/health", {}, WAKE_TRY_MS);
          if (res.ok) {
            const data = await res.json().catch(() => null);
            if (data && data.status === "ok") { await setState("ok"); return true; }
          }
          // 502/503/504 from the host while it starts: keep waiting
          await new Promise((r) => setTimeout(r, 3000));
        } catch (_) {
          await new Promise((r) => setTimeout(r, 2000));
        }
        await setState("waking", `${Math.round((Date.now() - t0) / 1000)} s`); // also keeps the worker alive
      }
      await setState("offline");
      _wakeFailedAt = Date.now();
      return false;
    })().then((ok) => { if (ok) _wakeFailedAt = 0; return ok; }).finally(() => { _waking = null; });
    return _waking;
  }

  async function health({ allowWake = false } = {}) {
    const base = await apiBase();
    if (!base) { await setState("not_configured"); return { ok: false, error: "not_configured" }; }
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const res = await timedFetch(base + "/health", {}, 10000);
        const data = res.ok ? await res.json().catch(() => null) : null;
        if (data && data.status === "ok") { await setState("ok"); return { ok: true, data }; }
        if (![502, 503, 504].includes(res.status)) {
          await setState("offline", `http_${res.status}`);
          return { ok: false, error: `http_${res.status}` };
        }
      } catch (_) { /* unreachable or slow: maybe asleep */ }
      if (!allowWake || attempt === 1 || !(await wake({ force: true }))) break;
    }
    await setState("offline");
    return { ok: false, error: "offline" };
  }

  async function register() {
    const r = await fetchJson("POST", "/extension/register");
    if (r.status === 200 && r.data && typeof r.data.token === "string") {
      const install = { id: r.data.install_id, token: r.data.token, at: Date.now() };
      await chrome.storage.local.set({ install });
      return install;
    }
    return null;
  }

  async function token() {
    const { install } = await chrome.storage.local.get("install");
    return (install && install.token) || ((await register()) || {}).token || null;
  }

  async function once(method, path, opts) {
    let tok = await token();
    let r = await fetchJson(method, path, { ...opts, token: tok });
    if (r.status === 401 && r.data && /install_token/.test(String(r.data.detail))) {
      // The server restarted with a new secret (or the token expired): register again, once.
      await chrome.storage.local.remove("install");
      tok = ((await register()) || {}).token;
      r = await fetchJson(method, path, { ...opts, token: tok });
    }
    return r;
  }

  /** Authenticated call. A sleeping server is woken up and the call retried once
   *  (unless opts.wake === false: then it fails fast, for checks that must not keep the user waiting). */
  async function call(method, path, opts = {}) {
    const { wake: mayWake = true, ...rest } = opts;
    let r = await once(method, path, rest);
    if (mayWake && ((r.status === 0 && (r.error === "offline" || r.error === "timeout")) || [502, 503, 504].includes(r.status))) {
      if (await wake()) r = await once(method, path, rest);
    }
    if (r.status === 200) {
      if (!r.data || typeof r.data !== "object") return { ok: false, error: "bad_reply" };  // not our server
      await setState("ok");
      return { ok: true, data: r.data };
    }
    if (r.status === 429) return { ok: false, error: "rate_limited" };
    if (r.status === 401) return { ok: false, error: "not_registered" };
    if (r.status === 0) {
      if (r.error !== "not_configured") await setState("offline");
      return { ok: false, error: r.error || "offline" };
    }
    return { ok: false, error: `http_${r.status}` };
  }

  root.FLApi = Object.freeze({
    isAllowedBase, normaliseInput, cleanBase, apiBase, health, wake, register,
    analyze: (text, sender, channel) => call("POST", "/analyze", { body: { text, sender: sender || null, channel } }),
    checkUrl: (url, { wake: w = true } = {}) => call("GET", "/intel/url", { query: { url }, wake: w, timeoutMs: w ? undefined : 8000 }),
    report: (text, label, sender) => call("POST", "/report", { body: { text, label, sender: sender || null } }),
    feedback: (analysisId, verdict) => call("POST", "/feedback", { body: { analysis_id: analysisId, verdict } }),
    directory: ({ wake: w = true } = {}) => call("GET", "/directory", { wake: w, timeoutMs: w ? undefined : 10000 }),
    providers: () => call("GET", "/status/providers"),
  });
})(typeof self !== "undefined" ? self : globalThis);
