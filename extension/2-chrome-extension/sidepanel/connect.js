/* Shared by the side panel and the welcome page: connect to a FraudLens server, show which
 * services work. The service worker does all network calls; this page only asks Chrome for
 * permission (that needs the user's click) and renders text (never HTML).
 */
"use strict";

const FLConnect = (() => {
  const send = (msg) => chrome.runtime.sendMessage(msg).catch(() => null);

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

  /** Call straight from a click handler: Chrome only shows the permission prompt during a click. */
  function connect(inputText, onProgress) {
    const base = FLApi.normaliseInput(inputText);
    if (!base) {
      return Promise.resolve({ ok: false, message: "That isn't a server address. Paste the https://… address of your FraudLens server." });
    }
    const permission = base.startsWith("https://")
      ? chrome.permissions.request({ origins: [`${base}/*`] })   // first call, still inside the click
      : Promise.resolve(true);                                   // this computer: already allowed
    return permission.then(async (allowed) => {
      if (!allowed) return { ok: false, message: "Chrome wasn't allowed to talk to that server. Click Connect again and choose Allow." };
      const saved = await send({ type: "SAVE_SETTINGS", apiBase: base });
      if (!saved || !saved.ok) return { ok: false, message: (saved && saved.error) || "Couldn't save the address." };
      if (onProgress) onProgress("Connecting… A free server that was asleep takes up to a minute to wake up.");
      const t = await send({ type: "TEST_CONNECTION", wake: true });
      if (!t || !t.ok) {
        return { ok: false, base, message: t && /^http_/.test(t.error || "")
          ? `The address answered with an error (${t.error.replace("http_", "HTTP ")}). Is it the FraudLens server's address?`
          : "Can't reach the server. Check the address, and on Render check that the service is \"Live\"." };
      }
      return { ok: true, base, data: t.data, registered: t.registered,
        message: `Connected to ${new URL(base).host}` + (t.registered ? "" : " (but it refused to register this browser)") };
    }, () => ({ ok: false, message: "Chrome refused the permission request." }));
  }

  const ICON = { working: "✓", error: "✗", not_set: "–", off: "–", untested: "?" };

  function renderServices(box, r) {
    if (!r || !r.ok) {
      box.replaceChildren(el("div", { class: "out bad" }, r && r.error === "rate_limited"
        ? "Checked too often. Wait a few minutes."
        : "Couldn't ask the server. Connect first, then try again."));
      return;
    }
    const rows = (r.data.providers || []).map((p) => {
      const tips = [];
      if (p.state !== "working" && p.env) tips.push(`Render → your service → Environment → ${p.env}`);
      const link = typeof p.signup === "string" && /^https:\/\/[^\s]+$/.test(p.signup) && p.state !== "working"
        ? el("a", { href: p.signup, target: "_blank", rel: "noopener noreferrer" },
          ["telesign", "ipqs"].includes(p.id) ? "sign up" : "get a free key") : null;
      return el("div", { class: `svc ${String(p.state).replace(/[^a-z_]/g, "")}` },
        el("span", { class: "i" }, ICON[p.state] || "?"),
        el("b", {}, p.name),
        el("div", { class: "d" }, p.detail || "", tips.length ? ` · ${tips.join(" · ")}` : "", link ? " · " : "", link));
    });
    box.replaceChildren(...rows, el("div", { class: "hint" }, "✓ works · ✗ key rejected or failing · – not set up (optional)"));
  }

  return { send, el, connect, renderServices };
})();
