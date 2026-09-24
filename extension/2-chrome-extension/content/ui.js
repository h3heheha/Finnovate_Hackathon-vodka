/* FraudLens on-page UI: warning banners, link interstitial and the Pause-Before-Pay overlay.
 *
 * Security rules:
 *  - Everything is drawn inside a CLOSED Shadow DOM: the page can't read, restyle or click into it.
 *  - Text only (textContent), never HTML: nothing from a message or a server can run as code.
 *  - A watchdog puts a warning back if the page removes or hides it, and tells the service worker
 *    (the toolbar badge then shows "!"). The on-page banner is only an alert; the badge and side
 *    panel carry the real verdict, and FraudLens NEVER shows a green "safe" banner on a page, so a
 *    green "verified by FraudLens" box on a website is fake by definition.
 */
(function () {
  "use strict";
  if (window.FLUI) return; // ui.js may be injected by two scripts on the same page

  const TAG = "data-" + Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => "abcdefghijklmnopqrstuvwxyz"[b % 26]).join("");
  const COLORS = { high: "#C62828", medium: "#E65100", error: "#546E7A" };
  const LABELS = { high: "Likely scam", medium: "Be careful", error: "Couldn't verify" };

  const CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
    .card { border-left: 6px solid var(--c); background: #fff; color: #1b1b1b; border-radius: 10px;
      box-shadow: 0 2px 10px rgba(0,0,0,.18); padding: 12px 14px; margin: 8px 0; max-width: 760px;
      font-size: 14px; line-height: 1.4; }
    .top { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .pill { background: var(--c); color: #fff; font-weight: 700; border-radius: 999px; padding: 2px 10px; font-size: 12px; }
    .brand { font-weight: 700; color: #333; font-size: 13px; }
    .score { margin-left: auto; font-weight: 700; color: var(--c); }
    .title { font-weight: 700; margin: 6px 0 2px; font-size: 15px; }
    .text { margin: 2px 0 6px; color: #333; }
    ul { margin: 4px 0 8px 18px; padding: 0; } li { margin: 2px 0; }
    .chips { display: flex; gap: 6px; flex-wrap: wrap; margin: 4px 0 8px; }
    .chip { background: #f1f1f1; border-radius: 6px; padding: 2px 8px; font-size: 12px; }
    .btns { display: flex; gap: 8px; flex-wrap: wrap; }
    button { font: inherit; font-size: 13px; border-radius: 8px; padding: 6px 12px; cursor: pointer;
      border: 1px solid #bbb; background: #fff; color: #1b1b1b; }
    button.primary { background: var(--c); border-color: var(--c); color: #fff; font-weight: 600; }
    button[disabled] { opacity: .5; cursor: default; }
    .note { font-size: 12px; color: #555; margin-top: 6px; }
    .fixed { position: fixed; top: 12px; left: 50%; transform: translateX(-50%); z-index: 2147483647;
      width: min(760px, calc(100vw - 24px)); }
    .veil { position: fixed; inset: 0; z-index: 2147483647; background: rgba(20,20,20,.72);
      display: flex; align-items: center; justify-content: center; padding: 16px; }
    .modal { background: #fff; color: #1b1b1b; border-radius: 14px; max-width: 520px; width: 100%;
      padding: 20px; border-top: 8px solid var(--c); box-shadow: 0 10px 40px rgba(0,0,0,.4); }
    .modal h2 { margin: 6px 0 8px; font-size: 20px; }
    .count { font-size: 34px; font-weight: 800; color: var(--c); text-align: center; margin: 8px 0; }
  `;

  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") e.className = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    }
    for (const c of children) if (c !== null && c !== undefined) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return e;
  }

  function send(msg) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (r) => resolve(chrome.runtime.lastError ? null : r));
      } catch (_) {
        resolve(null); // extension reloaded
      }
    });
  }

  function makeHost(level) {
    const host = document.createElement("div");
    host.setAttribute(TAG, "");
    host.style.setProperty("all", "initial", "important");
    host.style.setProperty("display", "block", "important");
    const root = host.attachShadow({ mode: "closed" });
    root.append(el("style", {}, CSS));
    const wrap = el("div", { style: `--c:${COLORS[level] || COLORS.error}` });
    root.append(wrap);
    return { host, wrap };
  }

  /** Is the warning really on screen? Measures the card inside the shadow root (the host itself
   *  can be 0px tall when the card is position:fixed), plus the host's own styles. */
  function visible(host, probe) {
    if (!host.isConnected) return false;
    const cs = getComputedStyle(host);
    if (cs.display === "none" || cs.visibility === "hidden" || Number(cs.opacity) < 0.5) return false;
    const r = (probe || host).getBoundingClientRect();
    return r.width > 20 && r.height > 10;
  }

  /** Keep a warning on the page. If the page removes/hides it: restore it and report tampering. */
  function guardHost(host, place, what, probe) {
    let reported = false;
    let restores = 0;
    const timer = setInterval(() => {
      if (host.__flDismissed) return clearInterval(timer);
      if (!visible(host, probe)) {
        if (!reported) { reported = true; send({ type: "TAMPER", what }); }
        if (restores++ < 5) {
          host.style.setProperty("all", "initial", "important");
          host.style.setProperty("display", "block", "important");
          place(host);
        } else {
          clearInterval(timer); // the page keeps fighting: the badge + side panel still show the truth
        }
      }
    }, 800);
    setTimeout(() => clearInterval(timer), 120000);
  }

  function actionButtons(opts, level) {
    const btns = el("div", { class: "btns" });
    // "See why" opens the side panel ON THIS message / page (not just whatever it showed last).
    btns.append(el("button", { class: "primary", onclick: () => send({ type: "OPEN_PANEL", ref: String(opts.ref || "latest").slice(0, 64) }).then((r) => {
      if (!r || !r.opened) note.textContent = "The details are in the FraudLens side panel: click the FraudLens icon in the toolbar.";
      else note.textContent = "";
    }) }, "See why"));
    if (opts.reportText && level !== "error") {
      const rep = el("button", { onclick: async () => {
        rep.disabled = true;
        const r = await send({ type: "REPORT", text: opts.reportText, label: "scam", sender: opts.sender || null });
        note.textContent = (r && r.message) || "Couldn't send the report.";
      } }, "Report scam");
      btns.append(rep);
    }
    btns.append(el("button", { onclick: () => { opts.host.__flDismissed = true; opts.host.remove(); } }, "Dismiss"));
    const note = el("div", { class: "note" });
    return [btns, note];
  }

  /** Banner above a message (email / chat). */
  function banner(anchor, r, extra) {
    const level = r.level === "high" || r.level === "medium" ? r.level : "error";
    const { host, wrap } = makeHost(level);
    const card = el("div", { class: "card" },
      el("div", { class: "top" }, el("span", { class: "pill" }, LABELS[level]), el("span", { class: "brand" }, "FraudLens"),
        level !== "error" ? el("span", { class: "score" }, `${r.score}/100`) : null),
      el("div", { class: "title" }, level === "error" ? "FraudLens couldn't check this message" : (r.verdict || LABELS[level])),
      el("div", { class: "text" }, level === "error"
        ? (r.error === "not_configured"
          ? "FraudLens isn't connected to its server yet: click the FraudLens icon and connect. This does NOT mean the message is safe."
          : "The FraudLens server didn't answer. This does NOT mean the message is safe.")
        : String(r.summary || "").slice(0, 240)),
      r.tactics && r.tactics.length ? el("div", { class: "chips" }, ...r.tactics.map((t) => el("span", { class: "chip" }, t))) : null,
      r.offline ? el("div", { class: "note" }, "Offline copy of a demo result.") : null);
    const [btns, note] = actionButtons({ ...extra, host, ref: r.analysisId || (level === "error" ? "error" : "latest") }, level);
    card.append(btns, note);
    wrap.append(card);
    const place = (h) => { if (anchor.isConnected) anchor.parentNode.insertBefore(h, anchor); else document.documentElement.append(h); };
    place(host);
    guardHost(host, place, "banner_removed", card);
    return host;
  }

  /** Fixed banner at the top of a page (look-alike site / page reached from a scam). */
  function pageBanner(r) {
    const level = r.level === "high" ? "high" : "medium";
    const { host, wrap } = makeHost(level);
    const card = el("div", { class: "card fixed" },
      el("div", { class: "top" }, el("span", { class: "pill" }, LABELS[level]), el("span", { class: "brand" }, "FraudLens")),
      el("div", { class: "title" }, level === "high" ? "This page may be a scam" : "Check this website carefully"),
      el("ul", {}, ...(r.reasons || []).map((t) => el("li", {}, t))),
      r.practice ? el("div", { class: "note" }, `Practice page: it pretends to be at ${String(r.practice).slice(0, 80)}.`) : null);
    const [btns, note] = actionButtons({ host, ref: "page" }, level);
    card.append(btns, note);
    wrap.append(card);
    const place = (h) => document.documentElement.append(h);
    place(host);
    guardHost(host, place, "banner_removed", card);
    return host;
  }

  /** Modal while a clicked link is checked. Resolves "open" or "back". */
  function linkInterstitial(url, checking) {
    return new Promise((resolve) => {
      const { host, wrap } = makeHost("medium");
      const title = el("h2", {}, "Checking this link…");
      const body = el("div", { class: "text" }, url.length > 90 ? url.slice(0, 90) + "…" : url);
      const list = el("ul");
      const openBtn = el("button", { disabled: "", onclick: () => { host.__flDismissed = true; host.remove(); resolve("open"); } }, "Open anyway");
      const backBtn = el("button", { class: "primary", onclick: () => { host.__flDismissed = true; host.remove(); resolve("back"); } }, "Don't open");
      const modal = el("div", { class: "modal" }, el("div", { class: "brand" }, "FraudLens"), title, body, list,
        el("div", { class: "btns" }, backBtn, openBtn));
      wrap.append(el("div", { class: "veil" }, modal));
      document.documentElement.append(host);
      checking.then((r) => {
        const level = (r && r.level) || "error";
        wrap.style.setProperty("--c", COLORS[level] || "#2E7D32");
        title.textContent = level === "high" ? "Dangerous link" : level === "medium" ? "Suspicious link"
          : level === "low" ? "No warning signs found for this link" : "FraudLens couldn't check this link";
        for (const t of (r && r.reasons) || []) list.append(el("li", {}, t));
        const dest = r && r.expanded && Object.values(r.expanded)[0];
        if (dest) list.append(el("li", {}, `This short link really goes to: ${dest}`));
        if (level === "error") list.append(el("li", {}, "This does NOT mean the link is safe."));
        if (r && r.practice) list.append(el("li", {}, "Practice link: it opens a FraudLens practice page."));
        list.append(el("li", {}, "It came from a message FraudLens flagged. Open your bank's site by typing its address yourself."));
        openBtn.removeAttribute("disabled");
      });
    });
  }

  /** Pause-Before-Pay: full-screen pause with a countdown.
   *  There is deliberately NO "continue" button on the page: a scam page can draw over anything inside
   *  the page (even relabel our buttons), but not over Chrome's side panel. Continuing is only possible
   *  from the FraudLens side panel. Returns { left: Promise (user chose to leave), close() }. */
  function pauseOverlay(r) {
    const { host, wrap } = makeHost("high");
    let left = Math.max(3, Math.min(60, r.cooldown || 10));
    let onLeave;
    const leftPromise = new Promise((resolve) => { onLeave = resolve; });
    const count = el("div", { class: "count" }, String(left));
    const how = el("div", { class: "note" }, "Wait for the countdown, then think it over.");
    const openPanel = el("button", { disabled: "", onclick: () => send({ type: "OPEN_PANEL", ref: "page" }).then((x) => {
      if (!x || !x.opened) how.textContent = "Click the FraudLens icon in Chrome's toolbar to open its panel.";
    }) }, "Continue from the FraudLens panel");
    const leave = el("button", { class: "primary", onclick: () => { close(); onLeave(); } }, "Leave this page");
    const modal = el("div", { class: "modal" },
      el("div", { class: "top" }, el("span", { class: "pill" }, "Pause before you pay"), el("span", { class: "brand" }, "FraudLens")),
      el("h2", {}, "Stop. Don't enter card details, passwords or codes here."),
      el("ul", {}, ...(r.reasons || []).map((t) => el("li", {}, t)),
        el("li", {}, "Call your bank on the number on the back of your card, never one from a message.")),
      count, el("div", { class: "btns" }, leave, openPanel), how);
    wrap.append(el("div", { class: "veil" }, modal));
    document.documentElement.append(host);
    guardHost(host, (h) => document.documentElement.append(h), "overlay_removed", modal);
    const tick = setInterval(() => {
      left -= 1;
      count.textContent = left > 0 ? String(left) : "";
      if (left <= 0) {
        clearInterval(tick);
        openPanel.removeAttribute("disabled");
        how.textContent = "To continue anyway, use the FraudLens side panel: a scam page can't fake it.";
      }
    }, 1000);
    function close() {
      clearInterval(tick);
      host.__flDismissed = true;
      host.remove();
    }
    return { left: leftPromise, close };
  }

  Object.defineProperty(window, "FLUI", {
    value: Object.freeze({ banner, pageBanner, linkInterstitial, pauseOverlay, send }),
    writable: false, configurable: false,
  });
})();
