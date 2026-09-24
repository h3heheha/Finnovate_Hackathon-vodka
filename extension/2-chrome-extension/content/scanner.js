/* FraudLens scanner: Gmail, Outlook, WhatsApp Web and the local demo inbox.
 * Runs only on sites the user switched on. For each new message:
 *   local prefilter → (only if suspicious) service worker → FraudLens server → banner if medium/high.
 * Links inside a flagged message are checked before they open.
 * It never listens to window.postMessage or page events: the page can't talk to it.
 */
(function () {
  "use strict";
  if (window.__flScanner) return;
  Object.defineProperty(window, "__flScanner", { value: true });

  const MAX_SCANS_PER_PAGE = 40;
  const done = new WeakMap(); // element -> text hash already checked
  let scans = 0;

  const host = location.hostname;
  const SITE = host === "mail.google.com" ? "gmail"
    : /outlook\.(live|office)\.com$/.test(host) ? "outlook"
      : host === "web.whatsapp.com" ? "whatsapp" : "demo";

  const ADAPTERS = {
    gmail: {
      channel: "email",
      find: () => document.querySelectorAll("div.a3s"),
      sender: (e) => { const s = e.closest(".gs, .adn")?.querySelector("span.gD[email], span[email]"); return s ? s.getAttribute("email") : null; },
    },
    outlook: {
      channel: "email",
      find: () => document.querySelectorAll('div[aria-label="Message body"], div[role="document"]'),
      sender: () => null,
    },
    whatsapp: {
      channel: "whatsapp",
      find: () => document.querySelectorAll("div.message-in"),
      sender: (e) => {
        const meta = e.querySelector("[data-pre-plain-text]")?.getAttribute("data-pre-plain-text") || "";
        const m = meta.match(/\]\s*(.+?):\s*$/);
        return m ? m[1].slice(0, 120) : null;
      },
    },
    demo: {
      channel: "email",
      find: () => document.querySelectorAll("[data-fl-message]"),
      sender: (e) => (e.getAttribute("data-sender") || "").slice(0, 120) || null,
    },
  };
  const A = ADAPTERS[SITE];

  function textOf(e) {
    return FLPrefilter.normalise(e.innerText || e.textContent || "");
  }

  function interceptLinks(e, result) {
    e.addEventListener("click", async (ev) => {
      const a = ev.target instanceof Element ? ev.target.closest("a[href]") : null;
      if (!a || !e.contains(a)) return;
      const href = a.href;
      if (!/^https?:/i.test(href)) return;
      ev.preventDefault();
      ev.stopImmediatePropagation();
      const checking = FLUI.send({ type: "CHECK_LINK", url: href.slice(0, 2000) });
      const choice = await FLUI.linkInterstitial(href, checking);
      if (choice === "open") window.open(href, "_blank", "noopener,noreferrer");
    }, true);
  }

  async function scanOne(e) {
    const text = textOf(e);
    const h = FLPrefilter.hash(text);
    if (done.get(e) === h) return;
    done.set(e, h);
    if (!FLPrefilter.check(text).send) return;          // stays on this computer
    if (++scans > MAX_SCANS_PER_PAGE) return;
    const sender = A.sender(e);
    const r = await FLUI.send({ type: "SCAN_TEXT", text, sender, channel: A.channel });
    if (!r || r.level === "skip" || r.level === "low") return;
    if (r.level === "high" || r.level === "medium" || r.level === "error") {
      FLUI.banner(e, r, { reportText: text, sender });
      if (r.level !== "error") interceptLinks(e, r);
    }
  }

  // Throttle, not debounce: a page that changes its DOM non-stop (e.g. every 250 ms) must not be able
  // to postpone scanning forever.
  let timer = null;
  function scanAll() {
    if (timer) return;
    timer = setTimeout(() => { timer = null; for (const e of A.find()) scanOne(e); }, 600);
  }

  scanAll();
  new MutationObserver(scanAll).observe(document.documentElement, { childList: true, subtree: true });
})();
