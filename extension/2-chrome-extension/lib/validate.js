/* Strict message validation for the service worker.
 * Only these message types exist, each with a fixed shape. Anything else is dropped.
 * Content scripts can never name a URL for the service worker to fetch: every request goes to the
 * configured FraudLens server on a fixed path, and page URLs are taken from Chrome (sender.url).
 */
(function (root) {
  "use strict";

  const str = (max, optional = false) => (v) =>
    (optional && (v === undefined || v === null)) || (typeof v === "string" && v.length <= max);
  const bool = (optional = true) => (v) => (optional && v === undefined) || typeof v === "boolean";
  const oneOf = (...vals) => (v) => vals.includes(v);

  // who: "content" = from a content script in a tab, "panel" = from our own side panel page.
  const SCHEMAS = {
    SCAN_TEXT: { who: "content", fields: { text: str(5000), sender: str(120, true), channel: oneOf("email", "whatsapp", "sms", "social", "other") } },
    CHECK_LINK: { who: "content", fields: { url: str(2000) } },
    PAGE_CHECK: { who: "content", fields: {} },
    TAMPER: { who: "content", fields: { what: oneOf("banner_removed", "overlay_removed") } },
    OPEN_PANEL: { who: "content", fields: { ref: str(64, true) } },
    REPORT: { who: "any", fields: { text: str(5000), label: oneOf("scam", "legit"), sender: str(120, true) } },
    PAUSE_SHOWN: { who: "content", fields: {} },
    RELEASE_PAUSE: { who: "panel", fields: { tabId: (v) => Number.isInteger(v) && v >= 0 } },
    PANEL_STATE: { who: "panel", fields: { tabId: (v) => Number.isInteger(v) && v >= 0 } },
    PANEL_CHECK_TEXT: { who: "panel", fields: { text: str(5000), tabId: (v) => Number.isInteger(v) && v >= 0 } },
    FEEDBACK: { who: "panel", fields: { analysisId: str(64), verdict: oneOf("scam", "legit", "unsure") } },
    GET_SETTINGS: { who: "panel", fields: {} },
    SAVE_SETTINGS: { who: "panel", fields: { apiBase: str(300, true), keepAwake: bool() } },
    TEST_CONNECTION: { who: "panel", fields: { wake: bool() } },
    CHECK_SERVICES: { who: "panel", fields: {} },
  };

  /** @returns {string|null} error text, or null if the message is valid */
  function check(msg, sender, extensionId, panelUrlPrefix) {
    if (!sender || sender.id !== extensionId) return "foreign sender";
    if (!msg || typeof msg !== "object" || Array.isArray(msg)) return "not an object";
    const schema = SCHEMAS[msg.type];
    if (!schema) return "unknown type";
    // Our own pages have a chrome-extension://<our id>/ URL; content scripts report the web page's URL.
    const ownPage = typeof sender.url === "string" && sender.url.startsWith(`chrome-extension://${extensionId}/`);
    const fromPanel = ownPage && sender.url.startsWith(panelUrlPrefix);
    const fromContent = !ownPage && !!(sender.tab && Number.isInteger(sender.tab.id) && sender.tab.id >= 0);
    if (schema.who === "content" && !fromContent) return "wrong origin";
    if (schema.who === "panel" && !fromPanel) return "wrong origin";
    if (schema.who === "any" && !fromContent && !fromPanel) return "wrong origin";
    const allowed = new Set(["type", ...Object.keys(schema.fields)]);
    for (const k of Object.keys(msg)) if (!allowed.has(k)) return `unexpected field ${k}`;
    for (const [k, ok] of Object.entries(schema.fields)) if (!ok(msg[k])) return `bad field ${k}`;
    return null;
  }

  root.FLValidate = Object.freeze({ check, SCHEMAS });
})(typeof self !== "undefined" ? self : globalThis);
