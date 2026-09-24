/* FraudLens guard: look-alike site warning + Pause-Before-Pay.
 * The service worker decides (from the page address Chrome gives it, not from this script):
 *   - is this a look-alike of a bank / post / brand in the verified directory?
 *   - did the user reach this site from a message FraudLens rated high risk?
 * If so, a warning banner is shown, and the first time the user focuses a field on the page (any
 * text, card, password or code field, also inside frames and shadow DOM) the page is paused with a
 * countdown. Continuing is only possible from the FraudLens side panel, which the page can't fake.
 * FraudLens only notices that a field was focused; it never reads what is typed.
 */
(function () {
  "use strict";
  if (window.top !== window || window.__flGuard) return;
  Object.defineProperty(window, "__flGuard", { value: true });

  const NOT_TEXT = new Set(["hidden", "button", "submit", "reset", "checkbox", "radio", "range", "color", "file", "image"]);
  let armed = null;       // result from the service worker when pause is on
  let released = false;
  let overlay = null;

  function isField(t) {
    if (t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement) return true;
    if (t instanceof HTMLInputElement) return !NOT_TEXT.has((t.type || "text").toLowerCase());
    return !!(t && t.isContentEditable);
  }

  function pause(target) {
    if (released) return;
    if (target && typeof target.blur === "function") target.blur();   // no typing while paused
    if (overlay) return;
    overlay = FLUI.pauseOverlay(armed);
    FLUI.send({ type: "PAUSE_SHOWN" });
    overlay.left.then(() => {
      if (history.length > 1) history.back();
      else location.replace("about:blank");
    });
  }

  // The side panel's "continue" arrives here (only the extension can send it).
  chrome.runtime.onMessage.addListener((msg, sender) => {
    if (sender.id !== chrome.runtime.id || !msg || msg.type !== "FL_RELEASE") return;
    released = true;
    if (overlay) { overlay.close(); overlay = null; }
  });

  function arm(r) {
    armed = r;
    // composedPath()[0] = the real field, also inside a web component's shadow DOM
    document.addEventListener("focusin", (ev) => {
      const t = (ev.composedPath && ev.composedPath()[0]) || ev.target;
      if (isField(t)) pause(t);
    }, true);
    // Fields inside frames (e.g. an embedded card form): focus moves into the frame
    window.addEventListener("blur", () => setTimeout(() => {
      const a = document.activeElement;
      if (!released && a && (a.tagName === "IFRAME" || a.tagName === "FRAME")) { a.blur(); pause(null); }
    }, 0));
    document.addEventListener("submit", (ev) => {
      if (released) return;
      ev.preventDefault();
      ev.stopImmediatePropagation();
      pause(null);
    }, true);
    const a = document.activeElement;
    if (isField(a) || (a && a.tagName === "IFRAME")) pause(a);
  }

  FLUI.send({ type: "PAGE_CHECK" }).then((r) => {
    if (!r || !r.warn) return;
    FLUI.pageBanner(r);
    if (r.pause) arm(r);
  });
})();
