/* FraudLens local prefilter: decides IN THE BROWSER whether a message is worth checking.
 * Ordinary chats never leave the computer; only messages with a link, a phone/account number,
 * money, or pressure words (EN / FR / Kreol) are sent to the FraudLens server.
 * Same idea as FraudLens Shield's on-phone prefilter. Shared by the service worker and content scripts.
 */
(function (root) {
  "use strict";

  const MIN_LENGTH = 12;
  const MAX_LENGTH = 5000;

  const LINK = /\b(?:https?:\/\/|www\.)\S+|\b[a-z0-9-]+\.(?:com|net|org|info|xyz|top|site|online|app|live|link|click|mu|ly|me|co|io|cc|tk|ml|ga|gq|shop|store|support|help|page)\b/i;
  const NUMBER = /(?:\+\d{1,3}[\s-]?)?\b\d{3,4}[\s-]?\d{4}\b|\b\d{9,20}\b/;
  const MONEY = /\b(?:rs\.?|mur|eur|usd|\$|€|£)\s?\d|\b\d[\d,.]*\s?(?:rs|rupees?|roupies?|mur|euros?|dollars?)\b/i;
  const PRESSURE = new RegExp([
    // English
    "urgent", "immediately", "within \\d+ ?(?:h|hours?|min)", "today only", "suspend", "blocked", "locked",
    "verify", "confirm your", "otp", "pin", "password", "one[- ]time", "click (?:here|the link)", "prize",
    "won", "winner", "lottery", "refund", "customs", "parcel", "fee", "crypto", "invest", "guaranteed",
    "new number", "lost my phone", "send money", "transfer", "gift card", "bank details", "account",
    // French
    "urgent", "imm[ée]diatement", "bloqu[ée]", "suspendu", "v[ée]rifi", "confirme[rz]", "code", "colis",
    "douane", "frais", "gagn[ée]", "rembourse", "virement", "coordonn[ée]es", "mot de passe",
    // Kreol Morisien
    "vit vit", "avoy", "kas", "gagne", "lamone", "nouvo nimero", "pa dir personn", "urzan", "transfer"
  ].join("|"), "i");

  function normalise(text) {
    return String(text || "").replace(/\s+/g, " ").trim().slice(0, MAX_LENGTH);
  }

  /** @returns {{send: boolean, reasons: string[]}} */
  function check(text) {
    const t = normalise(text);
    if (t.length < MIN_LENGTH) return { send: false, reasons: ["too short"] };
    const reasons = [];
    if (LINK.test(t)) reasons.push("link");
    if (NUMBER.test(t)) reasons.push("number");
    if (MONEY.test(t)) reasons.push("money");
    if (PRESSURE.test(t)) reasons.push("pressure words");
    return { send: reasons.length > 0, reasons };
  }

  /** Short stable hash (FNV-1a) so the same message is only checked once. */
  function hash(text) {
    let h = 0x811c9dc5;
    const t = normalise(text);
    for (let i = 0; i < t.length; i++) {
      h ^= t.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h.toString(16);
  }

  root.FLPrefilter = Object.freeze({ check, hash, normalise, MAX_LENGTH });
})(typeof self !== "undefined" ? self : globalThis);
