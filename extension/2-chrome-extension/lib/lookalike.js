/* Look-alike / risky site check, done LOCALLY against the verified directory (directory.json).
 * Normal browsing never leaves the computer. Only an address that
 *   - imitates a bank / post / brand in the directory, or
 *   - shows phishing signals (free hosting, raw IP, throwaway ending, "login/verify" words, a brand
 *     name in the path, look-alike letters)
 * is sent on to the server's threat-intelligence check (Safe Browsing, URLhaus, domain age).
 */
(function (root) {
  "use strict";

  // Second-level suffixes where the registered domain has three labels (mcb.co.mu style).
  const TWO_LEVEL = new Set(["co.mu", "com.mu", "org.mu", "gov.mu", "ac.mu", "net.mu", "co.uk", "org.uk",
    "ac.uk", "gov.uk", "com.au", "co.za", "co.in", "com.fr", "com.br", "co.jp", "govmu.org"]);
  // Brand words too generic to judge a web address on their own.
  const GENERIC = new Set(["juice", "post", "poste", "bank", "la", "apple", "office", "live", "meta"]);
  const HOMOGLYPHS = [[/rn/g, "m"], [/vv/g, "w"], [/0/g, "o"], [/1/g, "l"], [/3/g, "e"], [/5/g, "s"], [/4/g, "a"], [/@/g, "a"], [/\$/g, "s"]];
  // Free hosting where ANYONE can publish a page under the provider's name (never "official").
  const FREE_HOSTING = ["github.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app", "web.app",
    "firebaseapp.com", "weebly.com", "wixsite.com", "blogspot.com", "000webhostapp.com", "glitch.me",
    "repl.co", "replit.dev", "onrender.com", "herokuapp.com", "ngrok-free.app", "ngrok.io", "ngrok.app",
    "trycloudflare.com", "surge.sh", "framer.website", "webflow.io", "square.site", "godaddysites.com",
    "sites.google.com", "forms.gle", "ipfs.io", "r2.dev", "azurewebsites.net", "appspot.com"];
  const RISKY_TLDS = new Set(["top", "xyz", "click", "link", "shop", "rest", "icu", "cfd", "sbs", "buzz", "monster",
    "cyou", "quest", "zip", "mov", "country", "gq", "tk", "ml", "cf", "ga", "support", "live", "online", "site",
    "info", "lat", "bond", "win", "vip"]);
  const LURE = /(^|[.-])(login|log-in|signin|sign-in|verify|verification|secure|security|account|update|billing|unlock|confirm|wallet|recovery|auth|validate|suspended|refund|payment|banking)([.-]|$)/;
  // What scammers glue onto a brand name: country codes and "service" words (netflixde, paypal-help, amazonsupport).
  const BRAND_ADDONS = new Set(["de", "fr", "us", "uk", "mu", "in", "es", "it", "nl", "ca", "au", "br", "jp", "eu",
    "ae", "za", "ng", "pk", "sa", "mx", "ch", "be", "at", "se", "pl", "pt", "tr", "ru", "cn", "sg", "my", "ph",
    "app", "apps", "web", "online", "secure", "login", "signin", "account", "accounts", "support", "help", "care",
    "service", "services", "pay", "billing", "verify", "update", "official", "team", "center", "centre", "portal",
    "id", "auth", "mail", "customer", "refund", "gift", "promo", "free", "bonus", "reward", "rewards", "tv", "hd",
    "premium", "member", "members", "renew", "unlock", "wallet", "prime", "store", "shop"]);
  const PATH_LURE = /(login|signin|sign-in|verify|verification|account|update|billing|unlock|confirm|wallet|recovery|password|payment|card|otp|suspend)/;

  function registered(host) {
    const labels = host.split(".").filter(Boolean);
    if (labels.length <= 2) return labels.join(".");
    const last2 = labels.slice(-2).join(".");
    return TWO_LEVEL.has(last2) ? labels.slice(-3).join(".") : last2;
  }

  function unconfuse(s) {
    return HOMOGLYPHS.reduce((acc, [re, to]) => acc.replace(re, to), s);
  }

  /** Optimal-string-alignment distance: typos, missing letters AND swapped neighbours ("gitbuh"). */
  function editDistance(a, b) {
    if (Math.abs(a.length - b.length) > 2) return 99;
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
    return d[a.length][b.length];
  }

  function parse(input) {
    let s = String(input || "").trim().toLowerCase();
    if (!/^[a-z][a-z0-9+.-]*:\/\//.test(s)) s = "http://" + s;
    try {
      const u = new URL(s);
      return { host: u.hostname.replace(/^www\./, "").replace(/\.$/, ""), path: decodeURIComponent(u.pathname || "/") };
    } catch (_) {
      return { host: "", path: "/" };
    }
  }

  // Sites where the page owner is chosen by the PATH, not the address (sites.google.com/view/<anyone>).
  const PATH_HOSTED = new Set(["sites.google.com", "forms.gle"]);

  function freeHost(host) {
    if (PATH_HOSTED.has(host)) return host;
    return FREE_HOSTING.find((f) => host.endsWith("." + f)) || null;
  }

  /**
   * @param {string} input     a URL ("https://x.github.io/Netflix") or a hostname
   * @param {object} directory the verified directory ({organisations: [...]})
   * @returns {{official: boolean, suspicious: boolean, risky: boolean, org: string|null, reasons: string[]}}
   *   suspicious = show a warning; risky = worth a security-database check (no warning on its own)
   */
  function check(input, directory) {
    const { host, path } = parse(input);
    const out = { official: false, suspicious: false, risky: false, org: null, reasons: [] };
    if (!host || (!host.includes(".") && host !== "localhost")) return out;
    const orgs = (directory && directory.organisations) || [];
    const hosting = freeHost(host);

    // 1) The organisation's own website (but never a page anyone can publish on free hosting).
    if (!hosting) {
      for (const org of orgs) {
        for (const d of org.domains || []) {
          if (host === d || host.endsWith("." + d)) {
            out.official = true;
            out.org = org.name;
            return out;
          }
        }
      }
    }

    // 2) Phishing signals in the address itself.
    const signals = [];
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
    // home routers / this computer (192.168.x, 10.x, 127.x…) are not scam sites
    const privateIp = /^(10|127)\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.|^169\.254\./.test(host);
    const tld = host.split(".").pop();
    if (hosting) signals.push(`The page is on free hosting (${hosting}) where anyone can publish a page.`);
    if (isIp && !privateIp) signals.push("The address is a raw number (IP address) instead of a company name.");
    if ((hosting || (isIp && !privateIp)) && PATH_LURE.test(path)) signals.push("It asks you to log in or verify on a page anyone could have made.");
    if (host.split(".").some((l) => l.startsWith("xn--"))) signals.push("The web address uses look-alike letters from another alphabet.");
    if (RISKY_TLDS.has(tld) && !isIp) signals.push(`The address ends in ".${tld}", which is cheap and often used for scam sites.`);
    if (LURE.test(host)) signals.push("The address contains words like \"login\", \"verify\" or \"secure\" to look official.");
    if ((host.match(/-/g) || []).length >= 3 || host.length > 45) signals.push("The address is unusually long or full of hyphens.");

    // 3) Imitating a brand in the directory (address or, on free hosting, the path).
    // on free hosting, only the part the page owner chose counts (not "github" in "x.github.io")
    const own = hosting ? (hosting === host ? "" : host.slice(0, -(hosting.length + 1))) : host;
    const tokens = own.split(/[.-]/).filter(Boolean).map(unconfuse);
    const compact = unconfuse(own.replace(/[^a-z0-9]/g, ""));
    const reg = registered(host);
    const rawLabel = hosting ? (own.split(".").pop() || "") : reg.split(".")[0];
    const regLabel = unconfuse(rawLabel);
    const pathText = unconfuse(path.replace(/[^a-z0-9]/g, ""));
    for (const org of orgs) {
      const officialLabels = (org.domains || []).map((d) => d.split(".")[0]);
      const words = (org.keywords || []).filter((k) => !k.includes(" ") && !GENERIC.has(k));
      const inHost = words.some((k) => k.length <= 4 ? tokens.includes(k) : compact.includes(k));
      const brandInPath = words.some((k) => k.length >= 4 && pathText.includes(k));
      const inPath = brandInPath && (hosting || (isIp && !privateIp) || signals.length > 0);
      if (brandInPath && !inPath && !out.org) { out.risky = true; out.reasons.push(`The page mentions ${org.name} but is not on their website.`); }
      // short names (mcb, mra, dhl) only match exact look-alike letters; longer ones also a typo / swap
      const nearMiss = officialLabels.some((o) => rawLabel !== o &&
        (o.length >= 5 ? editDistance(regLabel, o) <= 1 : regLabel === o));
      const sameBrandElsewhere = !hosting && officialLabels.includes(rawLabel); // e.g. dhl.de, amazon.fr
      // brand + country code / "service" word glued together: netflixde, paypal-help, amazon-support
      const addOn = words.some((k) => {
        if (k.length < 3 || !rawLabel.includes(k)) return false;
        const rest = rawLabel.replace(k, "").split("-").filter(Boolean);
        return rest.length > 0 && rest.every((r) => BRAND_ADDONS.has(r));
      });
      // Global brands ("strict") need more than their name in the address: an add-on, a lure word or
      // another signal. Their name alone still sends the address to the security databases.
      const brandHit = (inHost || addOn) && (!org.strict || addOn || signals.length > 0 || LURE.test(host));
      if (inHost && !brandHit && !nearMiss && !inPath && !sameBrandElsewhere && !out.org) {
        out.risky = true;
        out.reasons.push(`The address uses the name ${org.name} but is not their website.`);
      }
      if ((brandHit || nearMiss || inPath) && !sameBrandElsewhere) {
        out.suspicious = true;
        out.org = org.name;
        const official = (org.domains || [])[0];
        out.reasons.push(nearMiss
          ? `The address is one letter away from ${official}, the real ${org.name} website.`
          : inPath && !inHost
            ? `The page pretends to be ${org.name}, but it is not on ${official}, their real website.`
            : `The address mentions ${org.name}, but it is not ${official}, their real website.`);
        break;
      }
    }

    out.reasons.push(...signals);
    if (out.suspicious) out.risky = false;
    if (!out.suspicious && signals.length) {
      out.risky = true;
      // two independent signals, or a lure word on free hosting / raw IP, are enough to warn
      if (signals.length >= 2) out.suspicious = true;
    }
    return out;
  }

  root.FLLookalike = Object.freeze({ check, registered, editDistance });
})(typeof self !== "undefined" ? self : globalThis);
