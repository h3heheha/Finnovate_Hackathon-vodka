"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  let base = null;

  async function load() {
    const s = await FLConnect.send({ type: "GET_SETTINGS" });
    if (s && s.apiBase) {
      base = s.apiBase;
      $("connectInput").value = s.apiBase;
      $("practiceBtn").disabled = false;
    }
  }

  $("connectBtn").addEventListener("click", () => {
    $("connectBtn").disabled = true;
    $("connectOut").className = "out";
    $("connectOut").textContent = "Asking Chrome for permission…";
    FLConnect.connect($("connectInput").value, (msg) => { $("connectOut").textContent = msg; }).then(async (r) => {
      $("connectBtn").disabled = false;
      $("connectOut").className = `out ${r.ok ? "good" : "bad"}`;
      $("connectOut").textContent = r.ok ? `✓ ${r.message}` : r.message;
      if (r.ok) {
        base = r.base;
        $("practiceBtn").disabled = false;
        FLConnect.renderServices($("services"), await FLConnect.send({ type: "CHECK_SERVICES" }));
      }
    });
  });

  $("practiceBtn").addEventListener("click", () => {
    if (base) chrome.tabs.create({ url: `${base}/demo/` });
  });

  load();
})();
