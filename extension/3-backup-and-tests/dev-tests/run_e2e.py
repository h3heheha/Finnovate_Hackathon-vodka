"""End-to-end test of EXTENSION V2, done exactly the way START HERE.md tells people to set it up.

    (developers only, Linux)  xvfb-run python 3-backup-and-tests/dev-tests/run_e2e.py

What it does:
  * starts the server the way the Render container does (non-root user, same env vars, install
    tokens required) but behind HTTPS on a fake Render address: https://fraudlens-test.onrender.com
    (Chromium maps that name to this computer and accepts the test certificate);
  * loads the chrome-extension folder into Chromium. The only change to the test copy is that the
    server address is pre-approved in the manifest, standing in for the user's "Allow" click (automated
    tests can't click Chrome's own permission prompt);
  * follows the guide: welcome page -> paste address -> Connect -> practice pages, then attacks,
    live learning, the free server falling asleep and waking up, and "every site" protection.
Screenshots go to 3-backup-and-tests/dev-tests/screenshots/.

Environment variables: FL_SERVER_DIR (container-like copy of the server, default /srv/fltest/app),
FL_PYTHON (python with the server requirements), FL_RUN_AS (user to run the server as).
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
V2 = HERE.parents[1]
EXT_SRC = V2 / "2-chrome-extension"
DEMO = V2 / "1-server" / "app" / "static" / "demo"
SHOTS = HERE / "screenshots"
SERVER_DIR = Path(os.environ.get("FL_SERVER_DIR", "/srv/fltest/app"))
PYTHON = os.environ.get("FL_PYTHON", "/srv/fltest/venv/bin/python")
RUN_AS = os.environ.get("FL_RUN_AS", "fraudlens")
HOST = "fraudlens-test.onrender.com"
BASE = f"https://{HOST}"
PORT = 8443
PINNED_ID = "bnoincbnfccidpkdnfelgejnldhicimk"
SECRET_A = "dGVzdC1zZWNyZXQtQS0xMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA="
SECRET_B = "dGVzdC1zZWNyZXQtQi0xMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA="

results: list[tuple[str, bool, str]] = []


def check(name: str, ok, detail: str = "") -> None:
    results.append((name, bool(ok), str(detail)))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def port_open(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def wait_port(port: int, timeout: float = 120, up: bool = True) -> None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if port_open(port) == up:
            return
        time.sleep(0.3)
    raise RuntimeError(f"port {port} never {'opened' if up else 'closed'}")


# ---- the server, like the Render container ---------------------------------------------------------
def make_cert(tmp: Path) -> tuple[Path, Path]:
    key, crt = tmp / "key.pem", tmp / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", f"/CN={HOST}",
                    "-addext", f"subjectAltName=DNS:{HOST}", "-keyout", str(key), "-out", str(crt)],
                   check=True, capture_output=True)
    for p in (key, crt):
        p.chmod(0o644)
    return key, crt


def start_server(tmp: Path, key: Path, crt: Path, secret: str, fresh: bool = False) -> None:
    if fresh:
        for d in ("data/runtime", "data/cache"):
            shutil.rmtree(SERVER_DIR / d, ignore_errors=True)
    env = " ".join(f"{k}={v}" for k, v in {
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONUNBUFFERED": "1", "MALLOC_ARENA_MAX": "2",
        "FRAUDLENS_REQUIRE_INSTALL_TOKEN": "true", "FRAUDLENS_ONNX_THREADS": "1",
        "FRAUDLENS_INSTALL_SECRET": secret, "FRAUDLENS_HASH_SALT": "c2FsdA==", "FRAUDLENS_REPORT_CONFIRMATIONS": "1",
        "HTTPS_PROXY": os.environ.get("HTTPS_PROXY", ""), "SSL_CERT_FILE": "/srv/fltest/ca.crt",
        "NO_PROXY": "localhost,127.0.0.1"}.items())
    cmd = (f"cd {SERVER_DIR} && env {env} {PYTHON} -m uvicorn app.main:app --host 127.0.0.1 --port {PORT} "
           f"--ssl-keyfile {key} --ssl-certfile {crt} --proxy-headers --forwarded-allow-ips '*' >> {tmp}/server.log 2>&1")
    subprocess.Popen(["su", RUN_AS, "-s", "/bin/sh", "-c", cmd])
    wait_port(PORT)


def stop_server() -> None:
    subprocess.run(["pkill", "-u", RUN_AS, "-f", f"port {PORT}"], check=False)
    wait_port(PORT, up=False, timeout=30)


def server_hwm_mb() -> int:
    """Peak memory of the uvicorn (python) process; the su / sh wrappers are ignored."""
    out = subprocess.run(["pgrep", "-u", RUN_AS, "-f", f"port {PORT}"], capture_output=True, text=True).stdout.split()
    best = -1
    for pid in out:
        try:
            if b"uvicorn" not in open(f"/proc/{pid}/cmdline", "rb").read() or b"python" not in open(f"/proc/{pid}/cmdline", "rb").read():
                continue
            for line in open(f"/proc/{pid}/status"):
                if line.startswith("VmHWM"):
                    best = max(best, int(line.split()[1]) // 1024)
        except OSError:
            pass
    return best


def test_copy(tmp: Path, name: str, extra_hosts: list[str]) -> Path:
    ext = tmp / name
    shutil.copytree(EXT_SRC, ext)
    m = json.loads((ext / "manifest.json").read_text())
    m["host_permissions"] += [f"{BASE}/*", *extra_hosts]   # = the user's "Allow" click(s)
    (ext / "manifest.json").write_text(json.dumps(m, indent=2))
    return ext


def launch(pw, tmp: Path, ext: Path, profile: str):
    return pw.chromium.launch_persistent_context(
        str(tmp / profile), headless=False, viewport={"width": 1200, "height": 900},
        args=[f"--disable-extensions-except={ext}", f"--load-extension={ext}", "--no-first-run",
              f"--host-resolver-rules=MAP {HOST}:443 127.0.0.1:{PORT}", "--ignore-certificate-errors",
              "--no-proxy-server"])


# ---- helpers for pages ------------------------------------------------------------------------------
HOSTS_JS = "() => [...document.querySelectorAll('html *')].filter(e => [...e.attributes].some(a => /^data-[a-z]{8}$/.test(a.name))).length"
LAST_HOST_JS = "[...document.documentElement.children].filter(e => [...e.attributes].some(a => /^data-[a-z]{8}$/.test(a.name))).pop()"


def wait_until(page, fn_js: str, timeout: float) -> None:
    """Poll a JS arrow function (extension pages forbid eval, which wait_for_function uses)."""
    t0 = time.time()
    while time.time() - t0 < timeout / 1000:
        if page.evaluate(fn_js):
            return
        time.sleep(0.5)
    raise TimeoutError(f"timed out waiting for {fn_js}")


def shadow_click(page, host_expr: str, text: str) -> bool:
    """Click a button inside FraudLens's CLOSED shadow root (DevTools protocol can see into it)."""
    cdp = page.context.new_cdp_session(page)
    try:
        cdp.send("DOM.enable")
        obj = cdp.send("Runtime.evaluate", {"expression": host_expr})["result"]
        if "objectId" not in obj:
            return False
        node = cdp.send("DOM.describeNode", {"objectId": obj["objectId"], "depth": -1, "pierce": True})["node"]

        def find(n):
            if n.get("nodeName") == "BUTTON" and any(c.get("nodeValue", "").strip() == text for c in n.get("children", [])):
                return n
            for c in n.get("children", []) + n.get("shadowRoots", []):
                hit = find(c)
                if hit:
                    return hit
            return None

        btn = find(node)
        if not btn:
            return False
        q = cdp.send("DOM.getBoxModel", {"backendNodeId": btn["backendNodeId"]})["model"]["content"]
        page.mouse.click((q[0] + q[2]) / 2, (q[1] + q[5]) / 2)
        return True
    finally:
        cdp.detach()


def main() -> int:
    SHOTS.mkdir(exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="fl-v2-e2e-"))
    tmp.chmod(0o755)
    (tmp / "server.log").touch()
    (tmp / "server.log").chmod(0o666)   # the server runs as an ordinary user, like in the container
    key, crt = make_cert(tmp)
    for port in (8765, 8000, PORT):   # leftovers of an interrupted run
        subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True)
    time.sleep(1)
    pages = subprocess.Popen([sys.executable, "-m", "http.server", "8765", "--bind", "127.0.0.1"], cwd=DEMO,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    start_server(tmp, key, crt, SECRET_A, fresh=True)
    try:
        with sync_playwright() as pw:
            phase1(pw, tmp, key, crt)
            phase2(pw, tmp)
            phase3(pw, tmp)
    finally:
        stop_server()
        pages.terminate()
        shutil.copy(tmp / "server.log", HERE / "last_server.log")
        shutil.rmtree(tmp, ignore_errors=True)
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    for name, _, detail in failed:
        print(f"  FAILED: {name} [{detail}]")
    return 1 if failed else 0


def tools(ctx, sw):
    def session() -> dict:
        return sw.evaluate("chrome.storage.session.get(null)")

    def items() -> list[dict]:
        out = []
        for k, v in session().items():
            if k.startswith("tab:"):
                out += v.get("items", [])
        return out

    def badge_where(pred_js: str):
        return sw.evaluate(f"""async () => {{
            for (const [k, v] of Object.entries(await chrome.storage.session.get(null)))
              if (k.startsWith('tab:') && (v.items || []).some({pred_js})) return chrome.action.getBadgeText({{tabId: Number(k.slice(4))}});
            return null; }}""")
    return session, items, badge_where


# ---- phase 1: fresh install, follow the guide ---------------------------------------------------------
def phase1(pw, tmp: Path, key: Path, crt: Path) -> None:
    ext = test_copy(tmp, "ext1", [])
    ctx = launch(pw, tmp, ext, "profile1")
    sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker", timeout=20000)
    ext_id = sw.url.split("/")[2]
    check("Extension ID is pinned (the server trusts only this ID)", ext_id == PINNED_ID, ext_id)
    session, items, badge_where = tools(ctx, sw)

    # -- welcome page opens by itself
    t0 = time.time()
    welcome = None
    while time.time() - t0 < 15 and not welcome:
        welcome = next((p for p in ctx.pages if p.url.endswith("/sidepanel/welcome.html")), None)
        ctx.pages[0].wait_for_timeout(300)   # lets Playwright process new-tab events (time.sleep would not)
    check("Welcome page opens by itself after installing", welcome is not None)
    scripts = sw.evaluate("chrome.scripting.getRegisteredContentScripts().then(s => s.map(x => x.id))")
    check("Before connecting: FraudLens reads no website", scripts == [], str(scripts))

    # -- connect exactly like a person: paste the address without https://
    welcome.bring_to_front()
    welcome.fill("#connectInput", f"  {HOST}/  ")
    welcome.click("#connectBtn")
    wait_until(welcome, "() => document.getElementById('connectOut').textContent.startsWith('✓')", timeout=90000)
    check("Welcome page: paste address -> Connect -> connected", True, welcome.inner_text("#connectOut"))
    wait_until(welcome, "() => document.querySelectorAll('#services .svc').length > 0", timeout=60000)
    svc = welcome.evaluate("[...document.querySelectorAll('#services .svc')].map(e => [e.className.replace('svc ', ''), e.querySelector('b').textContent])")
    check("Service check lists every outside service", len(svc) >= 8, "; ".join(f"{n}={s}" for s, n in svc))
    check("Missing keys are shown as optional, not as broken",
          all(s in ("working", "not_set", "untested", "error", "off") for s, _ in svc) and any(s == "not_set" for s, _ in svc))
    welcome.screenshot(path=str(SHOTS / "01_welcome_connected.png"), full_page=True)
    stored = sw.evaluate("chrome.storage.local.get(['apiBase', 'install'])")
    check("Server address cleaned up and saved", stored.get("apiBase") == BASE, stored.get("apiBase"))
    check("Browser registered with the server (signed install token)", bool(stored.get("install", {}).get("token")))
    scripts = sw.evaluate("chrome.scripting.getRegisteredContentScripts().then(s => s.map(x => [x.id, x.matches]))")
    check("Practice pages on the server are checked automatically",
          sorted(scripts) == [["fl-guard", [f"{BASE}/demo/*"]], ["fl-scanner", [f"{BASE}/demo/*"]]], str(scripts))
    alarm = sw.evaluate("chrome.alarms.get('fl-keepalive')")
    check("Keep-awake visit scheduled every 10 minutes", alarm and alarm.get("periodInMinutes") == 10, str(alarm))

    # -- practice pages
    with ctx.expect_page() as newp:
        welcome.click("#practiceBtn")
    index = newp.value
    index.wait_for_load_state()
    check("'Open the practice pages' opens the server's /demo/ page", index.url == f"{BASE}/demo/", index.url)
    index.wait_for_timeout(1500)
    check("No warning on the practice index page", index.evaluate(HOSTS_JS) == 0)

    inbox = ctx.new_page()
    inbox.goto(f"{BASE}/demo/inbox.html")
    inbox.wait_for_timeout(12000)
    msgs = [i for i in items() if i["kind"] == "message"]
    by = lambda s: next((i for i in msgs if s in i["text"]), None)
    for label, snippet in [("card blocked", "Your card has been blocked"), ("fake bank", "temporarily suspended"),
                           ("parcel fee", "Mauritius Post"), ("hi mum", "Hi Mum"), ("prompt injection", "SYSTEM NOTE TO AI")]:
        it = by(snippet)
        check(f"Scam flagged: {label}", it and it["level"] == "high", it and f"{it['data']['risk_score']}/100")
    it = by("Juice account is on hold")
    check("Short-link scam flagged", it and it["level"] in ("medium", "high"), it and f"{it['data']['risk_score']}/100")
    check("Genuine chat never left the browser", by("Still on for dinner") is None)
    otp = by("Your OTP for the online payment")
    check("Genuine OTP: checked, no warning", otp and otp["level"] == "low", otp and f"{otp['data']['risk_score']}/100")
    flagged = sum(1 for i in msgs if i["level"] in ("medium", "high"))
    check("One banner per flagged message, none on genuine ones", inbox.evaluate(HOSTS_JS) == flagged, f"{flagged} flagged")
    check("Toolbar badge shows '!'", badge_where("i => i.kind === 'message'") == "!")
    inbox.screenshot(path=str(SHOTS / "02_inbox.png"), full_page=True)

    host_of_fake_bank = "document.querySelector('#m-fake_bank .body').previousElementSibling"
    inbox.evaluate(f"{host_of_fake_bank}.scrollIntoView({{block: 'center'}})")
    ok = shadow_click(inbox, host_of_fake_bank, "See why")
    inbox.wait_for_timeout(2500)
    opened = sw.evaluate("chrome.runtime.getContexts({contextTypes: ['SIDE_PANEL']}).then(c => c.length)")
    st = next(v for k, v in session().items() if k.startswith("tab:") and any("temporarily suspended" in i.get("text", "") for i in v.get("items", [])))
    focused = next((i for i in st["items"] if i["id"] == st.get("focus")), {})
    check("'See why' opens the side panel on that message", ok and opened >= 1 and "temporarily suspended" in focused.get("text", ""))

    # -- scam link -> check before opening -> practice page pretending to be the scam site -> Pause-Before-Pay
    before = inbox.url
    inbox.click("#m-demo_card a")
    inbox.wait_for_timeout(2500)
    check("Link in a scam is checked before it opens", inbox.url == before)
    inbox.screenshot(path=str(SHOTS / "03_link_check.png"))
    link = next((i for i in items() if i["kind"] == "link"), {})
    check("Link check sees the pretend scam address", link.get("url", "").startswith("http://mcb-secure-verify.com/")
          and link.get("level") == "high" and link.get("practice"), f"{link.get('url')} {link.get('level')}")
    check("Scam address remembered for Pause-Before-Pay", "mcb-secure-verify.com" in session().get("tainted", {}))
    with ctx.expect_page() as newp:
        clicked = shadow_click(inbox, LAST_HOST_JS, "Open anyway")
    fake = newp.value
    fake.wait_for_load_state()
    fake.wait_for_timeout(3500)
    check("'Open anyway' opens the practice scam page", clicked and fake.url == f"{BASE}/demo/login.html#as=mcb-secure-verify.com", fake.url)
    page_it = next((i for i in items() if i["kind"] == "page" and i.get("host") == "mcb-secure-verify.com"), {})
    check("Practice scam page flagged high: reached from a scam + look-alike",
          page_it.get("level") == "high" and any("rated" in r for r in page_it.get("reasons", [])), "; ".join(page_it.get("reasons", []))[:150])
    check("Warning banner shown on the page", fake.evaluate(HOSTS_JS) >= 1)
    fake.focus("#pw")
    fake.wait_for_timeout(800)
    check("Pause-Before-Pay stops the password field", fake.evaluate("document.activeElement && document.activeElement.id") != "pw")
    fake.keyboard.type("secret123")
    fake.focus("#card")
    fake.keyboard.type("4111111111111111")
    check("Nothing can be typed while paused", fake.evaluate("[pw.value, card.value]") == ["", ""])
    fake.screenshot(path=str(SHOTS / "04_pause_before_pay.png"))
    overlay_host = LAST_HOST_JS
    check("The page has no 'continue' button a scam page could relabel",
          not shadow_click(fake, overlay_host, "I checked with my bank, continue")
          and shadow_click(fake, overlay_host, "Continue from the FraudLens panel"))
    fake_tab = sw.evaluate("""async () => { for (const [k, v] of Object.entries(await chrome.storage.session.get(null)))
        if (k.startsWith('tab:') && v.paused) return Number(k.slice(4)); return null; }""")
    check("Pause recorded for the side panel", fake_tab is not None)
    early = sw.evaluate("(id) => HANDLERS.RELEASE_PAUSE({tabId: id})", fake_tab)
    check("Side panel can't skip the countdown", early == {"ok": False}, str(early))
    fake.wait_for_timeout(10500)
    before = fake.evaluate(HOSTS_JS)
    released = sw.evaluate("(id) => HANDLERS.RELEASE_PAUSE({tabId: id})", fake_tab)
    fake.wait_for_timeout(800)
    after = fake.evaluate(HOSTS_JS)
    fake.focus("#pw")
    fake.keyboard.type("ok")
    check("Continue from the side panel closes the pause and unlocks the page",
          released == {"ok": True} and after == before - 1 and fake.evaluate("pw.value") == "ok", f"{before}->{after}")

    # -- look-alike practice addresses
    for addr, want in [("rncb.mu", "high"), ("netflix-account-billing.com", "high"), ("paypal-login.xyz", "high"),
                       ("news.example.org", None)]:
        p = ctx.new_page()
        p.goto(f"{BASE}/demo/login.html#as={addr}")
        p.wait_for_timeout(3000)
        it = next((i for i in items() if i["kind"] == "page" and i.get("host") == addr), None)
        banners = p.evaluate(HOSTS_JS)
        if want:
            check(f"Look-alike practice: {addr} warned", it and it["level"] == want and banners >= 1,
                  it and it["reasons"][0][:80])
        else:
            check(f"Look-alike practice: {addr} (normal) stays quiet", it is None and banners == 0)
        if addr == "rncb.mu":
            p.screenshot(path=str(SHOTS / "05_lookalike_rncb.png"))
        p.close()
    own = ctx.new_page()
    own.goto(f"{BASE}/health")
    own.wait_for_timeout(1500)
    check("The FraudLens server itself is never flagged", not [i for i in items() if i.get("host") == HOST] and own.evaluate(HOSTS_JS) == 0)
    own.close()

    # -- hostile page on the server's own address
    log_before = (tmp / "server.log").read_text()
    atk = ctx.new_page()
    atk.goto(f"{BASE}/demo/attacks.html")
    atk.wait_for_timeout(12000)
    res = atk.inner_text("#results")
    check("Attack page can't message the extension", "available to page: false" in res)
    check("Attack page can't use the server's lookups", "succeeded: 0 / 25" in res, res.splitlines()[-1] if res else "")
    new_log = (tmp / "server.log").read_text()[len(log_before):]
    check("Server did no lookups for the page", not [l for l in new_log.splitlines() if "/intel/" in l and " 200" in l])
    check("Removing the warning is detected", any(i["kind"] == "tamper" for i in items()))
    check("Badge still warns after the page deleted the banner", badge_where("i => i.kind === 'tamper'") == "!")
    atk.screenshot(path=str(SHOTS / "06_attack_page.png"), full_page=True)

    # -- side panel (opened in a tab for inspection)
    panel = ctx.new_page()
    panel.goto(f"chrome-extension://{ext_id}/sidepanel/sidepanel.html")
    panel.wait_for_timeout(1500)
    check("Panel: connected, no connect card", panel.is_hidden("#connectCard") and panel.inner_text("#connText") == "Connected",
          panel.inner_text("#connText"))
    xss = ('<img src=x onerror="document.title=\'pwned\'"> MCB ALERT: your account is suspended. '
           'Verify within 2 hours at http://mcb-secure-verify.com/login and send the OTP.')
    panel.fill("#paste", xss)
    panel.click("#checkBtn")
    wait_until(panel, "() => document.querySelectorAll('#result mark').length > 0", timeout=30000)
    check("Panel shows text as text (no HTML injection)", panel.evaluate("document.querySelectorAll('#result img').length") == 0
          and panel.title() != "pwned" and "<img" in panel.inner_text("#result"))
    check("Panel shows the Scam X-Ray", True)
    panel.screenshot(path=str(SHOTS / "07_side_panel.png"), full_page=True)
    forged = panel.evaluate("""async () => [
        await chrome.runtime.sendMessage({type: 'SCAN_TEXT', text: 'x'.repeat(20), channel: 'email'}),
        await chrome.runtime.sendMessage({type: 'FETCH', url: 'https://evil.example'}),
        await chrome.runtime.sendMessage({type: 'SAVE_SETTINGS', apiBase: 'https://x.example', evil: 1})]""")
    check("Service worker rejects forged / unknown / malformed messages", all(f and f.get("error") == "rejected" for f in forged), json.dumps(forged))

    # -- live learning (one report is enough on the demo server)
    scam = ("Bonzour! Nou pe rekrite pou enn travay depi lakaz ek ou telefonn, Rs 3000 par zour. "
            "Pey Rs 500 pou lenskripsion lor Juice 5871 2233 zordi mem.")
    reworded = ("Bonzour! Nou pe rekrite pou enn travay depi lakaz ar ou telefonn, Rs 3500 par zour. "
                "Pey Rs 600 pou lenskripsion lor Juice 5871 2244 zordi.")
    panel.fill("#paste", scam)
    panel.click("#checkBtn")
    panel.wait_for_timeout(4000)
    labels = panel.locator("#result .actions button").all_inner_texts()
    yes = "Yes, it's a scam" if "Yes, it's a scam" in labels else "No, it's a scam"
    panel.locator("#result .actions button", has_text=yes).click()
    wait_until(panel, "() => document.querySelector('#result .msg').textContent.length > 10", timeout=20000)
    reply = panel.inner_text("#result .msg")
    locked = panel.evaluate("[...document.querySelectorAll('#result .actions button')].every(b => b.disabled)")
    check("Learning: one answer, both buttons lock", locked and len(reply) > 10, reply[:80])
    panel.fill("#paste", reworded)
    panel.click("#checkBtn")
    panel.wait_for_timeout(4000)
    check("Live learning: reworded scam caught by scam memory", "reported by a FraudLens user" in panel.inner_text("#result"),
          panel.inner_text("#result")[:160].replace("\n", " | "))

    panel.fill("#paste", "MCB ALERT: account suspended. Verify now at http://mcb-secure-verify.com/login or on https://www.mcb.mu and send the OTP.")
    panel.click("#checkBtn")
    wait_until(panel, "() => document.getElementById('checkBtn').textContent === 'Check'", timeout=60000)
    tainted = session().get("tainted", {})
    check("A scam that also links the REAL bank never marks the real bank", "mcb.mu" not in tainted and "mcb-secure-verify.com" in tainted,
          ", ".join(tainted))

    panel.click("#settings summary")
    panel.click("#servicesBtn")
    wait_until(panel, "() => document.querySelectorAll('#services .svc').length > 0", timeout=60000)
    check("Settings: 'Check services' shows the list", panel.evaluate("document.querySelectorAll('#services .svc').length") >= 8)
    panel.screenshot(path=str(SHOTS / "08_services.png"), full_page=True)

    # -- the free server falls asleep and wakes up while a check is waiting
    stop_server()
    panel.fill("#paste", "URGENT: MCB account blocked. Verify at http://mcb-secure-verify.com/login within 1 hour and send the OTP.")
    panel.click("#checkBtn")
    panel.wait_for_timeout(4000)
    state = sw.evaluate("chrome.storage.session.get('serverState').then(s => s.serverState && s.serverState.state)")
    check("Server asleep: panel shows 'Waking up…'", state == "waking" and "Waking" in panel.inner_text("#connText"), f"{state}")
    panel.screenshot(path=str(SHOTS / "09_waking.png"))
    time.sleep(8)
    start_server(tmp, key, crt, SECRET_A)
    wait_until(panel, "() => document.getElementById('checkBtn').textContent === 'Check'", timeout=150000)
    txt = panel.inner_text("#result")
    check("Server woke up: the waiting check got a real verdict", "Likely scam" in txt and "couldn't verify" not in txt.lower(), txt[:100].replace("\n", " | "))
    check("Panel back to 'Connected'", panel.inner_text("#connText") == "Connected")

    # -- server redeployed with a new secret: the extension registers again by itself
    stop_server()
    start_server(tmp, key, crt, SECRET_B)
    panel.fill("#paste", "Mauritius Post: parcel MU2849 held at customs, pay Rs 95 today at http://mupost-fee.top/pay")
    panel.click("#checkBtn")
    wait_until(panel, "() => document.getElementById('checkBtn').textContent === 'Check'", timeout=60000)
    check("New server secret: extension re-registers automatically", "Likely scam" in panel.inner_text("#result") or "Be careful" in panel.inner_text("#result"),
          panel.inner_text("#result")[:80].replace("\n", " | "))
    hwm = server_hwm_mb()
    check("Server memory stays well under the free 512 MB", 200 < hwm < 430, f"{hwm} MB peak")

    # -- server really down: fail safe, never "safe"
    stop_server()
    t0 = time.time()
    panel.fill("#paste", "URGENT: your parcel is held, pay Rs 150 customs fee now at http://colis-mu.top/pay")
    panel.click("#checkBtn")
    wait_until(panel, "() => document.getElementById('checkBtn').textContent === 'Check'", timeout=200000)
    waited = time.time() - t0
    txt = panel.inner_text("#result").lower()
    check("Server down: \"Couldn't verify\", never \"safe\" (after trying to wake it)", "couldn't verify" in txt and "does not mean" in txt, f"{waited:.0f}s")
    t0 = time.time()
    panel.fill("#paste", "Another message: pay Rs 99 at http://colis-mu.top/pay2 now")
    panel.click("#checkBtn")
    wait_until(panel, "() => document.getElementById('checkBtn').textContent === 'Check'", timeout=60000)
    check("...and the next check answers at once (no second long wait)", time.time() - t0 < 30 and "couldn't verify" in panel.inner_text("#result").lower(), f"{time.time() - t0:.0f}s")
    panel.screenshot(path=str(SHOTS / "10_server_down.png"), full_page=True)
    ctx.close()
    start_server(tmp, key, crt, SECRET_B)


# ---- phase 2: "Protect every site" on, connect from the side panel ------------------------------------
def phase2(pw, tmp: Path) -> None:
    ext = test_copy(tmp, "ext2", ["<all_urls>", "http://localhost/*", "http://*.localhost/*"])
    ctx = launch(pw, tmp, ext, "profile2")
    sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker", timeout=20000)
    session, items, badge_where = tools(ctx, sw)
    ctx.pages[0].wait_for_timeout(6000)
    for p in ctx.pages:
        if "welcome" in p.url:
            p.close()
    panel = ctx.new_page()
    panel.goto(f"chrome-extension://{PINNED_ID}/sidepanel/sidepanel.html")
    panel.wait_for_timeout(1200)
    check("Panel before connecting: shows the connect card", panel.is_visible("#connectCard") and panel.inner_text("#connText") == "Not connected")
    panel.fill("#connectInput", BASE)
    panel.click("#connectBtn")
    wait_until(panel, "() => document.getElementById('connectOut').textContent.startsWith('✓')", timeout=90000)
    panel.wait_for_timeout(800)
    check("Panel: Connect works and the card disappears", panel.is_hidden("#connectCard"))
    scripts = sw.evaluate("chrome.scripting.getRegisteredContentScripts().then(s => Object.fromEntries(s.map(x => [x.id, x.matches])))")
    check("Every-site protection registered", "<all_urls>" in scripts.get("fl-guard", []), json.dumps(scripts))

    dead = ctx.new_page()
    try:
        dead.goto("http://rncb.mu/", timeout=15000)
    except Exception:
        pass   # doesn't exist: Chrome shows its own error page
    dead.wait_for_timeout(4000)
    d = next((i for i in items() if i["kind"] == "page" and i.get("host") == "rncb.mu"), None)
    check("Dead look-alike site (Chrome error page) still flagged", d and d["level"] == "high", d and d["reasons"][0][:70])
    check("...with the toolbar badge", badge_where("i => i.host === 'rncb.mu'") == "!")
    for host, want in [("netflixde.localhost", True), ("paypal-login.localhost", True), ("news.localhost", False)]:
        p = ctx.new_page()
        p.goto(f"http://{host}:8765/login.html")
        p.wait_for_timeout(3000)
        it = next((i for i in items() if i["kind"] == "page" and i.get("host") == host), None)
        if want:
            check(f"Real website {host}: warned", it and it["level"] == "high" and p.evaluate(HOSTS_JS) >= 1)
        else:
            check(f"Real website {host}: normal, quiet", it is None and p.evaluate(HOSTS_JS) == 0)
        p.close()
    p = ctx.new_page()
    p.goto("http://localhost:8765/login.html#as=rncb.mu")
    p.wait_for_timeout(3000)
    check("Pretend addresses are ignored on other websites (only the FraudLens server's practice pages)",
          p.evaluate(HOSTS_JS) == 0 and not [i for i in items() if i.get("host") == "rncb.mu" and i.get("practice")])
    p.close()
    p = ctx.new_page()
    p.goto(f"{BASE}/demo/login.html#as=rncb.mu")
    p.wait_for_timeout(3500)
    check("Practice page with every-site protection: exactly one banner", p.evaluate(HOSTS_JS) == 1, str(p.evaluate(HOSTS_JS)))
    p.close()
    # a practice page pretending to be paypal-login.localhost is released from the side panel...
    p = ctx.new_page()
    p.goto(f"{BASE}/demo/login.html#as=paypal-login.localhost")
    p.wait_for_timeout(3000)
    p.focus("#user")
    p.wait_for_timeout(11500)
    tab = sw.evaluate("""async () => { for (const [k, v] of Object.entries(await chrome.storage.session.get(null)))
        if (k.startsWith('tab:') && v.paused) return Number(k.slice(4)); return null; }""")
    rel = sw.evaluate("(id) => HANDLERS.RELEASE_PAUSE({tabId: id})", tab)
    p.close()
    # ...which must NOT switch off the pause on the real website with that name
    real = ctx.new_page()
    real.goto("http://paypal-login.localhost:8765/login.html")
    real.wait_for_timeout(3000)
    real.focus("#user")
    real.wait_for_timeout(800)
    check("Releasing a practice page never releases the real site", rel == {"ok": True}
          and real.evaluate("document.activeElement && document.activeElement.id") != "user")
    # fields inside a web component's shadow DOM are paused too
    shadow = ctx.new_page()
    shadow.goto("http://netflixde.localhost:8765/login.html")
    shadow.wait_for_timeout(3000)
    shadow.evaluate("""() => { const h = document.createElement('div'); document.body.append(h);
        const r = h.attachShadow({mode: 'open'}); r.innerHTML = '<input id="cc" name="x">'; window.__cc = r.getElementById('cc'); }""")
    shadow.evaluate("() => window.__cc.focus()")
    shadow.wait_for_timeout(800)
    check("Fields inside shadow DOM are paused too", shadow.evaluate("() => window.__cc.getRootNode().activeElement !== window.__cc"))
    ctx.close()


# ---- phase 3: Plan B, the server on this computer (what RUN_SERVER_ON_THIS_PC.bat does) ------------------
def tree(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*")}


def phase3(pw, tmp: Path) -> None:
    server = V2 / "1-server"
    before = tree(server)
    models, data = tmp / "local-models", tmp / "local-data"
    shutil.copytree(server / "models", models, ignore=shutil.ignore_patterns("onnx", "tokenizer.json", "model.onnx"))
    (models / "multilingual-e5-small" / "onnx").mkdir(parents=True)
    shutil.copy(SERVER_DIR / "models" / "multilingual-e5-small" / "onnx" / "model_quantized.onnx",
                models / "multilingual-e5-small" / "onnx" / "model_quantized.onnx")
    shutil.copytree(server / "data" / "seed", data / "seed")
    keys = tmp / "MY_KEYS.txt"
    keys.write_text("# test keys file\nFRAUDLENS_REPORT_CONFIRMATIONS=3\nFRAUDLENS_VIRUSTOTAL_KEY=\n", encoding="ascii")
    env = {**os.environ, "FRAUDLENS_DATA_DIR": str(data), "FRAUDLENS_MODELS_DIR": str(models),
           "FRAUDLENS_ENV_FILE": str(keys), "FRAUDLENS_REQUIRE_INSTALL_TOKEN": "true", "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONIOENCODING": "utf-8"}
    log = open(tmp / "local.log", "w")
    proc = subprocess.Popen([PYTHON, "-B", "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
                            cwd=server, env=env, stdout=log, stderr=log)
    try:
        wait_port(8000)
        import urllib.request
        health = json.loads(urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=10).read())
        check("Plan B: server on this computer reads MY_KEYS.txt", health["ml"]["memory"]["confirmations_required"] == 3)
        check("Plan B: full AI model loaded", health["ml"]["embedder"] == "e5-small-onnx" and health["ml"]["url_model"])
        # the REAL extension folder, unmodified: 127.0.0.1:8000 is allowed in its manifest
        ctx = pw.chromium.launch_persistent_context(
            str(tmp / "profile3"), headless=False, viewport={"width": 1200, "height": 900},
            args=[f"--disable-extensions-except={EXT_SRC}", f"--load-extension={EXT_SRC}", "--no-first-run", "--no-proxy-server"])
        sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker", timeout=20000)
        session, items, badge_where = tools(ctx, sw)
        panel = ctx.new_page()
        panel.goto(f"chrome-extension://{PINNED_ID}/sidepanel/sidepanel.html")
        panel.wait_for_timeout(1000)
        panel.fill("#connectInput", "127.0.0.1:8000")
        panel.click("#connectBtn")
        wait_until(panel, "() => document.getElementById('connectOut').textContent.startsWith('✓')", timeout=60000)
        check("Plan B: unmodified extension connects to 127.0.0.1:8000", True, panel.inner_text("#connectOut"))
        inbox = ctx.new_page()
        inbox.goto("http://127.0.0.1:8000/demo/inbox.html")
        inbox.wait_for_timeout(10000)
        flagged = [i for i in items() if i["kind"] == "message" and i["level"] == "high"]
        check("Plan B: practice inbox warns", len(flagged) >= 5 and inbox.evaluate(HOSTS_JS) >= 5, f"{len(flagged)} high")
        ctx.close()
    finally:
        proc.terminate()
        proc.wait(15)
    added = sorted(tree(server) - before)
    check("Plan B writes nothing inside 1-server (safe to upload to GitHub)", not added, ", ".join(added[:5]))


if __name__ == "__main__":
    sys.exit(main())
