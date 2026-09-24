# FraudLens: phone demo plan

Goal: show every feature live on your own Android phone (Android 10 or newer): Shield working in the background (messages and calls), the full app, and the backend-only features.

What's where: **one app on the phone, one server on the laptop.**

| Piece | Runs on | You open it with |
|---|---|---|
| FraudLens server (API + the app's screens) | Laptop | `run_backend.bat` |
| **FraudLens app**: Home, Scan, Learn, History (native) | Phone | The **FraudLens** icon |
| **FraudLens app**: Shield tab (background protection) | Phone | Same app, fifth tab in the dock |
| Web version of the app (backup demo) | Laptop browser | `http://localhost:8000/` |

---

## Phase 1: Laptop setup (day before, about 45 min)

1. **Unzip** `fraudlens_final.zip`, for example to `C:\FraudLens\fraudlens`.
2. **Install Python 3.11 or 3.12** from python.org, and tick *Add to PATH*.
3. **Create the environment:**
   ```bat
   cd C:\FraudLens\fraudlens\backend
   py -3.11 -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```
4. **Models:**
   - Copy `backend\models\multilingual-e5-small` and `backend\models\phishing-url-detection` from your old project folder,
   - or run `python -m scripts.setup_ml`.
5. **Configure `backend\.env`:**
   - `FRAUDLENS_REPORT_CONFIRMATIONS=1` is **already set** (demo mode: one report is enough on stage). Set it back to 2 after the hackathon, as explained in `SECURITY.md`.
   - Optionally set `FRAUDLENS_RATE_LIMIT_PER_MINUTE=60` for rehearsals. The default of 30 is plenty for the demo.
   - Your API keys (Safe Browsing, URLhaus, Telesign/IPQS) are already in it. Nothing to change.
6. **Test the server:**
   - Run `python -m scripts.check_intel`; each provider should print `ok`.
   - Run `run_backend.bat`. Windows Firewall asks: tick **Private** and click **Allow**.
   - In the laptop browser, `http://localhost:8000/` shows the app and `http://localhost:8000/health` shows `"status":"ok"`.

## Phase 2: Build and install the FraudLens app (day before, about 30 min)

1. Install **Android Studio**, open it once, and let it download the SDK.
2. **File → Open → `fraudlens\shield`**, and wait for Gradle sync.
3. On the phone, turn on developer mode:
   - **Settings → About phone → Build number**: tap it 7 times.
   - **Developer options → USB debugging**: on.
4. **Uninstall the old separate apps:** the Flet "FraudLens" app (`adb uninstall com.fraudlens.fraudlens`). The old "FraudLens Shield" is upgraded in place; if Android refuses ("signature doesn't match"), uninstall it too (`adb uninstall com.fraudlens.shield`).
5. Plug the phone in by USB, pick it in the device list and press **▶ Run**. **FraudLens** installs and opens on the landing screen → **Get started** → Home.
   - To get an APK file instead, use **Build → Build APK(s)**, or double-click `shield\build_apk.bat` (writes `shield\FraudLens.apk`, install with `adb install -r shield\FraudLens.apk`).
6. **Open the Shield tab (fifth in the dock) and tap each Enable button:**
   1. Read notifications: on. If it's greyed out, go to **Settings → Apps → FraudLens → ⋮ → Allow restricted settings**.
   2. Notifications: **Allow**.
   3. Display over other apps: on.
   4. Check incoming calls: **Set as default** caller ID & spam app. On Samsung: **Settings → Apps → Default apps → Caller ID & spam app**.
   5. Battery: **Unrestricted**.

## Phase 3: Connect phone and laptop (each time)

1. Turn on your **phone's hotspot** and connect the laptop to it.
2. On the laptop, run `ipconfig` and note the **IPv4 Address**, for example `192.168.43.12`.
3. Start `run_backend.bat`.
4. **In FraudLens, tap ⚙ (top right) → Settings:** enter `http://192.168.43.12:8000` and tap **Save & test**. It should say Connected, and the chip turns **ONLINE**.
5. While you're there, set **Trusted contact** (name and number) for the "Ask someone you trust" demo.
6. **Remove your helper friend from your phone contacts.** Saved contacts are never screened.
7. **Mirror the phone to the projector:** run `scrcpy` over USB on the laptop.

## Phase 4: Rehearsal checklist (tick every line)

### Shield: the phone reacts on its own
Stay on the home screen, not inside a chat. For the demo, turn on **Shield tab → Check every message (demo mode)**.
After each test, **Shield tab → What Shield saw** shows what happened (Warned / Checked / Skipped / Error).

- [ ] **A1 SMS** from your friend: *"MCB: Your card has been blocked due to suspicious activity. Confirm your details within 24h: https://bit.ly/mcb-verify-now . Do not share this message."*
  - Expect: a notification and red banner. Tap **See why** for the Scam X-Ray, then **Report as scam**.
- [ ] **A2 WhatsApp:** *"Salam, mo finn perdi mo telefonn, sa mo nouvo nimero. Avoy Rs 3000 lor my.t money urgent"*
  - Expect: a warning.
- [ ] **A3 Email to your Gmail:** subject "Parcel held", body *"Pay the Rs 95 customs fee today: http://mauritius-post-colis.top/pay"*
  - Expect: a warning.
- [ ] **A4 Genuine SMS:** *"MCB: Your OTP for the online payment of Rs 1,250.00 at DARTY is 482913. Never share this code with anyone, including MCB staff."*
  - Expect: **no alert.** (A bare "your code is 482915" from a personal mobile number *is* suspicious, so FraudLens flags that one.)
- [ ] **A5 Chat:** *"See you at 7 for dinner?"*
  - Expect: nothing (it's filtered on the phone and never sent anywhere).
- [ ] **A6 Friend calls you** after A1 and A2:
  - Expect: **"Likely scam caller"** while it rings.
- [ ] **A7 See why → Open FraudLens**
  - Expect: FraudLens opens on **History**, with the alert at the top.
- [ ] **A8 Share to FraudLens:** in Messages, long-press the A1 SMS → **Share** → **FraudLens**.
  - Expect: FraudLens opens on Scan and shows the result straight away.
- [ ] **Backups:** the Shield tab's **Send a test scam alert** and **Test a caller check** buttons work.

### The app (Home, Scan, Learn, History)
- [ ] **Landing:** animation, then **Get started**, then Home.
- [ ] **Try a real example:** all 8. The 6 scams are high or medium; the genuine OTP and the chat are low.
- [ ] **On a scam result:**
  - X-Ray highlights, a warning sign expanded, "Dangerous combinations".
  - **Official contact**, **Ask guardian**, **Copy reply**.
  - **How FraudLens decided**, including **Closest known messages**.
- [ ] **Security databases:** scan *"Your account is locked, verify here: http://malware.testing.google.test/testing/malware/"*.
  - Expect: a red blocklist card.
- [ ] **Short link:** a message with a real `bit.ly` link shows "really goes to …".
- [ ] **Live learning:**
  - Scan *"Good evening, I'm Karen from the members desk. Our group made 12,000 last month from home with a simple app. Shall I add you so you can start tonight?"*, which scores low or medium.
  - Tap **Report scam**.
  - Scan a reworded or French version. It should score 85 or more and say it matches a reported scam.
- [ ] **It's genuine** on a genuine message.
- [ ] **Home → Paste and scan** with a copied scam text, and the 📋 button on Scan.
- [ ] **Learn:** a quiz answer and two lessons open. **History:** the counters, and a past check reopens.
- [ ] **Home → Verified contacts** (tap a number: the dialler opens), **Ask someone you trust** (Send by SMS / Share), **Shield in the background** (opens the Shield tab), **Settings**.
- [ ] **History:** filters All / Your checks / Shield alerts; tap an item for its full result.
- [ ] **Offline fallback:**
  - In Settings, enter `http://1.2.3.4:8000` and tap Save & test. The chip shows OFFLINE DEMO and the examples still work.
  - **Set it back to your laptop address** (`http://192.168.43.12:8000`).

### Backend-only features (`http://<laptop-IP>:8000/docs` → Try it out)
- [ ] **Pause-Before-Pay:** `POST /api/v1/payments/check` with
  `{"payee_name":"Invest Group","payee_account":"000123456789","amount":45000,"is_saved_payee":false}`.
  Expect `pause` or `warn` with reasons.
- [ ] **Scam Radar:** `GET /api/v1/radar` shows trends from everything scanned today.
- [ ] **Caller lookup:** `GET /api/v1/intel/phone?number=<friend's number>`.
- [ ] **Models:** `GET /api/v1/models` shows versions and memory size.

## Phase 5: On stage (about 6 min)

1. **Open FraudLens → landing → Home:** "One app. FraudLens protects you in the background, even when the app is closed." The Home card says **Shield · running in background**; tap it to show the Shield tab (all ✅).
2. **Scam SMS arrives (A1):** banner, **See why**, **Report as scam**.
3. **WhatsApp scam arrives (A2):** "every channel, even Kreol."
4. **Friend calls (A6):** the caller warning appears while the phone rings. "It learnt this number from the two messages."
5. **Genuine OTP arrives (A4):** no alert. "No false alarms, and private chats never leave the phone."
6. **App, live learning:** the Karen message, **Report**, then the reworded version is caught.
7. **Security databases:** the blocklist card for the test link.
8. **`/docs`:** Pause-Before-Pay and the Scam Radar.
9. **Learn:** one quiz question. Close.

## If something goes wrong

| Problem | Fix |
|---|---|
| Chip says OFFLINE DEMO | Same as the next row. Tap the chip → fix the address → **Save & test**. |
| Shield: "Can't reach server" | The laptop IP changed (run `ipconfig` again), the server isn't running, or the firewall isn't allowing Python on private networks. |
| No message warning | Look at **Shield tab → What Shield saw**. Nothing listed: the app posted no notification (you were inside the chat, Gmail put the email in Spam/Promotions, or Messages spam protection hid it), or notification access is off. "Skipped": turn on demo mode. "Error": check the server address. |
| No call warning | The caller role isn't set, the caller is a saved contact, or **the server restarted** (reputations reset). Redo A1 and A2. Unknown callers are only flagged on real evidence (FraudLens reports, fraud-linked, VoIP or premium-rate numbers). |
| "Clipboard is empty" | Copy the message first (long-press → Copy), or share it to FraudLens instead. |
| "Too many checks from this device" | The rate limit was hit during rapid testing. Wait 1 minute, or raise `FRAUDLENS_RATE_LIMIT_PER_MINUTE`. |
| A screen looks wrong | Swipe FraudLens away in Recents and reopen it. Fallback: run the demo from the laptop at `http://localhost:8000/`. |

**After the hackathon:** delete the keys from `backend/.env` and `.env.example` and create new ones.
