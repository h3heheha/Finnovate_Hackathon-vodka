# FraudLens: phone demo plan

Goal: show every feature live on your own Android phone (Android 10 or newer): Shield working in the background (messages and calls), the full app, and the backend-only features.

What's where: **one app on the phone, one server on the laptop.**

| Piece | Runs on | You open it with |
|---|---|---|
| FraudLens server (API + the app's screens) | Laptop | `run_backend.bat` |
| **FraudLens app** → 🔍 **FraudLens** tab (Scan, Learn, History…) | Phone (screens come from the laptop) | The **FraudLens** icon |
| **FraudLens app** → 🛡️ **Shield** tab (background protection) | Phone | Same app, bottom tab |

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
5. Plug the phone in by USB, pick it in the device list and press **▶ Run**. **FraudLens** installs and opens on its **Shield** tab.
   - To get an APK file instead, use **Build → Build APK(s)**, or double-click `shield\build_apk.bat` (writes `shield\FraudLens.apk`, install with `adb install -r shield\FraudLens.apk`).
6. **In the Shield tab, tap each Enable button:**
   1. Read notifications: on. If it's greyed out, go to **Settings → Apps → FraudLens → ⋮ → Allow restricted settings**.
   2. Notifications: **Allow**.
   3. Display over other apps: on.
   4. Check incoming calls: **Set as default** caller ID & spam app. On Samsung: **Settings → Apps → Default apps → Caller ID & spam app**.
   5. Battery: **Unrestricted**.

## Phase 3: Connect phone and laptop (each time)

1. Turn on your **phone's hotspot** and connect the laptop to it.
2. On the laptop, run `ipconfig` and note the **IPv4 Address**, for example `192.168.43.12`.
3. Start `run_backend.bat`.
4. **In FraudLens → Shield tab:** enter `http://192.168.43.12:8000` and tap **Save & test connection**. It should say ✅ Connected.
5. **Tap the 🔍 FraudLens tab:** the landing animation plays, then **Get started** → Home. (No Chrome and no `chrome://flags` needed any more.)
6. **Remove your helper friend from your phone contacts.** Saved contacts are never screened.
7. **Mirror the phone to the projector:** run `scrcpy` over USB on the laptop.

## Phase 4: Rehearsal checklist (tick every line)

### Shield: the phone reacts on its own
Stay on the home screen, not inside a chat.

- [ ] **A1 SMS** from your friend: *"MCB: Your card has been blocked due to suspicious activity. Confirm your details within 24h: https://bit.ly/mcb-verify-now . Do not share this message."*
  - Expect: a notification and red banner. Tap **See why** for the Scam X-Ray, then **Report as scam**.
- [ ] **A2 WhatsApp:** *"Salam, mo finn perdi mo telefonn, sa mo nouvo nimero. Avoy Rs 3000 lor my.t money urgent"*
  - Expect: a warning.
- [ ] **A3 Email to your Gmail:** subject "Parcel held", body *"Pay the Rs 95 customs fee today: http://mauritius-post-colis.top/pay"*
  - Expect: a warning.
- [ ] **A4 Genuine SMS:** *"Your Juice verification code is 482915. Never share this code with anyone."*
  - Expect: **no alert.**
- [ ] **A5 Chat:** *"See you at 7 for dinner?"*
  - Expect: nothing (it's filtered on the phone and never sent anywhere).
- [ ] **A6 Friend calls you** after A1 and A2:
  - Expect: **"Likely scam caller"** while it rings.
- [ ] **A7 See why → Open FraudLens**
  - Expect: the FraudLens app comes to the front on its **FraudLens** tab.
- [ ] **A8 Check copied text:** copy the A1 text, then **Shield tab → 📋 Check copied text**.
  - Expect: the Scam X-Ray opens.
- [ ] **Backups:** the Shield tab's **Send a test scam alert** and **Test a caller check** buttons work.

### The app (🔍 FraudLens tab)
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
- [ ] **Home → Paste and scan:** long-press the message box → Paste (or use A8). The paste button itself needs HTTPS, so inside the app it shows a hint instead.
- [ ] **Learn:** a quiz answer and two lessons open. **History:** the counters, and a past check reopens.
- [ ] **Home → Verified contacts, Ask someone you trust, Shield in the background, Server settings** each open. Shield in the background says "Turn it on once in the Shield tab".
- [ ] **Offline fallback:**
  - In Server settings, enter `http://1.2.3.4:8000` and tap Save & test. The chip shows OFFLINE DEMO and the examples still work.
  - **Set it back to `http://127.0.0.1:8000`.**

### Backend-only features (`http://<laptop-IP>:8000/docs` → Try it out)
- [ ] **Pause-Before-Pay:** `POST /api/v1/payments/check` with
  `{"payee_name":"Invest Group","payee_account":"000123456789","amount":45000,"is_saved_payee":false}`.
  Expect `pause` or `warn` with reasons.
- [ ] **Scam Radar:** `GET /api/v1/radar` shows trends from everything scanned today.
- [ ] **Caller lookup:** `GET /api/v1/intel/phone?number=<friend's number>`.
- [ ] **Models:** `GET /api/v1/models` shows versions and memory size.

## Phase 5: On stage (about 6 min)

1. **Open FraudLens → landing → Home:** "One app. FraudLens protects you in the background, even when the app is closed." Show the **Shield** tab for two seconds (all ✅), then back.
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
| FraudLens tab: "Can't reach the FraudLens server" | Same as the next row. Fix the address in the Shield tab, then tap **Retry**. |
| Shield: "Can't reach server" | The laptop IP changed (run `ipconfig` again), the server isn't running, or the firewall isn't allowing Python on private networks. |
| No message warning | Notification access is off, you're inside the chat, the same text was sent within the last 10 minutes, or Messages spam protection hid it. |
| No call warning | The caller role isn't set, the caller is a saved contact, or **the server restarted** (reputations reset). Redo A1 and A2. |
| Paste does nothing | Long-press the message box → Paste, or **Shield tab → 📋 Check copied text**. |
| "Too many checks from this device" | The rate limit was hit during rapid testing. Wait 1 minute, or raise `FRAUDLENS_RATE_LIMIT_PER_MINUTE`. |
| The FraudLens tab freezes | **Long-press the 🔍 FraudLens tab** to reload it. Fallback: run the demo from the laptop at `http://localhost:8000/`. |

**After the hackathon:** delete the keys from `backend/.env` and `.env.example` and create new ones.
