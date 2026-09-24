# The FraudLens Android app (native, Shield built in)

This `shield/` folder is **the** FraudLens Android app: one native app (Kotlin, plain Android views, no WebView) with five tabs in a floating dock.

| Tab | What it does |
|---|---|
| **Home** | Shield's status at a glance, "Scan a message", your numbers, and a menu of every feature. |
| **Scan** | Paste or type a message (native paste works), or tap one of the 8 real examples. Shows the full result: Scam X-Ray, what to do now, warning signs, threat intelligence, how FraudLens decided, reply safely, report scam / it's genuine. |
| **Learn** | Spot-the-scam quiz and 30-second lessons on every trick. |
| **History** | Everything you checked **and** everything Shield caught, with filters. Tap any item for its full result. |
| **Shield** | Background protection: status, on/off switch, setup steps, test buttons, recent alerts, how it works, server. The notification listener and call screener in this same APK do the work, even when the app is closed. |

Also built in:
- **Share → FraudLens** from WhatsApp, Messages or Gmail (long-press a message → Share), and **Check with FraudLens** in the text-selection menu of any app. The message is checked straight away.
- **Verified contacts** with tap-to-call official numbers, **Ask someone you trust** (send by SMS or share to WhatsApp, with the message included), and **Settings** for the server address and your trusted contact.
- **Offline demo:** if the server can't be reached, the 8 examples still return their full results, and the last downloaded lessons, quiz and contacts are kept on the phone.
- "See why" on a Shield warning opens the same full result screen.

The laptop server still does the AI checking, exactly as before. The web version at `http://<laptop>:8000/` still works as a backup demo. You don't need the separate Flet APK (`com.fraudlens.fraudlens`); uninstall it.

> **Quick path:** this folder is a complete Android Studio project.
> 1. Install Android Studio (default options), open it once, and let it finish downloading the Android SDK.
> 2. **File → Open…** and choose this `shield/` folder, not the whole `fraudlens/` folder. Wait for *Gradle sync* to finish; the first time it downloads Gradle and the Android build tools, so you need internet.
> 3. Plug in your phone with USB debugging on and press the green **▶ Run**.
>    Or **Build → Build App Bundle(s) / APK(s) → Build APK(s)**, then click **locate** to find `app/build/outputs/apk/debug/app-debug.apk`.
> 4. From the command line instead: double-click **`build_apk.bat`**. It writes `FraudLens.apk` next to itself.
>
> The package is still `com.fraudlens.shield`, so it installs **over** an earlier Shield build and keeps the permissions you already gave. If Android says the signature doesn't match, uninstall the old Shield first.
> If Android Studio offers to upgrade the Android Gradle Plugin, accept. Sections 1–2 below, which create an empty project and paste the files in, are only needed if opening the folder doesn't work.

Shield sleeps until Android hands it a new notification (SMS, WhatsApp, email) or a ringing call. It checks suspicious ones with the FraudLens server on the laptop and warns straight away:
- a heads-up notification
- a red banner over the current app
- a "See why" Scam X-Ray screen

**You don't need to write any Kotlin.**

```
shield/app/src/main/
├── AndroidManifest.xml                  ← replaces the one Android Studio makes
└── java/com/fraudlens/shield/
    ├── MainActivity.kt                  ← replaces the one Android Studio makes: dock, top bar, share-in
    ├── Tabs.kt  Tabs2.kt  ShieldTab.kt     Home, Scan / Learn, History / Shield screens
    ├── ResultPanel.kt                      the full result (used by Scan, History and "See why")
    ├── WelcomeView.kt  Sheets.kt           landing screen / bottom sheets (contacts, trusted person, settings)
    ├── Theme.kt  Kit.kt  Icons.kt          design system: Clean Dark Slate tokens, components, Material icons
    ├── Repo.kt                             data, offline demo, background threads
    ├── DetailActivity.kt                   full result screen ("See why", History items)
    ├── ShieldNotificationListener.kt       reads new SMS / WhatsApp / email notifications
    ├── ShieldCallScreeningService.kt       checks the caller while the phone rings
    ├── Alerts.kt  OverlayBanner.kt         the warning notification + red banner
    ├── ApiClient.kt  Prefilter.kt          server calls + on-phone quick filter
    └── Prefs.kt  Ui.kt                     settings + screen helpers
```

The app uses only built-in Android classes, so there are no libraries to add. Fonts (Inter, JetBrains Mono, a small Material Icons subset) and the offline demo data are in `app/src/main/assets/`. The design follows the same tokens as the web version (`mobile/DESIGN_SPEC.md`).

---

## 1. Create the project (5 min)

1. Open Android Studio and choose **File → New → New Project…**
2. Under **Phone and Tablet**, pick **Empty Views Activity**.
   - Not "Empty Activity": that one is Jetpack Compose.
   - Click **Next**.
3. Fill in **exactly** these values:

   | Field | Value |
   |---|---|
   | Name | `FraudLens` |
   | Package name | `com.fraudlens.shield` ← delete what Android Studio suggests and type this |
   | Save location | anywhere, e.g. `Documents\FraudLensShield` |
   | Language | **Kotlin** |
   | Minimum SDK | **API 26 ("Oreo"; Android 8.0)** |
   | Build configuration language | leave the default (Kotlin DSL) |

4. Click **Finish**. Wait until the bottom status bar stops saying *Gradle sync…*. The first time this can take several minutes.

> Check: open **Gradle Scripts → build.gradle.kts (Module :app)**. It must say `namespace = "com.fraudlens.shield"` and `applicationId = "com.fraudlens.shield"`. If it shows something else, you mistyped the package name: delete the project and redo step 3. That is faster than renaming.

## 2. Paste in the FraudLens files (3 min)

The simplest way is to use Windows File Explorer. Android Studio picks up the changes by itself.

1. In Android Studio's left **Project** panel, open **app → kotlin+java → com.fraudlens.shield**.
   - Older versions call the folder **java** instead of **kotlin+java**.
2. Right-click **com.fraudlens.shield** and choose **Open In → Explorer**. In some versions it's **Show in Explorer**.
   - A window opens at `...\app\src\main\java\com\fraudlens\shield\` and shows `MainActivity.kt`.
3. Copy **all 10 `.kt` files** from the zip's `shield/app/src/main/java/com/fraudlens/shield/` into that folder.
   - When Windows asks, choose **Replace** for `MainActivity.kt`.
4. Go up three folders to `...\app\src\main\`. Copy the zip's `shield/app/src/main/AndroidManifest.xml` there and choose **Replace**.
5. Back in Android Studio, run **File → Sync Project with Gradle Files** (the elephant icon), then **Build → Rebuild Project**.
   - The build tab should end with **BUILD SUCCESSFUL**.

Leave the other files Android Studio created in place: `res/layout/activity_main.xml`, `themes.xml` and the test files. They're unused but harmless.

## 3. Start the FraudLens server on the laptop (2 min)

In a terminal on the laptop:
```bat
cd backend
.venv\Scripts\activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Open `http://localhost:8000/health` in the laptop browser. It should show JSON with `"status": "ok"`.

- The emulator reaches the laptop at **`http://10.0.2.2:8000`**. That is the emulator's name for "the computer I'm running on", and it is already the app's default.
- If Windows Firewall asks about Python, click **Allow**. You need that for a real phone.

## 4. Create the emulator and run (5 min)

1. Open **Device Manager** (phone icon on the right edge, or **Tools → Device Manager**) and click **+ → Create Virtual Device**.
2. Pick **Pixel 8** (any recent Pixel works) and click **Next**.
3. Choose a system image with **API 34 or 35** whose name says **Google Play** or **Google APIs**. Those include Google Messages and the Phone app.
   - Download it if needed, then **Next → Finish**.
4. In the top toolbar, choose **app** and your Pixel emulator, then press the green **▶ Run**.
   - The emulator boots and FraudLens opens on its **Shield** tab (first run).

## 5. One-time setup in the Shield tab (3 min)

The **Shield** tab lists the setup steps. Tap each **Enable** button and come back. Each ⚠️ turns into ✅.

| Step | What you'll see | What to do |
|---|---|---|
| 1. Read notifications | "Device & app notifications" / "Notification read, reply & control" list | Tap **FraudLens**, switch it on, and confirm **Allow**. |
| 2. Show warnings | Pop-up "Allow FraudLens to send you notifications?" | **Allow** |
| 3. Display over other apps | "Display over other apps" list | Switch on **FraudLens**, then press Back. |
| 4. Check incoming calls | "Set FraudLens as your default caller ID & spam app?" | **Set as default** |
| 5. Battery (optional) | Battery optimisation list | Choose **Don't optimise** or **Unrestricted** for FraudLens. |

**If step 1 is greyed out and says "Restricted setting":**
1. Go to **Settings → Apps → FraudLens**.
2. Tap **⋮** (top-right) → **Allow restricted settings** and confirm with the PIN if asked.
3. Try step 1 again.

Then, in the **FraudLens server** box:
1. Leave `http://10.0.2.2:8000` in the field.
2. Tap **Save & test connection**.
3. You should see **✅ Connected (v0.3.0) · AI: … · threat intel: safe_browsing, urlhaus, ipqs**.
4. The chip at the top right shows **ONLINE**. If it says **OFFLINE DEMO**, tap it (or ⚙) and fix the server address: the same Settings sheet is used everywhere.

## 6. Test it

### A. The button test (10 seconds)
1. In the Shield tab, tap **Send a test scam alert**.
2. After a second or two you should see:
   - a red banner at the top
   - a notification "⚠️ Likely scam from +230 5821 4470"
3. Tap **See why** to get the Scam X-Ray: highlighted tricks, threat intelligence, how the score was built and what to do.

### B. A real SMS arriving (the demo)
1. Press the emulator's **Home** button. Android doesn't post a notification while the conversation is open on screen.
2. Open **Extended Controls**:
   - Emulator in its own window: the **⋯** button at the bottom of the side toolbar.
   - Emulator inside Android Studio: the **⋮** in the Running Devices toolbar → **Extended Controls**.
3. Go to **Phone**. Set **From** to `+23058214470` and paste into the SMS box:
   ```
   MCB: Your card has been blocked due to suspicious activity. Confirm your details within 24h to avoid closure: https://bit.ly/mcb-verify-now . Do not share this message.
   ```
4. Click **Send message**. Messages shows the SMS, and within about 1–3 seconds Shield shows the warning and the red banner.

More messages to try (each one different, because identical texts are checked only once every 10 minutes):
```
Bonjour, votre colis est bloqué à la douane. Payez les frais de Rs 85 ici: http://mauritius-post-colis.top/pay
Salam, mo finn perdi mo telefonn, sa mo nouvo nimero. Avoy Rs 3000 lor my.t money urgent, mo pou rann ou demin
Hi, your Juice verification code is 482915. Never share this code with anyone.     ← genuine: no alert expected
```

### C. A scam caller (Android 10+)
The caller check uses what FraudLens users have already flagged, plus IPQualityScore. First make the number "known":
1. Do test A once (sample sender `+230 5821 4470`).
2. Do test B once from the same number.
   - That gives two high-risk scams from this number. The server keeps this in memory, so it resets when the API restarts.
3. In **Extended Controls → Phone**, enter `+23058214470` and click **Call device**.
4. While the phone rings, Shield shows "📞 Likely scam caller" with the red banner. The call itself is never blocked.

The **Test a caller check** button does the same lookup without a call.

### D. Share a message to FraudLens
In WhatsApp or Messages, long-press a message → **Share** → **FraudLens**. FraudLens opens on Scan and checks it straight away. (Or copy it and use **Home → Paste and scan**.)

## 7. On a real Android phone (optional)
1. Put the phone and the laptop on the **same Wi-Fi**. A phone hotspot works well at venues.
2. On the laptop, run `ipconfig` and note the **IPv4 Address**, e.g. `192.168.1.23`.
3. Turn on USB debugging on the phone:
   - Tap **Settings → About phone → Build number** 7 times.
   - Then go to **Settings → System → Developer options → USB debugging**.
4. Plug in the phone. It appears next to the emulator in Android Studio; press **▶ Run**.
5. In the Shield tab, set the server to `http://192.168.1.23:8000` (your IP) and tap **Save & test connection**.
6. The API must be started with `--host 0.0.0.0`, and Windows Firewall must allow Python on private networks.

## Troubleshooting

| Problem | Fix |
|---|---|
| Chip says OFFLINE DEMO | Same fixes as the next row, then tap the chip → **Save & test**. |
| ❌ Can't reach http://10.0.2.2:8000 | Is uvicorn running? Does `http://localhost:8000/health` work on the laptop? Did you tap **Save & test** after editing the URL? |
| SMS arrives but no warning | Check that setup step 1 shows ✅. Go to the Home screen before sending, so Messages posts a notification. Very short messages (under 12 characters) or messages with no link, number, money or pressure words are skipped on purpose. |
| Messages hides the SMS as spam | Open **Messages → profile picture → Messages settings → Spam protection** and switch it off on the emulator. |
| Notification appears but no red banner | Turn on setup step 3. The banner appears only for **high** risk; medium risk gets a notification only. |
| No call warning | Setup step 4 must show ✅ (Android 10+). Numbers saved in Contacts are not screened. Do the "make the number known" steps first. |
| Build error `Unresolved reference` / wrong package | `namespace` and `applicationId` in `build.gradle.kts (Module :app)` must be `com.fraudlens.shield`. Every `.kt` file must sit in `java/com/fraudlens/shield/`. |
| "Clipboard is empty" | Copy the message first (long-press → Copy). Or share it to FraudLens instead. |
| Want to see what Shield is doing | **Logcat** tab, filter `FraudLensShield`. |
| A screen looks wrong or a button does nothing | Take a screenshot (Power + Volume down) and send it. The app is built in code, so fixes are quick. |

## Why it is built this way (for the pitch)

- **No battery drain:** there's no background loop and no foreground service. Android wakes Shield only when a notification arrives or a call rings.
- **Private by design:**
  - An on-phone prefilter decides in milliseconds. Ordinary chats never leave the phone.
  - Only suspicious messages go to the server, which strips personal details before any AI sees them.
  - The call check sends only the number.
- **Minimal permissions:** no `READ_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG` or `READ_PHONE_STATE`. Shield uses the user-granted notification access and the official "Caller ID & spam" role.
- **One native app:** the full FraudLens experience and the background protection live in one APK, with one server address, and you can share any message into it.
- **Works across channels:** SMS, WhatsApp, Telegram, Messenger, Viber, Gmail and Outlook all go through the same notification pipeline.
