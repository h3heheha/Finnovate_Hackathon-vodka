package com.fraudlens.shield

import android.Manifest
import android.app.Activity
import android.app.role.RoleManager
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The one FraudLens app. Two tabs at the bottom:
 *  - FraudLens: the full app (Scan, Examples, Learn, History, Verified contacts…), drawn from the
 *    FraudLens server at <server>/app/ inside this activity.
 *  - Shield: background protection. Turn on the permissions, point the app at the server, test alerts,
 *    and see recent alerts. The listener and call screener in this same APK do the background work.
 */
class MainActivity : Activity() {

    private lateinit var prefs: Prefs
    private lateinit var content: LinearLayout
    private lateinit var serverStatus: TextView
    private lateinit var webView: WebView
    private lateinit var shieldScroll: ScrollView
    private lateinit var errorBox: LinearLayout
    private lateinit var errorText: TextView
    private lateinit var tabAppLabel: TextView
    private lateinit var tabShieldLabel: TextView
    private var currentTab = TAB_APP
    private var loadedUrl: String? = null
    private var pageFailed = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = Prefs(this)
        Alerts.ensureChannels(this)
        window.statusBarColor = Color.parseColor(Ui.BG)
        window.navigationBarColor = Color.parseColor(Ui.SURFACE)

        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(Ui.dp(this@MainActivity, 16), Ui.dp(this@MainActivity, 20),
                Ui.dp(this@MainActivity, 16), Ui.dp(this@MainActivity, 32))
        }
        shieldScroll = ScrollView(this).apply {
            setBackgroundColor(Color.parseColor(Ui.BG))
            addView(content)
        }
        webView = buildWebView()
        errorBox = buildErrorBox()

        val pages = FrameLayout(this).apply {
            val full = FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT)
            addView(webView, full)
            addView(errorBox, FrameLayout.LayoutParams(full))
            addView(shieldScroll, FrameLayout.LayoutParams(full))
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            fitsSystemWindows = true  // keep content clear of the status and navigation bars (Android 15)
            setBackgroundColor(Color.parseColor(Ui.BG))
            addView(pages, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
            addView(bottomBar(), LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT))
        })

        render()
        // First run: open on Shield so the permissions and server address get set up.
        val needsSetup = !listenerEnabled() || prefs.serverUrl == Prefs.DEFAULT_SERVER
        showTab(intent.getStringExtra(EXTRA_TAB) ?: if (needsSetup) TAB_SHIELD else TAB_APP)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        intent.getStringExtra(EXTRA_TAB)?.let { showTab(it) }
    }

    override fun onResume() {
        super.onResume()
        webView.onResume()
        render()  // permissions may have changed in Settings
    }

    override fun onPause() {
        webView.onPause()
        super.onPause()
    }

    override fun onDestroy() {
        webView.destroy()
        super.onDestroy()
    }

    @Deprecated("Still called on every API level this app supports")
    override fun onBackPressed() {
        when {
            currentTab == TAB_SHIELD -> showTab(TAB_APP)
            webView.canGoBack() -> webView.goBack()
            else -> super.onBackPressed()
        }
    }

    // ---- tabs ----------------------------------------------------------------------------------
    private fun bottomBar(): LinearLayout {
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Color.parseColor(Ui.SURFACE))
            setPadding(0, Ui.dp(this@MainActivity, 6), 0, Ui.dp(this@MainActivity, 6))
        }
        tabAppLabel = tab("🔍", "FraudLens") { showTab(TAB_APP) }
        tabShieldLabel = tab("🛡️", "Shield") { showTab(TAB_SHIELD) }
        tabAppLabel.setOnLongClickListener {  // long-press = reload the app (handy if it ever freezes)
            pageFailed = true
            showTab(TAB_APP)
            Toast.makeText(this, "Reloading FraudLens…", Toast.LENGTH_SHORT).show()
            true
        }
        val w = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        bar.addView(tabAppLabel, w)
        bar.addView(tabShieldLabel, LinearLayout.LayoutParams(w))
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(View(this@MainActivity).apply { setBackgroundColor(Color.parseColor(Ui.LINE)) },
                LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, Ui.dp(this@MainActivity, 1)))
            addView(bar)
        }
    }

    private fun tab(icon: String, label: String, onClick: () -> Unit): TextView = TextView(this).apply {
        text = "$icon\n$label"
        tag = label
        gravity = Gravity.CENTER
        textSize = 12.5f
        setPadding(0, Ui.dp(this@MainActivity, 4), 0, Ui.dp(this@MainActivity, 4))
        setOnClickListener { onClick() }
    }

    private fun showTab(which: String) {
        currentTab = if (which == TAB_SHIELD) TAB_SHIELD else TAB_APP
        val app = currentTab == TAB_APP
        shieldScroll.visibility = if (app) View.GONE else View.VISIBLE
        if (app) loadAppIfNeeded()
        styleTab(tabAppLabel, app)
        styleTab(tabShieldLabel, !app)
        updateShieldBadge()
    }

    private fun styleTab(t: TextView, selected: Boolean) {
        t.setTextColor(Color.parseColor(if (selected) Ui.SAFE else Ui.MUTED))
        t.setTypeface(Typeface.DEFAULT, if (selected) Typeface.BOLD else Typeface.NORMAL)
    }

    /** "Shield ⚠️" on the tab until the essential permission is on, so a missing step is visible. */
    private fun updateShieldBadge() {
        if (!::tabShieldLabel.isInitialized) return
        tabShieldLabel.text = if (listenerEnabled()) "🛡️\nShield" else "🛡️\nShield ⚠️"
    }

    // ---- the FraudLens app (served by the FraudLens server) ------------------------------------
    private fun appUrl(): String = prefs.serverUrl.trim().trimEnd('/') + "/app/"

    private fun loadAppIfNeeded() {
        val url = appUrl()
        if (loadedUrl != url || pageFailed) {
            loadedUrl = url
            pageFailed = false
            errorBox.visibility = View.GONE
            webView.loadUrl(url)
        }
    }

    private fun buildWebView(): WebView = WebView(this).apply {
        setBackgroundColor(Color.parseColor(Ui.BG))
        settings.javaScriptEnabled = true           // the app UI is a web app
        settings.domStorageEnabled = true
        settings.javaScriptCanOpenWindowsAutomatically = true
        settings.setSupportMultipleWindows(false)   // links that open a new window stay routable below
        settings.useWideViewPort = true
        settings.loadWithOverviewMode = true
        settings.allowFileAccess = false
        settings.allowContentAccess = false
        // Lets the app know it runs inside the Android app (it then points to the Shield tab).
        settings.userAgentString = settings.userAgentString + " FraudLensApp/1.0"
        webChromeClient = WebChromeClient()
        webViewClient = object : WebViewClient() {
            override fun onPageStarted(view: WebView, url: String?, favicon: android.graphics.Bitmap?) {
                pageFailed = false
            }

            override fun onPageFinished(view: WebView, url: String?) {
                if (!pageFailed) errorBox.visibility = View.GONE
            }

            override fun onReceivedError(view: WebView, request: WebResourceRequest, error: WebResourceError) {
                if (request.isForMainFrame) showError(error.description?.toString())
            }

            override fun onReceivedHttpError(view: WebView, request: WebResourceRequest,
                                             response: WebResourceResponse) {
                if (request.isForMainFrame && response.statusCode >= 400) showError("HTTP ${response.statusCode}")
            }

            // Pages of the FraudLens server stay in the app; everything else (tel:, mailto:, official
            // websites, WhatsApp links) opens in the app that handles it.
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                if (isServerUrl(request.url)) return false
                try {
                    startActivity(Intent(Intent.ACTION_VIEW, request.url))
                } catch (e: Exception) {
                    Toast.makeText(this@MainActivity, "No app can open ${request.url}", Toast.LENGTH_SHORT).show()
                }
                return true
            }
        }
    }

    private fun isServerUrl(u: Uri): Boolean {
        val server = Uri.parse(prefs.serverUrl.trim())
        fun port(x: Uri) = if (x.port != -1) x.port else if (x.scheme == "https") 443 else 80
        return (u.scheme == "http" || u.scheme == "https") && u.host == server.host && port(u) == port(server)
    }

    private fun buildErrorBox(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER
        visibility = View.GONE
        isClickable = true  // don't let taps reach the blank page underneath
        setBackgroundColor(Color.parseColor(Ui.BG))
        val pad = Ui.dp(this@MainActivity, 28)
        setPadding(pad, pad, pad, pad)
        addView(Ui.text(this@MainActivity, "📡", 40f).apply { gravity = Gravity.CENTER })
        addView(Ui.text(this@MainActivity, "Can't reach the FraudLens server", 19f, true).apply {
            gravity = Gravity.CENTER
        })
        errorText = Ui.text(this@MainActivity, "", 13.5f, false, Ui.MUTED).apply { gravity = Gravity.CENTER }
        addView(errorText)
        addView(Ui.button(this@MainActivity, "Retry", Ui.TEAL) {
            pageFailed = true
            loadAppIfNeeded()
        }, Ui.matchWidth(this@MainActivity, 16))
        addView(Ui.button(this@MainActivity, "Server settings") { showTab(TAB_SHIELD) },
            Ui.matchWidth(this@MainActivity, 8))
        addView(Ui.text(this@MainActivity,
            "Background protection keeps working in the Shield tab whenever the server is reachable.",
            12.5f, false, Ui.MUTED).apply { gravity = Gravity.CENTER }, Ui.matchWidth(this@MainActivity, 16))
    }

    private fun showError(detail: String?) {
        pageFailed = true
        errorText.text = "Tried ${appUrl()}${if (detail.isNullOrBlank()) "" else " ($detail)"}.\n\n" +
            "Check that the laptop runs run_backend.bat, that both are on the same Wi-Fi or hotspot, " +
            "and that the address in Shield → FraudLens server is right."
        errorBox.visibility = View.VISIBLE
    }

    private fun render() {
        content.removeAllViews()
        content.addView(hero())
        content.addView(setupCard(), Ui.matchWidth(this, 14))
        content.addView(serverCard(), Ui.matchWidth(this, 14))
        content.addView(demoCard(), Ui.matchWidth(this, 14))
        content.addView(alertsCard(), Ui.matchWidth(this, 14))
        updateShieldBadge()
    }

    // ---- header -----------------------------------------------------------------------------
    private fun hero(): LinearLayout = Ui.card(this, Ui.SURFACE, "#1F5E4B").apply {
        addView(Ui.text(this@MainActivity, "RUNS IN THE BACKGROUND", 11f, true, Ui.SAFE))
        addView(Ui.text(this@MainActivity, "🛡️ Shield", 22f, true))
        addView(Ui.text(this@MainActivity,
            "Checks suspicious SMS, WhatsApp and email notifications as they arrive, and incoming calls while " +
                "they ring, and warns you before you act. It keeps working when FraudLens is closed.",
            14f, false, Ui.MUTED))
        val sw = Switch(this@MainActivity).apply {
            text = "Protection on"
            setTextColor(Color.WHITE)
            isChecked = prefs.protectionOn
            setOnCheckedChangeListener { _, on -> prefs.protectionOn = on }
        }
        addView(sw, Ui.matchWidth(this@MainActivity, 8))
    }

    // ---- permissions ---------------------------------------------------------------------------
    private fun setupCard(): LinearLayout = Ui.card(this).apply {
        addView(Ui.text(this@MainActivity, "Setup", 18f, true))
        addView(Ui.text(this@MainActivity, "Turn on each item once. Come back here after each step.", 13f,
            false, Ui.MUTED))

        addView(step("1. Read notifications", "Lets Shield see new SMS, WhatsApp and email alerts.",
            listenerEnabled()) {
            startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
            Toast.makeText(this@MainActivity,
                "Find FraudLens and switch it on. If it's greyed out: App info > ⋮ > Allow restricted settings",
                Toast.LENGTH_LONG).show()
        })
        if (Build.VERSION.SDK_INT >= 33) {
            addView(step("2. Show warnings", "Allows Shield to post scam alerts.", notificationsAllowed()) {
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
            })
        }
        addView(step("3. Display over other apps", "Shows the red warning banner on top of any app.",
            Settings.canDrawOverlays(this@MainActivity)) {
            startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName")))
        })
        if (Build.VERSION.SDK_INT >= 29) {
            addView(step("4. Check incoming calls (optional)", "Warns while a known scam number is ringing.",
                callRoleHeld()) {
                val rm = getSystemService(RoleManager::class.java)
                if (rm != null && rm.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING)) {
                    startActivityForResult(rm.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING), REQ_ROLE)
                } else {
                    Toast.makeText(this@MainActivity, "Call screening isn't available on this phone",
                        Toast.LENGTH_LONG).show()
                }
            })
        }
        addView(step("5. Don't let the battery saver stop Shield (optional)",
            "Find FraudLens and choose 'Don't optimise' / 'Unrestricted'.", null) {
            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
        })
    }

    private fun step(title: String, desc: String, done: Boolean?, action: () -> Unit): LinearLayout {
        val row = Ui.row(this)
        val texts = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val mark = when (done) { true -> "✅ "; false -> "⚠️ "; null -> "▫️ " }
        texts.addView(Ui.text(this, mark + title, 15f, true))
        texts.addView(Ui.text(this, desc, 12.5f, false, Ui.MUTED))
        row.addView(texts, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        if (done != true) {
            row.addView(Ui.button(this, if (done == null) "Open" else "Enable", Ui.TEAL) { action() })
        }
        row.setPadding(0, Ui.dp(this, 8), 0, Ui.dp(this, 4))
        return row
    }

    private fun listenerEnabled(): Boolean {
        val flat = Settings.Secure.getString(contentResolver, "enabled_notification_listeners") ?: return false
        val me = ComponentName(this, ShieldNotificationListener::class.java).flattenToString()
        return flat.split(":").any { it == me }
    }

    private fun notificationsAllowed(): Boolean =
        Build.VERSION.SDK_INT < 33 ||
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    private fun callRoleHeld(): Boolean {
        if (Build.VERSION.SDK_INT < 29) return false
        val rm = getSystemService(RoleManager::class.java) ?: return false
        return rm.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)
    }

    // ---- server --------------------------------------------------------------------------------
    private fun serverCard(): LinearLayout = Ui.card(this).apply {
        addView(Ui.text(this@MainActivity, "FraudLens server", 18f, true))
        addView(Ui.text(this@MainActivity,
            "Used by both tabs. Real phone: http://<laptop Wi-Fi IP>:8000 · Emulator: http://10.0.2.2:8000",
            12.5f, false, Ui.MUTED))
        val input = EditText(this@MainActivity).apply {
            setText(prefs.serverUrl)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
        }
        addView(input, Ui.matchWidth(this@MainActivity, 6))
        serverStatus = Ui.text(this@MainActivity, "Not tested yet", 13f, false, Ui.MUTED)
        addView(Ui.button(this@MainActivity, "Save & test connection") {
            prefs.serverUrl = input.text.toString().trim()
            loadedUrl = null  // the FraudLens tab reloads from the new address next time it opens
            testServer()
        }, Ui.matchWidth(this@MainActivity, 6))
        addView(serverStatus)
    }

    private fun testServer() {
        serverStatus.text = "Connecting…"
        val url = prefs.serverUrl
        Thread {
            val msg = try {
                val h = ApiClient(url).health()
                val ml = h.optJSONObject("ml")
                val intel = h.optJSONObject("intel")
                val providers = if (intel == null) "off" else listOf("safe_browsing", "urlhaus", "ipqs")
                    .filter { intel.optBoolean(it) }.joinToString(", ").ifEmpty { "none configured" }
                "✅ Connected (v${h.optString("version")}) · AI: ${ml?.optString("embedder") ?: "rules only"} · " +
                    "threat intel: $providers"
            } catch (e: Exception) {
                "❌ Can't reach $url (${e.message}). Is the API running with --host 0.0.0.0?"
            }
            runOnUiThread { serverStatus.text = msg }
        }.start()
    }

    // ---- demo ----------------------------------------------------------------------------------
    private fun demoCard(): LinearLayout = Ui.card(this).apply {
        addView(Ui.text(this@MainActivity, "Try it", 18f, true))
        addView(Ui.text(this@MainActivity,
            "Best demo: send an SMS to this phone (emulator: ⋯ Extended controls > Phone > SMS). " +
                "Or use the buttons below.", 12.5f, false, Ui.MUTED))
        addView(Ui.button(this@MainActivity, "Send a test scam alert", Ui.RED) { testAlert() },
            Ui.matchWidth(this@MainActivity, 8))
        addView(Ui.button(this@MainActivity, "📋 Check copied text") { checkClipboard() },
            Ui.matchWidth(this@MainActivity, 8))
        if (Build.VERSION.SDK_INT >= 29) {
            addView(Ui.button(this@MainActivity, "Test a caller check", Ui.AMBER) { testCall() },
                Ui.matchWidth(this@MainActivity, 8))
        }
    }

    private fun testAlert() {
        val url = prefs.serverUrl
        Toast.makeText(this, "Analysing a sample scam SMS…", Toast.LENGTH_SHORT).show()
        Thread {
            try {
                val analysis = ApiClient(url).analyze(SAMPLE_SCAM, SAMPLE_SENDER, "sms")
                Alerts.showMessageAlert(this, analysis, SAMPLE_SCAM, SAMPLE_SENDER, "Messages (test)")
                runOnUiThread { render() }
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Server not reachable: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }

    /** Checks whatever is on the clipboard and opens the Scam X-Ray (works even where web paste can't). */
    private fun checkClipboard() {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val text = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)
            ?.toString()?.trim().orEmpty()
        if (text.isEmpty()) {
            Toast.makeText(this, "Copy a message first (long-press it → Copy)", Toast.LENGTH_LONG).show()
            return
        }
        val url = prefs.serverUrl
        Toast.makeText(this, "Checking the copied text…", Toast.LENGTH_SHORT).show()
        Thread {
            try {
                val analysis = ApiClient(url).analyze(text.take(5000), null, "other")
                val alert = JSONObject()
                    .put("time", System.currentTimeMillis())
                    .put("kind", "message")
                    .put("app", "Copied text")
                    .put("sender", "Unknown sender")
                    .put("text", text.take(5000))
                    .put("score", analysis.optInt("risk_score"))
                    .put("level", analysis.optString("risk_level", "low"))
                    .put("verdict", analysis.optString("verdict"))
                    .put("summary", analysis.optString("summary"))
                    .put("analysis", analysis)
                runOnUiThread { startActivity(Alerts.detailIntent(this, alert)) }
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Server not reachable: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }

    private fun testCall() {
        val url = prefs.serverUrl
        Thread {
            try {
                val result = ApiClient(url).checkPhone(SAMPLE_SENDER)
                if (result.optString("risk_level") == "low") {
                    runOnUiThread {
                        Toast.makeText(this, "Caller check works: ${result.optString("headline")}",
                            Toast.LENGTH_LONG).show()
                    }
                } else {
                    Alerts.showCallAlert(this, SAMPLE_SENDER, result)
                    runOnUiThread { render() }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Server not reachable: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }

    // ---- history -------------------------------------------------------------------------------
    private fun alertsCard(): LinearLayout = Ui.card(this).apply {
        addView(Ui.text(this@MainActivity, "Recent alerts", 18f, true))
        val alerts = prefs.recentAlerts()
        if (alerts.isEmpty()) {
            addView(Ui.text(this@MainActivity, "No alerts yet. Shield is watching quietly.", 13f, false, Ui.MUTED))
        }
        val fmt = SimpleDateFormat("dd MMM HH:mm", Locale.getDefault())
        for (a in alerts.take(10)) {
            val row = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                background = Ui.rounded(Ui.SURFACE_2, 12, this@MainActivity, Ui.LINE)
                setPadding(Ui.dp(this@MainActivity, 12), Ui.dp(this@MainActivity, 8),
                    Ui.dp(this@MainActivity, 12), Ui.dp(this@MainActivity, 8))
                setOnClickListener { startActivity(Alerts.detailIntent(this@MainActivity, a)) }
            }
            row.addView(Ui.text(this@MainActivity, "${a.optInt("score")}/100 · ${a.optString("verdict")}", 14f,
                true, Ui.levelText(a.optString("level"))))
            row.addView(Ui.text(this@MainActivity,
                "${a.optString("sender")} · ${a.optString("app")} · ${fmt.format(Date(a.optLong("time")))}",
                12f, false, Ui.MUTED))
            row.addView(Ui.text(this@MainActivity, a.optString("text").take(90), 13f))
            addView(row, Ui.matchWidth(this@MainActivity, 8))
        }
        if (alerts.isNotEmpty()) {
            addView(Ui.button(this@MainActivity, "Clear history") {
                prefs.clearAlerts(); render()
            }, Ui.matchWidth(this@MainActivity, 8))
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        render()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        render()
    }

    companion object {
        const val EXTRA_TAB = "tab"
        const val TAB_APP = "app"
        const val TAB_SHIELD = "shield"
        private const val REQ_NOTIF = 1
        private const val REQ_ROLE = 2
        const val SAMPLE_SENDER = "+230 5821 4470"
        const val SAMPLE_SCAM = "MCB ALERT: Your account has been suspended due to unusual activity. " +
            "Verify within 2 hours to avoid closure: http://mcb-secure-verify.com/login " +
            "Reply with the OTP you receive to confirm."
    }
}
