package com.fraudlens.shield

import android.animation.LayoutTransition
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import com.fraudlens.shield.K.add

/**
 * FraudLens: one native app. Five tabs in a floating dock (Home, Scan, Learn, History, Shield), a landing
 * screen on launch, and "Share → FraudLens" / "Check with FraudLens" from any app.
 * Shield's background work (notification listener, call screening) lives in this same APK.
 */
class MainActivity : Activity() {
    lateinit var actions: Actions
    lateinit var homeTab: HomeTab
    lateinit var scanTab: ScanTab
    lateinit var learnTab: LearnTab
    lateinit var historyTab: HistoryTab
    lateinit var shieldTab: ShieldTab

    private val tabs = LinkedHashMap<String, Tab>()
    private var current = ""
    private lateinit var root: FrameLayout
    private lateinit var column: LinearLayout
    private lateinit var pages: FrameLayout
    private lateinit var statusHolder: FrameLayout
    private lateinit var dock: LinearLayout
    private val dockItems = LinkedHashMap<String, DockItem>()
    private var welcome: WelcomeView? = null
    private var topInset = 0
    private var navInset = 0
    private var imeOpen = false
    private var imeInset = 0
    private var sideInsets = 0 to 0
    private val repoListener: () -> Unit = { onRepoChanged() }

    /** Small phones or "Largest" display size: tighter dock and a dot-only status chip. */
    private val narrow: Boolean
        get() = resources.displayMetrics.widthPixels / resources.displayMetrics.density < 360

    private class DockItem(val view: LinearLayout, val icon: TextView, val label: TextView, val dot: View?)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Repo.init(this)
        Alerts.ensureChannels(this)
        actions = Actions(this) { snack(it) }
        setupWindow()
        build()
        Repo.listen(repoListener)
        Repo.refresh(this)

        val i = intent
        val special = i?.action == Intent.ACTION_SEND || i?.action == Intent.ACTION_PROCESS_TEXT || i?.getStringExtra(EXTRA_TAB) != null
        showTab(i?.getStringExtra(EXTRA_TAB) ?: "home", animate = false)
        // Reopened from Recents: Android replays the original share. Don't check that old message again.
        val fromRecents = i != null && (i.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) != 0
        if (savedInstanceState == null && !fromRecents) {
            if (!special) showWelcome()
            handleIntent(i)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        tabs[current]?.onShow()   // permissions may have changed in Settings; History may have new alerts
        // Make sure Shield's listener is connected (some phones drop it after an update or a battery clean-up).
        if (ShieldStatus.listenerEnabled(this)) {
            try {
                android.service.notification.NotificationListenerService.requestRebind(
                    android.content.ComponentName(this, ShieldNotificationListener::class.java))
            } catch (e: Exception) { /* not allowed right now: Android will reconnect it itself */ }
        }
        paintDock()
        if (Repo.online == false && Repo.secondsSinceRefresh() > 20) Repo.refresh(this)  // server may have started
    }

    override fun onDestroy() {
        Repo.unlisten(repoListener)
        welcome?.stop()
        super.onDestroy()
    }

    @Deprecated("Still called on every Android version this app supports")
    override fun onBackPressed() {
        when {
            welcome != null -> finish()
            current != "home" -> showTab("home")
            else -> @Suppress("DEPRECATION") super.onBackPressed()
        }
    }

    @Deprecated("Needed for the call-screening role request")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION") super.onActivityResult(requestCode, resultCode, data)
        afterPermissionChange()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        afterPermissionChange()
    }

    private fun afterPermissionChange() {
        shieldTab.render()
        homeTab.render()
        paintDock()
    }

    // ---- window: draw behind the system bars, pad for them ourselves (also Android 15 edge-to-edge) ------
    @Suppress("DEPRECATION")
    private fun setupWindow() {
        window.statusBarColor = Color.TRANSPARENT
        window.navigationBarColor = Color.TRANSPARENT
        if (Build.VERSION.SDK_INT >= 29) window.isNavigationBarContrastEnforced = false
        if (Build.VERSION.SDK_INT >= 30) {
            window.setDecorFitsSystemWindows(false)
        } else {
            window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
        }
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
    }

    @Suppress("DEPRECATION")
    private fun applyInsets(ins: WindowInsets) {
        val top: Int
        val nav: Int
        val ime: Int
        val left: Int
        val right: Int
        if (Build.VERSION.SDK_INT >= 30) {
            val bars = ins.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
            top = bars.top
            nav = bars.bottom
            left = bars.left
            right = bars.right
            ime = ins.getInsets(WindowInsets.Type.ime()).bottom
        } else {
            top = ins.systemWindowInsetTop
            nav = ins.stableInsetBottom
            left = ins.systemWindowInsetLeft
            right = ins.systemWindowInsetRight
            val b = ins.systemWindowInsetBottom
            ime = if (b > nav) b else 0
        }
        topInset = top
        navInset = nav
        imeOpen = ime > nav + K.dp(this, 60)
        imeInset = if (imeOpen) ime else 0
        column.setPadding(left, top, right, if (imeOpen) ime else 0)  // left/right: landscape nav bar, cutouts
        dock.visibility = if (imeOpen || welcome != null) View.GONE else View.VISIBLE
        (dock.layoutParams as ViewGroup.MarginLayoutParams).bottomMargin = nav + K.dp(this, 14)
        dock.requestLayout()
        val space = if (imeOpen) K.dp(this, 24) else nav + K.dp(this, 104)
        tabs.values.forEach { it.setBottomSpace(space) }
        welcome?.setInsets(top, nav, left, right)
        sideInsets = left to right
    }

    // ---- layout -----------------------------------------------------------------------------------------
    private fun build() {
        root = FrameLayout(this).apply { setBackgroundColor(T.BG) }
        column = K.col(this)
        column.add(topBar())
        pages = FrameLayout(this)
        column.add(pages, K.MATCH, 0, 1f)
        root.addView(column, FrameLayout.LayoutParams(K.MATCH, K.MATCH))

        homeTab = HomeTab(this); scanTab = ScanTab(this); learnTab = LearnTab(this)
        historyTab = HistoryTab(this); shieldTab = ShieldTab(this)
        tabs["home"] = homeTab; tabs["scan"] = scanTab; tabs["learn"] = learnTab
        tabs["history"] = historyTab; tabs["shield"] = shieldTab
        for (t in tabs.values) {
            t.scroll.visibility = View.GONE
            pages.addView(t.scroll, FrameLayout.LayoutParams(K.MATCH, K.MATCH))
            t.render()
        }

        dock = buildDock()
        root.addView(dock, FrameLayout.LayoutParams(K.WRAP, K.WRAP, Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL).apply {
            bottomMargin = K.dp(this@MainActivity, 18)
        })
        setContentView(root)
        root.setOnApplyWindowInsetsListener { _, ins -> applyInsets(ins); ins }
        refreshStatus()
    }

    private fun topBar(): LinearLayout = K.row(this).apply {
        setPadding(K.dp(context, T.GUTTER), K.dp(context, 8), K.dp(context, T.GUTTER - 4), K.dp(context, 8))
        val logo = FrameLayout(context).apply {
            background = K.rounded(context, T.SAFE, 9f)
            addView(K.icon(context, "SHIELD", 16f, T.ON_ACCENT), FrameLayout.LayoutParams(K.MATCH, K.MATCH))
        }
        add(logo, K.dp(context, 30), K.dp(context, 30), r = 10)
        add(K.text(context, "FraudLens", 17f, 700), K.WRAP, K.WRAP)
        add(K.space(context), 0, 1, 1f)
        statusHolder = FrameLayout(context)
        add(statusHolder, K.WRAP, K.WRAP, r = 8)
        add(K.iconButton(context, "TUNE", 40) { openSettings() }, K.dp(context, 40), K.dp(context, 40))
        minimumHeight = K.dp(context, 58)
    }

    private fun buildDock(): LinearLayout {
        val d = K.row(this).apply {
            background = K.rounded(context, T.SURFACE, 999f, T.LINE)
            setPadding(K.dp(context, 6), K.dp(context, 6), K.dp(context, 6), K.dp(context, 6))
            elevation = K.dpf(context, 12)
            layoutTransition = LayoutTransition().apply { enableTransitionType(LayoutTransition.CHANGING) }
        }
        val items = listOf(
            Triple("home", "GRID_VIEW_ROUNDED", "Home"), Triple("scan", "DOCUMENT_SCANNER_OUTLINED", "Scan"),
            Triple("learn", "SCHOOL_OUTLINED", "Learn"), Triple("history", "HISTORY", "History"),
            Triple("shield", "SHIELD_OUTLINED", "Shield"),
        )
        for ((key, iconName, label) in items) {
            val item = K.row(this, Gravity.CENTER).apply {
                val h = if (narrow) 10 else 14
                setPadding(K.dp(context, h), K.dp(context, 11), K.dp(context, h), K.dp(context, 11))
                layoutTransition = LayoutTransition()
                contentDescription = label
            }
            val iconBox = FrameLayout(this)
            val ic = K.icon(this, iconName, 21f, T.MUTED)
            iconBox.addView(ic, FrameLayout.LayoutParams(K.WRAP, K.WRAP, Gravity.CENTER))
            var dot: View? = null
            if (key == "shield") {
                dot = View(this).apply {
                    background = GradientDrawable().apply {
                        shape = GradientDrawable.OVAL; setColor(T.WARN); setStroke(K.dp(context, 2), T.SURFACE)
                    }
                }
                iconBox.addView(dot, FrameLayout.LayoutParams(K.dp(this, 10), K.dp(this, 10), Gravity.TOP or Gravity.END))
            }
            item.add(iconBox, K.WRAP, K.WRAP)
            val lbl = K.text(this, label, 13f, 600, T.SAFE_TEXT, maxLines = 1).apply { visibility = View.GONE }
            item.add(lbl, K.WRAP, K.WRAP, l = 7)
            K.pressable(item, 999f) { showTab(key) }
            dockItems[key] = DockItem(item, ic, lbl, dot)
            d.add(item, K.WRAP, K.WRAP)
        }
        return d
    }

    private fun paintDock() {
        val shieldOk = ShieldStatus(this).running
        for ((key, it) in dockItems) {
            val on = key == current
            it.icon.setTextColor(if (on) T.SAFE_TEXT else T.MUTED)
            it.label.visibility = if (on) View.VISIBLE else View.GONE
            it.view.background = if (on) K.rounded(this, T.tint(T.SAFE, 0.14f), 999f) else null
            it.dot?.visibility = if (shieldOk) View.GONE else View.VISIBLE
        }
    }

    fun refreshDock() = paintDock()

    private fun refreshStatus() {
        statusHolder.removeAllViews()
        val (label, color) = when (Repo.online) {
            true -> "Online" to T.SAFE_TEXT
            false -> "Offline demo" to T.WARN
            null -> "Connecting" to T.MUTED
        }
        val chip = if (narrow) K.row(this).apply {
            background = K.rounded(context, T.tint(color, 0.10f), 999f, T.tint(color, 0.25f))
            setPadding(K.dp(context, 9), K.dp(context, 9), K.dp(context, 9), K.dp(context, 9))
            contentDescription = label
            add(K.dot(context, color, 8), K.dp(context, 8), K.dp(context, 8))
        } else K.statusChip(this, label, color)
        K.pressable(chip, 999f) { openSettings() }
        statusHolder.addView(chip)
    }

    private fun onRepoChanged() {
        refreshStatus()
        welcome?.setReady(Repo.online)
        // Only the visible tab is rebuilt now; the others catch up when they are opened.
        for ((key, t) in tabs) if (key == current) t.render() else t.dirty = true
    }

    // ---- navigation -------------------------------------------------------------------------------------
    fun showTab(key: String, animate: Boolean = true) {
        val next = tabs[key] ?: return
        if (key == current) {
            next.scroll.smoothScrollTo(0, 0)   // tapping the open tab goes back to its top
            return
        }
        tabs[current]?.scroll?.visibility = View.GONE
        current = key
        next.scroll.visibility = View.VISIBLE
        next.onShow()
        if (animate) {
            next.scroll.alpha = 0f
            next.scroll.translationY = K.dpf(this, 8)
            next.scroll.animate().alpha(1f).translationY(0f).setDuration(200).start()
        }
        paintDock()
        (getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager).hideSoftInputFromWindow(root.windowToken, 0)
    }

    private fun showWelcome() {
        val w = WelcomeView(this) { dismissWelcome() }
        w.setReady(Repo.online)
        w.setInsets(topInset, navInset, sideInsets.first, sideInsets.second)
        welcome = w
        dock.visibility = View.GONE
        root.addView(w, FrameLayout.LayoutParams(K.MATCH, K.MATCH))
    }

    private fun dismissWelcome() {
        val w = welcome ?: return
        w.stop()
        root.removeView(w)
        welcome = null
        dock.visibility = if (imeOpen) View.GONE else View.VISIBLE
        K.enter(dock)
        tabs[current]?.onShow()
    }

    /** Text shared from WhatsApp, Messages, Gmail… ("Share" or "Check with FraudLens" on selected text). */
    private fun handleIntent(i: Intent?) {
        i ?: return
        val shared: String? = when (i.action) {
            Intent.ACTION_SEND -> listOfNotNull(
                i.getStringExtra(Intent.EXTRA_SUBJECT),
                i.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString(),
            ).filter { it.isNotBlank() }.joinToString("\n").ifBlank { null }
            Intent.ACTION_PROCESS_TEXT -> i.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
            else -> null
        }
        if (!shared.isNullOrBlank()) {
            dismissWelcome()
            scanTab.checkShared(shared)
            i.action = null  // handled; don't scan again if the activity is recreated
        }
        i.getStringExtra(EXTRA_TAB)?.let {
            dismissWelcome()
            showTab(it)
            i.removeExtra(EXTRA_TAB)
        }
    }

    // ---- shared helpers used by the tabs --------------------------------------------------------------------
    fun snack(msg: String) {
        val d = resources.displayMetrics.density
        val bottom = when {
            imeOpen -> (imeInset / d).toInt() + 16                  // above the keyboard
            dock.visibility == View.VISIBLE -> (navInset / d).toInt() + 84  // above the dock
            else -> (navInset / d).toInt() + 16
        }
        Snack.show(root, msg, bottom, sideInsets)
    }

    fun openSettings() = Sheets.settings(this, actions)

    fun startSafely(i: Intent) = actions.startSafely(i)

    /** Opens a History item (your check or a Shield alert) full screen. */
    fun openEntry(e: Entry) {
        startActivity(DetailActivity.forEntry(this, e))
        @Suppress("DEPRECATION")
        overridePendingTransition(android.R.anim.slide_in_left, android.R.anim.fade_out)
    }

    companion object {
        const val EXTRA_TAB = "tab"
        const val REQ_NOTIF = 1
        const val REQ_ROLE = 2
    }
}
