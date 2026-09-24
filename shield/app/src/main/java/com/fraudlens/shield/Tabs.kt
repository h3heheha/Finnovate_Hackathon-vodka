package com.fraudlens.shield

import android.content.ClipboardManager
import android.content.Context
import android.view.Gravity
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import com.fraudlens.shield.K.add
import org.json.JSONObject

/** One page of the app (Home, Scan, Learn, History, Shield). Each keeps its own scroll position. */
abstract class Tab(val app: MainActivity) {
    val ctx: Context get() = app
    val content: LinearLayout = K.col(app)
    val scroll: ScrollView = ScrollView(app).apply {
        isVerticalScrollBarEnabled = false
        isFillViewport = true
        overScrollMode = View.OVER_SCROLL_IF_CONTENT_SCROLLS
        addView(content, FrameLayout.LayoutParams(K.MATCH, K.WRAP))
    }

    init { setBottomSpace(K.dp(app, 112)) }

    /** Leaves room under the content for the floating dock (and the phone's navigation bar). */
    fun setBottomSpace(px: Int) {
        content.setPadding(K.dp(app, T.GUTTER), K.dp(app, 6), K.dp(app, T.GUTTER), px)
    }

    /** Rebuilds the page from current data. */
    abstract fun render()

    /** Set when data changed while the tab was hidden. */
    var dirty = false

    /** Called every time the tab becomes visible. */
    open fun onShow() {
        if (dirty) { dirty = false; render() }
    }

    fun scrollTo(v: View, offsetDp: Int = 8) {
        // Wait a moment so freshly added views have been measured and placed.
        scroll.postDelayed({
            var y = 0
            var cur: View? = v
            while (cur != null && cur !== content) {
                y += cur.top
                cur = cur.parent as? View
            }
            scroll.smoothScrollTo(0, (y - K.dp(app, offsetDp)).coerceAtLeast(0))
        }, 90)
    }
}

// =====================================================================================================
// Home: a menu of everything FraudLens can do, plus Shield's status and your numbers.
// =====================================================================================================
class HomeTab(app: MainActivity) : Tab(app) {
    override fun onShow() { dirty = false; render() }

    override fun render() {
        content.removeAllViews()
        content.add(K.pageHeader(ctx, "What would you like to do?",
            "Pick a feature. Everything runs through the same five-layer scam check.", "FraudLens"))
        content.add(shieldCard(), t = 18)
        if (Repo.online == false) content.add(offlineCard(), t = T.GAP)
        content.add(primary(), t = T.GAP)
        content.add(stats(), t = T.GAP)

        content.add(K.sectionHeader(ctx, "Check"), t = 18)
        val scams = (0 until Repo.samples.length()).count { Repo.samples.optJSONObject(it)?.optString("expected") != "legit" }
        val genuine = Repo.samples.length() - scams
        content.add(group(listOf(
            Item("CONTENT_PASTE", "Paste and scan", "Check your clipboard in one tap") { app.scanTab.pasteAndScan() },
            Item("BOLT_OUTLINED", "Try a real example",
                if (Repo.samples.length() > 0) "$scams real scams and $genuine genuine texts to test"
                else "Real scams and genuine texts to test") { app.scanTab.goToExamples() },
            Item("SHARE", "Check from any app", "In WhatsApp or Messages: long-press → Share → FraudLens") {
                Sheets.show(app, shareHelp())
            },
        )), t = 10)

        content.add(K.sectionHeader(ctx, "Learn"), t = 18)
        content.add(group(listOf(
            Item("QUIZ_OUTLINED", "Spot-the-scam quiz", "Find the red flag in real messages") { app.showTab("learn") },
            Item("MENU_BOOK_OUTLINED", "Scam tricks", "30-second lessons on each trick") { app.learnTab.goToLessons() },
        )), t = 10)

        content.add(K.sectionHeader(ctx, "Protection"), t = 18)
        content.add(group(listOf(
            Item("RADAR", "Shield in the background", "How messages and calls are checked as they arrive") { app.showTab("shield") },
            Item("HISTORY", "History", "Everything you've checked, and what Shield caught") { app.showTab("history") },
            Item("VERIFIED_OUTLINED", "Verified contacts", "Official numbers, never from a message") { app.actions.officialContact(null) },
            Item("GROUPS_OUTLINED", "Ask someone you trust", "Message your trusted contact first") { app.actions.askGuardian(null) },
            Item("DNS_OUTLINED", "Settings", "Server address and your trusted contact") { app.openSettings() },
        )), t = 10)
    }

    private class Item(val icon: String, val name: String, val desc: String, val onClick: () -> Unit)

    private fun group(items: List<Item>): View {
        val box = K.col(ctx).apply { background = K.rounded(ctx, T.SURFACE, T.R_CARD, T.LINE) }
        K.clipRounded(box, T.R_CARD)
        items.forEachIndexed { i, it ->
            if (i > 0) box.add(K.divider(ctx, 66))
            val row = K.row(ctx)
            row.setPadding(K.dp(ctx, 14), K.dp(ctx, 12), K.dp(ctx, 14), K.dp(ctx, 12))
            row.add(K.squircle(ctx, it.icon, T.TEXT, 38), K.dp(ctx, 38), K.dp(ctx, 38), r = 14)
            val t = K.col(ctx)
            t.add(K.text(ctx, it.name, 14.5f, 600))
            t.add(K.caption(ctx, it.desc, 12.5f), t = 2)
            row.add(t, 0, K.WRAP, 1f)
            row.add(K.icon(ctx, "CHEVRON_RIGHT", 20f, T.FAINT), K.WRAP, K.WRAP, l = 8)
            K.pressable(row, 0f) { _ -> it.onClick() }
            box.add(row)
        }
        return box
    }

    /** The main feature, one size up: scan a message. */
    private fun primary(): View = K.row(ctx).apply {
        background = K.rounded(ctx, T.tint(T.SAFE, 0.08f), T.R_CARD, T.tint(T.SAFE, 0.35f))
        K.pad(this, 16)
        val ic = FrameLayout(ctx).apply {
            background = K.rounded(ctx, T.SAFE, 13f)
            addView(K.icon(ctx, "DOCUMENT_SCANNER_OUTLINED", 24f, T.ON_ACCENT), FrameLayout.LayoutParams(K.MATCH, K.MATCH))
        }
        add(ic, K.dp(ctx, 48), K.dp(ctx, 48), r = 14)
        val t = K.col(ctx)
        t.add(K.text(ctx, "Scan a message", 16.5f, 700))
        t.add(K.caption(ctx, "Paste an SMS, WhatsApp or email. See every trick highlighted, and what to do next.", 12.5f), t = 3)
        add(t, 0, K.WRAP, 1f)
        val arrow = FrameLayout(ctx).apply {
            background = K.rounded(ctx, T.SAFE, 10f)
            addView(K.icon(ctx, "ARROW_FORWARD", 18f, T.ON_ACCENT), FrameLayout.LayoutParams(K.MATCH, K.MATCH))
        }
        add(arrow, K.dp(ctx, 34), K.dp(ctx, 34), l = 10)
        K.pressable(this, T.R_CARD) { app.scanTab.focusInput() }
    }

    /** Shield's state at a glance: on, or which setup steps are left. Ties the two halves of the app together. */
    private fun shieldCard(): View {
        val s = ShieldStatus(app)
        val on = s.running
        val color = if (on) T.SAFE_TEXT else T.WARN
        return K.row(ctx).apply {
            background = K.rounded(ctx, T.SURFACE, T.R_CARD, T.tint(color, 0.35f))
            K.pad(this, 14)
            add(K.squircle(ctx, if (on) "SHIELD" else "WARNING_AMBER_ROUNDED", color, 40, T.tint(color, 0.12f), false),
                K.dp(ctx, 40), K.dp(ctx, 40), r = 12)
            val t = K.col(ctx)
            t.add(K.mono(ctx, if (on) "SHIELD · RUNNING IN BACKGROUND" else "SHIELD · ${s.done} OF ${s.total} STEPS DONE",
                10.5f, color, bold = true, spacing = 0.06f))
            t.add(K.text(ctx, if (on) "Watching SMS, WhatsApp, email and calls" else if (!s.protectionOn) "Protection is paused"
                else "Finish setup to be warned automatically", 14f, 600), t = 4)
            add(t, 0, K.WRAP, 1f)
            add(K.icon(ctx, "CHEVRON_RIGHT", 20f, T.FAINT), K.WRAP, K.WRAP, l = 8)
            K.pressable(this, T.R_CARD) { app.showTab("shield") }
        }
    }

    private fun offlineCard(): View = K.row(ctx).apply {
        background = K.rounded(ctx, T.tint(T.WARN, 0.10f), T.R_CARD, T.tint(T.WARN, 0.3f))
        K.pad(this, 14)
        add(K.icon(ctx, "WIFI_OFF", 22f, T.WARN), K.WRAP, K.WRAP, r = 12)
        val t = K.col(ctx)
        t.add(K.text(ctx, "Offline demo", 14f, 700, T.WARN))
        t.add(K.caption(ctx, "The FraudLens server can't be reached. The examples still work. Tap to set the server address.", 12.5f), t = 2)
        add(t, 0, K.WRAP, 1f)
        K.pressable(this, T.R_CARD) { app.openSettings() }
    }

    private fun stats(): View {
        val tl = Repo.timeline(ctx)
        val box = K.row(ctx).apply { background = K.rounded(ctx, T.SURFACE, T.R_CARD, T.LINE) }
        fun stat(v: Int, label: String, color: Int): View = K.col(ctx).apply {
            setPadding(K.dp(ctx, 14), K.dp(ctx, 10), K.dp(ctx, 14), K.dp(ctx, 10))
            add(K.mono(ctx, String.format("%02d", v), 20f, color, bold = true, spacing = 0f))
            add(K.mono(ctx, label.uppercase(), 9.5f, T.MUTED, spacing = 0.08f), t = 4)
        }
        fun sep() = View(ctx).apply { setBackgroundColor(T.LINE) }
        box.add(stat(tl.size, "Checked", T.TEXT), 0, K.WRAP, 1f)
        box.add(sep(), K.dp(ctx, 1), K.dp(ctx, 34))
        box.add(stat(tl.count { it.level == "high" }, "Scams", T.FRAUD_TEXT), 0, K.WRAP, 1f)
        box.add(sep(), K.dp(ctx, 1), K.dp(ctx, 34))
        box.add(stat(tl.count { it.level == "low" }, "Safe", T.SAFE_TEXT), 0, K.WRAP, 1f)
        K.pressable(box, T.R_CARD) { app.showTab("history") }
        return box
    }

    private fun shareHelp(): View {
        val c = K.col(ctx)
        c.add(Sheets.header(ctx, "SHARE", "Check a message from any app",
            "No copying needed. FraudLens opens with the message and checks it straight away."))
        val steps = listOf(
            "In WhatsApp, Messages or Gmail, long-press the message (or select its text).",
            "Tap Share (or ⋮ → Share). On selected text you can also tap \"Check with FraudLens\".",
            "Choose FraudLens. The result appears in a second or two.",
        )
        steps.forEachIndexed { i, s ->
            val r = K.row(ctx, Gravity.TOP)
            r.add(K.mono(ctx, "${i + 1}", 12f, T.ON_ACCENT, bold = true).apply {
                gravity = Gravity.CENTER
                background = K.rounded(ctx, T.SAFE, 12f)
            }, K.dp(ctx, 24), K.dp(ctx, 24), r = 12)
            r.add(K.body(ctx, s, 14f), 0, K.WRAP, 1f)
            c.add(r, t = 14)
        }
        return c
    }
}

// =====================================================================================================
// Scan: paste or share a message, see the result.
// =====================================================================================================
class ScanTab(app: MainActivity) : Tab(app) {
    private val input = K.field(app, "Paste an SMS, WhatsApp or email message here…", "",
        android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_FLAG_CAP_SENTENCES,
        multiLine = true, bordered = false).apply {
        minLines = 5
        maxLines = 10
        setPadding(K.dp(app, 18), K.dp(app, 6), K.dp(app, 18), K.dp(app, 10))
    }
    private val sender = K.field(app, "Sender (optional), e.g. MCB or +230 5821 4470", "",
        android.text.InputType.TYPE_CLASS_TEXT, bordered = false).apply {
        textSize = 14f
        setPadding(K.dp(app, 4), K.dp(app, 12), K.dp(app, 4), K.dp(app, 12))
    }
    private val scanBtn = K.button(app, "Scan message", K.Style.PRIMARY, "DOCUMENT_SCANNER") { scan() }
    private val examples = K.col(app)
    private val status = K.col(app)       // loading or error card
    private val results = K.col(app)
    private var seq = 0          // each scan gets a number; late answers to older scans are ignored
    private var built = false

    override fun render() {
        if (!built) {
            built = true
            content.add(K.pageHeader(ctx, "Check a message",
                "Paste a suspicious text, WhatsApp or email. FraudLens shows you the tricks before you reply or pay.", "Scam X-Ray"))
            content.add(inputCard(), t = 18)
            content.add(examples, t = 18)
            content.add(status, t = 18)
            content.add(results, t = 0)
        }
        renderExamples()
    }

    private fun inputCard(): View {
        val card = K.col(ctx).apply { background = K.rounded(ctx, T.SURFACE, T.R_CARD, T.LINE) }
        val top = K.row(ctx)
        top.setPadding(K.dp(ctx, 16), K.dp(ctx, 14), K.dp(ctx, 16), K.dp(ctx, 4))
        top.add(K.dot(ctx, T.SAFE), K.dp(ctx, 7), K.dp(ctx, 7), r = 8)
        top.add(K.mono(ctx, "MESSAGE", 10.5f, T.TEXT, bold = true, spacing = 0.1f), K.WRAP, K.WRAP)
        top.add(K.space(ctx), 0, 1, 1f)
        top.add(K.mono(ctx, "SMS · WHATSAPP · EMAIL", 10f, T.MUTED, spacing = 0.08f), K.WRAP, K.WRAP)
        card.add(top)
        card.add(input)
        val senderRow = K.row(ctx).apply {
            background = K.rounded(ctx, T.SURFACE_2, T.R_INNER)
            setPadding(K.dp(ctx, 10), 0, K.dp(ctx, 8), 0)
            add(K.icon(ctx, "PERSON_OUTLINE", 20f, T.FAINT), K.WRAP, K.WRAP, r = 4)
            add(sender, 0, K.WRAP, 1f)
        }
        card.add(senderRow, l = 12, r = 12)
        val actions = K.row(ctx)
        actions.setPadding(K.dp(ctx, 12), K.dp(ctx, 12), K.dp(ctx, 12), K.dp(ctx, 12))
        actions.add(K.iconButton(ctx, "CONTENT_PASTE") { paste() }, K.dp(ctx, 48), K.dp(ctx, 48), r = 8)
        actions.add(K.iconButton(ctx, "CLEAR") { clear() }, K.dp(ctx, 48), K.dp(ctx, 48), r = 8)
        actions.add(scanBtn, 0, K.dp(ctx, 48), 1f)
        card.add(actions)
        return card
    }

    private fun renderExamples() {
        examples.removeAllViews()
        val head = K.row(ctx)
        head.add(K.overline(ctx, "Or try an example"), 0, K.WRAP, 1f)
        head.add(K.caption(ctx, "Tap to scan", 12f), K.WRAP, K.WRAP)
        examples.add(head)
        val list = ResultPanel.objects(Repo.samples)
        var row: LinearLayout? = null
        list.forEachIndexed { i, s ->
            if (i % 2 == 0) { row = K.row(ctx); examples.add(row!!, t = 10) }
            row!!.add(sampleTile(s), 0, K.dp(ctx, 82), 1f, l = if (i % 2 == 0) 0 else 10)
        }
        if (list.size % 2 == 1) row?.add(K.space(ctx), 0, 1, 1f, l = 10)
        if (list.isEmpty()) examples.add(K.caption(ctx, "Examples load when the app connects to the server."), t = 10)
    }

    private fun sampleTile(s: JSONObject): View {
        val legit = s.optString("expected") == "legit"
        val r = T.risk(if (legit) "low" else "high")
        return K.row(ctx).apply {
            background = K.rounded(ctx, T.SURFACE, T.R_INNER, T.LINE)
            setPadding(K.dp(ctx, 10), 0, K.dp(ctx, 10), 0)
            add(K.squircle(ctx, if (legit) "CHECK_CIRCLE_OUTLINE" else "SMS_FAILED_OUTLINED", r.color, 36, r.bg),
                K.dp(ctx, 36), K.dp(ctx, 36), r = 10)
            val t = K.col(ctx)
            t.add(K.text(ctx, s.optString("title"), 13.5f, 600, maxLines = 2))
            t.add(K.text(ctx, if (legit) "Genuine" else "Scam", 11.5f, 700, r.color), t = 2)
            add(t, 0, K.WRAP, 1f)
            K.pressable(this, T.R_INNER) { useSample(s) }
        }
    }

    // ---- actions ----------------------------------------------------------------------------------------
    fun focusInput() {
        app.showTab("scan")
        scroll.post {
            scroll.smoothScrollTo(0, 0)
            input.requestFocus()
            (app.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager)
                .showSoftInput(input, InputMethodManager.SHOW_IMPLICIT)
        }
    }

    fun goToExamples() {
        app.showTab("scan")
        scrollTo(examples)
    }

    private fun useSample(s: JSONObject) {
        input.setText(s.optString("text"))
        sender.setText(s.optString("sender").takeIf { it != "null" } ?: "")
        scan()
    }

    /** Fills the box with text shared from another app and checks it straight away. */
    fun checkShared(text: String, from: String? = null) {
        app.showTab("scan")
        input.setText(text.trim().take(5000))
        sender.setText(from ?: "")
        scan()
    }

    fun pasteAndScan() {
        app.showTab("scan")
        if (paste()) scan()
    }

    private fun paste(): Boolean {
        val cm = app.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = cm.primaryClip
        val t = if (clip != null && clip.itemCount > 0) clip.getItemAt(0).coerceToText(app)?.toString()?.trim().orEmpty() else ""
        if (t.isEmpty()) {
            app.snack("Clipboard is empty. Long-press a message → Copy, then try again.")
            return false
        }
        input.setText(t.take(5000))
        input.setSelection(input.text.length)
        return true
    }

    private fun clear() {
        seq++                 // forget any scan still running
        scanBtn.alpha = 1f
        input.setText("")
        sender.setText("")
        results.removeAllViews()
        status.removeAllViews()
    }

    private fun hideKeyboard() {
        (app.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager).hideSoftInputFromWindow(input.windowToken, 0)
        input.clearFocus(); sender.clearFocus()
    }

    fun scan() {
        val text = input.text.toString().trim()
        if (text.isEmpty()) { app.snack("Paste a message first."); return }
        val mine = ++seq
        hideKeyboard()
        scanBtn.alpha = 0.6f
        results.removeAllViews()
        showLoading()
        scrollTo(status)
        val from = sender.text.toString().trim().ifEmpty { null }
        Repo.analyze(ctx, text, from) { res ->
            if (mine != seq) return@analyze  // a newer scan was started meanwhile
            scanBtn.alpha = 1f
            status.removeAllViews()
            val a = res.analysis
            if (a != null) {
                Prefs(ctx).addScan(a)
                showResult(a, res.offline)
            } else {
                showError(res.error ?: "Something went wrong.", res.offline)
                scrollTo(status)
            }
        }
    }

    private fun showResult(a: JSONObject, offline: Boolean) {
        results.removeAllViews()
        results.add(ResultPanel.build(ctx, a, app.actions, offline), t = 0)
        scrollTo(results)
    }

    private fun showLoading() {
        status.removeAllViews()
        val card = K.card(ctx, 20)
        val top = K.row(ctx)
        top.add(ProgressBar(ctx).apply {
            isIndeterminate = true
            indeterminateTintList = android.content.res.ColorStateList.valueOf(T.SAFE)
        }, K.dp(ctx, 26), K.dp(ctx, 26), r = 14)
        val t = K.col(ctx)
        t.add(K.text(ctx, "Checking this message…", 15.5f, 700))
        t.add(K.caption(ctx, "This usually takes a second or two.", 12.5f), t = 1)
        top.add(t, 0, K.WRAP, 1f)
        card.add(top)
        val chips = FlowLayout(ctx)
        for ((ic, label) in listOf("RULE" to "Warning signs", "PSYCHOLOGY" to "AI layers", "PUBLIC" to "Security databases")) {
            chips.addView(K.row(ctx).apply {
                background = K.rounded(ctx, T.tint(T.SAFE, 0.14f), 999f)
                setPadding(K.dp(ctx, 10), K.dp(ctx, 6), K.dp(ctx, 10), K.dp(ctx, 6))
                add(K.icon(ctx, ic, 15f, T.SAFE), K.WRAP, K.WRAP, r = 5)
                add(K.text(ctx, label, 12f, 600, T.SAFE), K.WRAP, K.WRAP)
            })
        }
        card.add(chips, t = 14)
        card.add(K.skeleton(ctx, 12), t = 14)
        card.add(K.skeleton(ctx, 12, 220), t = 8)
        status.add(card)
        K.enter(card)
    }

    private fun showError(msg: String, offline: Boolean) {
        val color = if (offline) T.WARN else T.MUTED
        val card = K.card(ctx, T.PAD, if (offline) T.tint(T.WARN, 0.10f) else T.SURFACE, T.tint(color, 0.3f))
        val r = K.row(ctx)
        r.add(K.squircle(ctx, if (offline) "CLOUD_OFF" else "INFO_OUTLINE", color, 40, T.SURFACE), K.dp(ctx, 40), K.dp(ctx, 40), r = 12)
        r.add(K.body(ctx, msg, 13.5f), 0, K.WRAP, 1f)
        card.add(r)
        if (offline) card.add(K.button(ctx, "Server settings", K.Style.LINK, "DNS_OUTLINED") { app.openSettings() }, K.WRAP, K.WRAP, t = 6)
        status.add(card)
        K.enter(card)
    }
}
