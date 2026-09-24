package com.fraudlens.shield

import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import com.fraudlens.shield.K.add
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// =====================================================================================================
// Learn: spot-the-scam quiz plus 30-second lessons for every trick.
// =====================================================================================================
class LearnTab(app: MainActivity) : Tab(app) {
    private val quizBox = K.card(app, 20)
    private val lessons = K.col(app)
    private val lessonsBlock = K.col(app)
    private var qIndex = 0
    private var score = 0
    private var answered = false
    private var built = false
    private var quizCount = -1

    override fun render() {
        if (!built) {
            built = true
            content.add(K.pageHeader(ctx, "Train your scam radar",
                "Every scam uses the same few tricks. Learn to spot them in 30 seconds each.", "Learn"))
            content.add(quizBox, t = 18)
            lessonsBlock.add(K.sectionHeader(ctx, "The tricks scammers use"))
            val card = K.card(ctx).apply { setPadding(K.dp(ctx, 18), K.dp(ctx, 14), K.dp(ctx, 18), K.dp(ctx, 8)) }
            card.add(K.caption(ctx, "Tap a trick to open its lesson.", 13f))
            card.add(lessons, t = 4)
            lessonsBlock.add(card, t = 10)
            content.add(lessonsBlock, t = 18)
        }
        if (quizCount != Repo.quiz.length()) {  // new content arrived: restart the quiz
            quizCount = Repo.quiz.length()
            qIndex = 0; score = 0
            renderQuestion()
        }
        renderLessons()
    }

    fun goToLessons() {
        app.showTab("learn")
        scrollTo(lessonsBlock)
    }

    private fun renderLessons() {
        lessons.removeAllViews()
        val list = ResultPanel.objects(Repo.tactics)
        list.forEachIndexed { i, t ->
            if (i > 0) lessons.add(K.divider(ctx))
            val color = T.lighten(T.parse(t.optString("color")))
            val body = K.col(ctx)
            body.add(K.body(ctx, t.optString("lesson"), 14f))
            val safe = K.row(ctx, Gravity.TOP).apply {
                background = K.rounded(ctx, T.tint(T.SAFE, 0.10f), T.R_INNER)
                K.pad(this, 12)
                add(K.icon(ctx, "CHECK_CIRCLE", 18f, T.SAFE_TEXT), K.WRAP, K.WRAP, r = 8)
                add(K.text(ctx, t.optString("safe_action"), 13.5f, 600), 0, K.WRAP, 1f)
            }
            body.add(safe, t = 10)
            val ex = ResultPanel.strings(t.optJSONArray("examples"))
            if (ex.isNotEmpty()) body.add(K.text(ctx, "Sounds like: " + ex.joinToString(", ") { "“$it”" }, 12.5f,
                color = T.MUTED, italic = true), t = 10)
            lessons.add(K.expandable(ctx, K.squircle(ctx, t.optString("icon", "WARNING_AMBER"), color, 40),
                t.optString("label"), t.optString("short"), null, 54, body))
        }
        if (list.isEmpty()) lessons.add(K.caption(ctx, "Lessons load when the app connects to the server."), t = 8)
    }

    private fun renderQuestion() {
        quizBox.removeAllViews()
        val quiz = ResultPanel.objects(Repo.quiz)
        if (quiz.isEmpty()) {
            val r = K.row(ctx)
            r.add(K.squircle(ctx, "CLOUD_OFF", T.MUTED, 40), K.dp(ctx, 40), K.dp(ctx, 40), r = 12)
            r.add(K.body(ctx, "The quiz loads when the app connects to the server.", 14f, T.MUTED), 0, K.WRAP, 1f)
            quizBox.add(r)
            return
        }
        if (qIndex >= quiz.size) {
            val r = K.row(ctx)
            r.add(K.squircle(ctx, "EMOJI_EVENTS", T.SAFE_TEXT, 52, T.tint(T.SAFE, 0.12f)), K.dp(ctx, 52), K.dp(ctx, 52), r = 14)
            val t = K.col(ctx)
            t.add(K.text(ctx, "Quiz complete!", 16f, 600))
            t.add(K.text(ctx, "You scored $score / ${quiz.size}.", 15f, 700, T.SAFE_TEXT), t = 2)
            r.add(t, 0, K.WRAP, 1f)
            quizBox.add(r)
            quizBox.add(K.caption(ctx, "Scammers change their words, not their tricks. Keep an eye out for urgency, secrecy and " +
                "requests for codes.", 13.5f), t = 14)
            quizBox.add(K.button(ctx, "Play again", K.Style.SECONDARY, "REPLAY") { qIndex = 0; score = 0; renderQuestion() },
                K.WRAP, K.WRAP, t = 14)
            K.enter(quizBox)
            return
        }
        val q = quiz[qIndex]
        answered = false
        quizBox.add(K.sectionTitle(ctx, "Spot the scam", "Read the message, then pick the biggest red flag.",
            trailing = K.pill(ctx, String.format("%02d/%02d", qIndex + 1, quiz.size), T.SAFE_TEXT)))
        quizBox.add(BarView(ctx, (qIndex + 1f) / quiz.size, T.SAFE, T.SURFACE_2), K.MATCH, K.dp(ctx, 4), t = 14)
        quizBox.add(K.body(ctx, q.optString("message"), 14.5f).apply {
            background = K.corners(ctx, T.SURFACE_2, 2f, 12f, 12f, 12f, T.LINE)
            K.pad(this, 16)
        }, t = 14)
        quizBox.add(K.text(ctx, q.optString("question"), 15.5f, 700), t = 14)
        val options = ResultPanel.strings(q.optJSONArray("options"))
        val buttons = mutableListOf<LinearLayout>()
        val feedback = K.col(ctx)
        options.forEachIndexed { i, opt ->
            val b = option(i, opt)
            K.pressable(b, T.R_INNER) { answer(q, i, buttons, feedback) }
            buttons.add(b)
            quizBox.add(b, t = 10)
        }
        quizBox.add(feedback, t = 12)
    }

    private fun option(i: Int, label: String): LinearLayout = K.row(ctx).apply {
        background = K.rounded(ctx, T.SURFACE_2, T.R_INNER, T.LINE)
        K.pad(this, 12)
        val letter = K.mono(ctx, "ABCDEFG"[i].toString(), 12f, T.TEXT, bold = true, spacing = 0f).apply {
            gravity = Gravity.CENTER
            background = K.rounded(ctx, T.SURFACE_2, 7f, T.LINE)
        }
        add(letter, K.dp(ctx, 28), K.dp(ctx, 28), r = 12)
        add(K.text(ctx, label, 14.5f, 500), 0, K.WRAP, 1f)
    }

    private fun answer(q: JSONObject, i: Int, buttons: List<LinearLayout>, feedback: LinearLayout) {
        if (answered) return
        answered = true
        val right = q.optInt("answer")
        val correct = i == right
        if (correct) score++
        buttons.forEachIndexed { idx, b ->
            when (idx) {
                right -> b.background = K.rounded(ctx, T.tint(T.SAFE, 0.10f), T.R_INNER, T.SAFE, 1.5f)
                i -> b.background = K.rounded(ctx, T.tint(T.FRAUD, 0.10f), T.R_INNER, T.FRAUD, 1.5f)
            }
        }
        val color = if (correct) T.SAFE_TEXT else T.FRAUD_TEXT
        val box = K.inner(ctx, 16, if (correct) T.tint(T.SAFE, 0.10f) else T.tint(T.FRAUD, 0.10f))
        val head = K.row(ctx)
        head.add(K.icon(ctx, if (correct) "CHECK_CIRCLE" else "CANCEL", 22f, color), K.WRAP, K.WRAP, r = 8)
        head.add(K.text(ctx, if (correct) "Correct!" else "Not quite.", 16f, 800, color), K.WRAP, K.WRAP)
        box.add(head)
        box.add(K.body(ctx, q.optString("explanation"), 14f), t = 10)
        box.add(K.button(ctx, "Next", K.Style.PRIMARY, "ARROW_FORWARD") { qIndex++; renderQuestion() },
            K.WRAP, K.WRAP, t = 12, gravity = Gravity.END)
        feedback.add(box)
        K.enter(box)
    }
}

// =====================================================================================================
// History: your numbers, and every check or Shield alert, newest first.
// =====================================================================================================
class HistoryTab(app: MainActivity) : Tab(app) {
    private var filter = "all"   // all | scans | shield
    private val fmt = SimpleDateFormat("dd MMM, HH:mm", Locale.getDefault())

    override fun onShow() { dirty = false; render() }

    override fun render() {
        content.removeAllViews()
        val all = Repo.timeline(ctx)
        content.add(K.pageHeader(ctx, "Your protection", "What FraudLens has done for you so far.", "History"))
        val stats = K.row(ctx)
        stats.add(stat(all.size, "Checked", T.MUTED, "DOCUMENT_SCANNER_OUTLINED"), 0, K.WRAP, 1f)
        stats.add(stat(all.count { it.level == "high" }, "Scams found", T.FRAUD_TEXT, "GPP_BAD_OUTLINED"), 0, K.WRAP, 1f, l = 10)
        stats.add(stat(all.count { it.level == "low" }, "Looked safe", T.SAFE_TEXT, "VERIFIED_USER_OUTLINED"), 0, K.WRAP, 1f, l = 10)
        content.add(stats, t = 18)

        if (all.isEmpty()) {
            content.add(empty(), t = T.GAP)
            return
        }
        val chips = K.row(ctx)
        for ((key, label) in listOf("all" to "All", "scans" to "Your checks", "shield" to "Shield alerts")) {
            val on = filter == key
            val chip = K.text(ctx, label, 13f, 600, if (on) T.SAFE_TEXT else T.MUTED).apply {
                background = K.rounded(ctx, if (on) T.tint(T.SAFE, 0.14f) else T.SURFACE, 999f, if (on) T.tint(T.SAFE, 0.35f) else T.LINE)
                setPadding(K.dp(ctx, 14), K.dp(ctx, 8), K.dp(ctx, 14), K.dp(ctx, 8))
            }
            K.pressable(chip, 999f) { filter = key; render() }
            chips.add(chip, K.WRAP, K.WRAP, r = 8)
        }
        content.add(chips, t = 18)
        val shown = all.filter { filter == "all" || (filter == "shield") == it.fromShield }
        val card = K.card(ctx).apply { setPadding(K.dp(ctx, 16), K.dp(ctx, 6), K.dp(ctx, 16), K.dp(ctx, 6)) }
        if (shown.isEmpty()) card.add(K.caption(ctx, if (filter == "shield") "Shield hasn't warned you about anything yet."
                                                    else "You haven't checked a message yet.", 13f), t = 10, b = 10)
        shown.forEachIndexed { i, e ->
            if (i > 0) card.add(K.divider(ctx))
            card.add(row(e))
        }
        content.add(card, t = 12)
        content.add(K.button(ctx, "Clear history", K.Style.LINK, "DELETE_OUTLINE") {
            Sheets.confirm(app, "Clear history?", "This removes your checks and Shield's alerts from this phone.", "Clear") {
                Prefs(ctx).clearHistory()
                render()
                app.snack("History cleared.")
            }
        }, K.WRAP, K.WRAP, t = 8, gravity = Gravity.CENTER_HORIZONTAL)
    }

    private fun stat(v: Int, label: String, color: Int, icon: String): View = K.card(ctx, 14).apply {
        val top = K.row(ctx)
        top.add(K.icon(ctx, icon, 16f, color), K.WRAP, K.WRAP)
        top.add(K.space(ctx), 0, 1, 1f)
        top.add(K.dot(ctx, color, 6), K.dp(ctx, 6), K.dp(ctx, 6))
        add(top)
        add(K.mono(ctx, String.format("%02d", v), 26f, T.TEXT, bold = true, spacing = 0f), t = 6)
        add(K.mono(ctx, label.uppercase(), 9.5f, T.MUTED, spacing = 0.08f), t = 6)
    }

    private fun row(e: Entry): View {
        val r = T.risk(e.level)
        val row = K.row(ctx)
        row.setPadding(K.dp(ctx, 2), K.dp(ctx, 12), K.dp(ctx, 2), K.dp(ctx, 12))
        val ring = FrameLayout(ctx)
        ring.addView(RingView(ctx, 3f).apply { color = r.fill; setValue(e.score / 100f, animate = false) },
            FrameLayout.LayoutParams(K.MATCH, K.MATCH))
        ring.addView(K.mono(ctx, "${e.score}", 13f, r.color, bold = true, spacing = 0f).apply { gravity = Gravity.CENTER },
            FrameLayout.LayoutParams(K.MATCH, K.MATCH))
        row.add(ring, K.dp(ctx, 46), K.dp(ctx, 46), r = 14)
        val t = K.col(ctx)
        val top = K.row(ctx)
        top.add(K.text(ctx, e.title, 14.5f, 700, maxLines = 1), 0, K.WRAP, 1f)
        top.add(K.mono(ctx, if (e.time > 0) fmt.format(Date(e.time)).uppercase() else "", 10f, T.MUTED), K.WRAP, K.WRAP, l = 8)
        t.add(top)
        val preview = e.preview.replace('\n', ' ')
        t.add(K.caption(ctx, if (preview.length > 90) preview.take(90) + "…" else preview, 12.5f).apply { maxLines = 2 }, t = 4)
        val tags = K.row(ctx)
        tags.add(K.pill(ctx, r.label.uppercase(), r.color, r.bg, 10.5f), K.WRAP, K.WRAP)
        if (e.fromShield) {
            tags.add(K.pill(ctx, "SHIELD · ${e.source.uppercase()}", T.MUTED, T.SURFACE_2, 10.5f,
                if (e.isCall) "CALL_OUTLINED" else "SHIELD"), K.WRAP, K.WRAP, l = 6)
        }
        t.add(tags, t = 6)
        row.add(t, 0, K.WRAP, 1f)
        row.add(K.icon(ctx, "CHEVRON_RIGHT", 20f, T.FAINT), K.WRAP, K.WRAP, l = 6)
        K.pressable(row, T.R_INNER) { app.openEntry(e) }
        return row
    }

    private fun empty(): View = K.card(ctx, 28).apply {
        gravity = Gravity.CENTER_HORIZONTAL
        add(K.squircle(ctx, "HISTORY", T.MUTED, 52), K.dp(ctx, 52), K.dp(ctx, 52), gravity = Gravity.CENTER_HORIZONTAL)
        add(K.text(ctx, "No checks yet", 16f, 700).apply { gravity = Gravity.CENTER }, t = 10)
        add(K.caption(ctx, "Messages you check, and anything Shield warns you about, appear here. Your history stays on this phone.",
            13.5f).apply { gravity = Gravity.CENTER }, t = 6)
        add(K.button(ctx, "Check a message", K.Style.PRIMARY, "DOCUMENT_SCANNER") { app.scanTab.focusInput() },
            K.WRAP, K.WRAP, t = 14, gravity = Gravity.CENTER_HORIZONTAL)
    }
}
