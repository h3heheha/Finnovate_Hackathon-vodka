package com.fraudlens.shield

import android.content.Context
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.BackgroundColorSpan
import android.text.style.ForegroundColorSpan
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import com.fraudlens.shield.K.add
import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.roundToInt

/** What the buttons inside a result do. Implemented once in [Actions]. */
interface ResultActions {
    fun openUrl(url: String)
    fun officialContact(orgId: String?)
    fun askGuardian(analysis: JSONObject?)
    fun copy(text: String, what: String)
    fun report(analysis: JSONObject, label: String)
}

/**
 * The analysis result, built from the /analyze response. Order follows what a worried person needs first:
 *  1. verdict   2. Scam X-Ray   3. what to do now   4. warning signs   5. threat intelligence
 *  6. how FraudLens decided   7. reply safely & report   8. privacy / engine footer
 */
object ResultPanel {
    private val SOURCE_NAMES = mapOf("URLhaus" to "abuse.ch URLhaus", "RDAP" to "Domain registry (RDAP)")

    fun build(ctx: Context, a: JSONObject, actions: ResultActions, offline: Boolean = false,
              source: String? = null): LinearLayout {
        val tactics = objects(a.optJSONArray("tactics"))
        val byId = tactics.associateBy { it.optString("tactic") }
        val parts = listOfNotNull(
            header(ctx, a, source),
            xray(ctx, a, tactics, byId),
            nextSteps(ctx, a, actions),
            warningSigns(ctx, a, tactics),
            intelCard(ctx, a),
            verificationCard(ctx, a),
            respondCard(ctx, a, actions),
            footer(ctx, a, offline),
        )
        return stack(ctx, parts)
    }

    /** Result for a call Shield flagged while the phone was ringing (no message to analyse). */
    fun buildCall(ctx: Context, alert: JSONObject, actions: ResultActions, source: String?): LinearLayout {
        val call = alert.optJSONObject("call") ?: JSONObject()
        val level = alert.optString("level", call.optString("risk_level", "low"))
        val r = T.risk(level)
        val number = alert.optString("sender")
        val head = railCard(ctx, r.fill) { body ->
            body.add(topLine(ctx, r, "CALLER CHECK"))
            if (source != null) body.add(K.mono(ctx, source.uppercase(), 10f, T.SAFE_TEXT, spacing = 0.08f), t = 10)
            val mid = K.row(ctx)
            val texts = K.col(ctx)
            texts.add(K.text(ctx, alert.optString("verdict").ifBlank { call.optString("headline", "Suspicious caller") }, 20f, 700))
            texts.add(K.mono(ctx, number, 13f, T.TEXT), t = 8)
            mid.add(texts, 0, K.WRAP, 1f)
            mid.add(scoreRing(ctx, alert.optInt("score"), r), K.dp(ctx, 86), K.dp(ctx, 86), l = 14)
            body.add(mid, t = 14)
        }
        val reasons = K.card(ctx)
        reasons.add(K.sectionTitle(ctx, "Why this caller was flagged", null, "PHONE_IN_TALK_OUTLINED", r.color))
        val list = call.optJSONArray("reasons")
        if (list == null || list.length() == 0) reasons.add(K.caption(ctx, alert.optString("summary")), t = 10)
        else for (i in 0 until list.length()) reasons.add(K.body(ctx, "• " + list.optString(i), 14f), t = 8)
        val todo = K.card(ctx)
        todo.add(K.sectionTitle(ctx, "What to do now", null, "CHECKLIST", T.SAFE_TEXT))
        todo.add(K.body(ctx, "Don't share codes or card details. If they say they're your bank, hang up and call the " +
            "number printed on your card.", 14f), t = 10)
        todo.add(K.button(ctx, "Official contact", K.Style.LINK, "VERIFIED") { actions.officialContact(null) }, K.WRAP, K.WRAP, t = 6)
        return stack(ctx, listOf(head, reasons, todo))
    }

    private fun stack(ctx: Context, parts: List<View>): LinearLayout = K.col(ctx).apply {
        parts.forEachIndexed { i, v ->
            add(v, t = if (i == 0) 0 else T.GAP)
            K.enter(v, i * 50L)
        }
    }

    // ---- 1. verdict --------------------------------------------------------------------------------------
    private fun railCard(ctx: Context, fill: Int, fillBody: (LinearLayout) -> Unit): FrameLayout {
        val frame = FrameLayout(ctx)
        frame.background = K.rounded(ctx, T.SURFACE, T.R_CARD, T.tint(fill, 0.35f))
        K.clipRounded(frame, T.R_CARD)
        val body = K.col(ctx)
        body.setPadding(K.dp(ctx, 22), K.dp(ctx, 18), K.dp(ctx, 18), K.dp(ctx, 18))
        fillBody(body)
        frame.addView(body, FrameLayout.LayoutParams(K.MATCH, K.WRAP))
        frame.addView(View(ctx).apply { setBackgroundColor(fill) }, FrameLayout.LayoutParams(K.dp(ctx, 4), K.MATCH))
        return frame
    }

    private fun topLine(ctx: Context, r: T.Risk, right: String): LinearLayout = K.row(ctx).apply {
        add(K.statusChip(ctx, r.label, r.color), K.WRAP, K.WRAP)
        add(K.space(ctx), 0, 1, 1f)
        add(K.mono(ctx, right, 10f, T.MUTED, spacing = 0.12f), K.WRAP, K.WRAP)
    }

    private fun scoreRing(ctx: Context, score: Int, r: T.Risk): FrameLayout = FrameLayout(ctx).apply {
        val ring = RingView(ctx, 5f).apply { color = r.fill; trackColor = T.SURFACE_2; setValue(score / 100f) }
        addView(ring, FrameLayout.LayoutParams(K.MATCH, K.MATCH))
        val c = K.col(ctx).apply { gravity = Gravity.CENTER }
        c.add(K.mono(ctx, "$score", 26f, r.color, bold = true, spacing = -0.02f), K.WRAP, K.WRAP, gravity = Gravity.CENTER_HORIZONTAL)
        c.add(K.mono(ctx, "/100", 10f, T.MUTED), K.WRAP, K.WRAP, gravity = Gravity.CENTER_HORIZONTAL)
        addView(c, FrameLayout.LayoutParams(K.MATCH, K.MATCH))
    }

    private fun header(ctx: Context, a: JSONObject, source: String?): View {
        val r = T.risk(a.optString("risk_level", "low"))
        return railCard(ctx, r.fill) { body ->
            body.add(topLine(ctx, r, "FRAUDLENS VERDICT"))
            if (source != null) body.add(K.mono(ctx, source.uppercase(), 10f, T.SAFE_TEXT, spacing = 0.08f), t = 10)
            val mid = K.row(ctx)
            val texts = K.col(ctx)
            texts.add(K.text(ctx, a.optString("verdict"), 20f, 700).apply { letterSpacing = -0.01f })
            val cat = a.optString("category_label")
            if (cat.isNotBlank()) texts.add(K.pill(ctx, cat.uppercase(), T.MUTED, T.SURFACE_2, 10.5f), K.WRAP, K.WRAP, t = 10)
            mid.add(texts, 0, K.WRAP, 1f)
            mid.add(scoreRing(ctx, a.optInt("risk_score"), r), K.dp(ctx, 86), K.dp(ctx, 86), l = 14)
            body.add(mid, t = 14)
            body.add(K.divider(ctx), t = 14)
            body.add(K.body(ctx, a.optString("summary"), 14f), t = 14)
        }
    }

    // ---- 2. Scam X-Ray -----------------------------------------------------------------------------------
    private fun xray(ctx: Context, a: JSONObject, tactics: List<JSONObject>, byId: Map<String, JSONObject>): View {
        val sb = SpannableStringBuilder()
        val segments = objects(a.optJSONArray("segments"))
        val semi = T.font(ctx, 600)
        if (segments.isEmpty()) sb.append(a.optString("_text"))
        for (seg in segments) {
            val start = sb.length
            sb.append(seg.optString("text"))
            val tid = if (seg.isNull("tactic")) null else seg.optString("tactic")
            val t = if (tid != null) byId[tid] else null
            if (t != null && sb.length > start) {
                val color = T.parse(t.optString("color"))
                val end = sb.length
                sb.setSpan(BackgroundColorSpan(T.tint(color, 0.22f)), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                sb.setSpan(K.FontSpan(semi), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                sb.setSpan(K.UnderlineColorSpan(color, K.dpf(ctx, 2)), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                sb.setSpan(ForegroundColorSpan(T.TEXT), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
        }
        val card = K.card(ctx)
        card.add(K.sectionTitle(ctx, "Scam X-Ray",
            if (tactics.isNotEmpty()) "Highlighted words are the tricks used in this message."
            else "No classic trick words found. See below for what the AI layers detected.", "DOCUMENT_SCANNER"))
        val bubble = K.text(ctx, sb, 15f).apply {
            setTextIsSelectable(true)
            setLineSpacing(0f, 1.3f)
            background = K.corners(ctx, T.SURFACE_2, 2f, 12f, 12f, 12f, T.LINE)
            K.pad(this, 16)
        }
        card.add(bubble, t = 14)
        if (tactics.isNotEmpty()) {
            val legend = FlowLayout(ctx, 6, 6)
            for (t in tactics) {
                val color = T.parse(t.optString("color"))
                legend.addView(K.row(ctx).apply {
                    background = K.rounded(ctx, T.tint(color, 0.10f), 6f)
                    setPadding(K.dp(ctx, 10), K.dp(ctx, 6), K.dp(ctx, 10), K.dp(ctx, 6))
                    add(K.dot(ctx, color, 8), K.dp(ctx, 8), K.dp(ctx, 8))
                    add(K.text(ctx, t.optString("short"), 12f, 600), K.WRAP, K.WRAP, l = 6)
                })
            }
            card.add(legend, t = 14)
        }
        return card
    }

    // ---- 3. what to do now -------------------------------------------------------------------------------
    private fun nextSteps(ctx: Context, a: JSONObject, actions: ResultActions): View? {
        val advice = objects(a.optJSONArray("advice"))
        if (advice.isEmpty()) return null
        val card = K.card(ctx)
        card.add(K.sectionTitle(ctx, "What to do now", null, "CHECKLIST", T.SAFE_TEXT))
        var guardianShown = false  // one "Ask someone you trust" button is enough
        advice.forEachIndexed { i, adv ->
            if (i > 0) card.add(K.divider(ctx))
            val row = K.row(ctx, Gravity.TOP)
            row.setPadding(0, K.dp(ctx, 12), 0, K.dp(ctx, 12))
            val badgeBox = FrameLayout(ctx)
            badgeBox.addView(K.squircle(ctx, T.ADVICE_ICONS[adv.optString("id")] ?: "SHIELD", T.TEXT, 40),
                FrameLayout.LayoutParams(K.dp(ctx, 40), K.dp(ctx, 40), Gravity.BOTTOM or Gravity.START))
            val badge = K.mono(ctx, "${i + 1}", 9.5f, T.ON_ACCENT, bold = true, spacing = 0f).apply {
                gravity = Gravity.CENTER
                background = android.graphics.drawable.GradientDrawable().apply {
                    shape = android.graphics.drawable.GradientDrawable.OVAL
                    setColor(T.SAFE)
                    setStroke(K.dp(ctx, 2), T.SURFACE)
                }
            }
            badgeBox.addView(badge, FrameLayout.LayoutParams(K.dp(ctx, 20), K.dp(ctx, 20), Gravity.TOP or Gravity.END))
            row.add(badgeBox, K.dp(ctx, 46), K.dp(ctx, 46), r = 12)
            val texts = K.col(ctx)
            texts.add(K.text(ctx, adv.optString("title"), 15f, 700))
            texts.add(K.caption(ctx, adv.optString("detail"), 13.5f), t = 3)
            val payload = adv.optJSONObject("payload") ?: JSONObject()
            val action: View? = when (adv.optString("action")) {
                "call_official" -> K.button(ctx, "Official contact", K.Style.LINK, "VERIFIED") {
                    actions.officialContact(payload.optString("org_id").ifBlank { null })
                }
                "open_url" -> payload.optString("url").takeIf { it.startsWith("http") }?.let { url ->
                    K.button(ctx, "Open official website", K.Style.LINK, "OPEN_IN_NEW") { actions.openUrl(url) }
                }
                "verify_contact", "share_guardian" -> if (guardianShown) null else {
                    guardianShown = true
                    K.button(ctx, "Ask someone you trust", K.Style.LINK, "GROUPS") { actions.askGuardian(a) }
                }
                else -> null
            }
            if (action != null) texts.add(action, K.WRAP, K.WRAP, t = 2)
            row.add(texts, 0, K.WRAP, 1f)
            card.add(row)
        }
        return card
    }

    // ---- 4. warning signs --------------------------------------------------------------------------------
    private fun warningSigns(ctx: Context, a: JSONObject, tactics: List<JSONObject>): View {
        val level = a.optString("risk_level", "low")
        if (tactics.isEmpty()) {
            val card = K.card(ctx)
            val row = K.row(ctx)
            if (level != "low") {
                row.add(K.squircle(ctx, "PSYCHOLOGY", T.risk(level).color, 40), K.dp(ctx, 40), K.dp(ctx, 40), r = 12)
                row.add(K.body(ctx, "No classic trick words. This message was flagged by the AI layers, which recognise " +
                    "scams by meaning, not keywords.", 13.5f), 0, K.WRAP, 1f)
            } else {
                row.add(K.squircle(ctx, "CHECK_CIRCLE", T.SAFE_TEXT, 40), K.dp(ctx, 40), K.dp(ctx, 40), r = 12)
                row.add(K.text(ctx, "No warning signs found.", 15f, 600), 0, K.WRAP, 1f)
            }
            card.add(row)
            return card
        }
        val card = K.card(ctx)
        card.add(K.sectionTitle(ctx, "Warning signs (${tactics.size})",
            "Points show how much each sign adds to the score. Tap a sign to see the evidence.",
            "WARNING_AMBER_ROUNDED", T.WARN))
        val list = K.col(ctx)
        tactics.forEachIndexed { i, t ->
            if (i > 0) list.add(K.divider(ctx))
            val color = T.lighten(T.parse(t.optString("color")))
            val body = K.col(ctx)
            val evidence = strings(t.optJSONArray("evidence")).take(3)
            if (evidence.isNotEmpty()) {
                body.add(K.text(ctx, evidence.joinToString(", ") { "“$it”" }, 13f, 500, color, italic = true))
            }
            for (d in strings(t.optJSONArray("details")).take(2)) body.add(K.caption(ctx, d, 13f), t = 4)
            list.add(K.expandable(ctx, K.squircle(ctx, t.optString("icon", "WARNING_AMBER"), color, 40),
                t.optString("label"), t.optString("description"),
                K.pill(ctx, "+${t.optInt("contribution")}", color), 54, body))
        }
        card.add(list, t = 8)
        val combos = strings(a.optJSONObject("engine")?.optJSONArray("combos"))
        if (combos.isNotEmpty()) {
            val box = K.inner(ctx, 12, T.tint(T.FRAUD, 0.10f))
            val head = K.row(ctx)
            head.add(K.icon(ctx, "BOLT", 18f, T.FRAUD_TEXT), K.WRAP, K.WRAP, r = 6)
            head.add(K.text(ctx, "Dangerous combinations", 13.5f, 700, T.FRAUD_TEXT), K.WRAP, K.WRAP)
            box.add(head)
            for (c in combos) box.add(K.body(ctx, "• $c", 13f), t = 4)
            card.add(box, t = 8)
        }
        return card
    }

    // ---- 5. threat intelligence -----------------------------------------------------------------------------
    private fun intelCard(ctx: Context, a: JSONObject): View? {
        val intel = a.optJSONObject("intel") ?: return null
        val findings = objects(intel.optJSONArray("findings"))
        val expanded = intel.optJSONObject("expanded_links") ?: JSONObject()
        if (!intel.optBoolean("enabled") || (findings.isEmpty() && expanded.length() == 0)) return null
        val card = K.card(ctx)
        val ms = intel.optInt("latency_ms")
        card.add(K.sectionTitle(ctx, "Threat intelligence",
            "Links and numbers checked live against security databases" + (if (ms > 0) " in $ms ms." else "."), "PUBLIC"))
        if (intel.optBoolean("blocklisted")) {
            val warn = K.row(ctx).apply {
                background = K.rounded(ctx, T.tint(T.FRAUD, 0.14f), T.R_INNER, T.tint(T.FRAUD, 0.5f))
                K.pad(this, 14)
                add(K.icon(ctx, "GPP_BAD", 22f, T.FRAUD_TEXT), K.WRAP, K.WRAP, r = 10)
                add(K.text(ctx, "This link is on a security blocklist. Do not open it.", 14f, 700, T.FRAUD_TEXT), 0, K.WRAP, 1f)
            }
            card.add(warn, t = 12)
        }
        val keys = expanded.keys()
        while (keys.hasNext()) {
            val short = keys.next()
            val box = K.inner(ctx, 12)
            val r = K.row(ctx)
            r.add(K.squircle(ctx, "CALL_SPLIT", T.LAYER_COLORS.getValue("url"), 34, T.SURFACE), K.dp(ctx, 34), K.dp(ctx, 34), r = 10)
            val t = K.col(ctx)
            t.add(K.caption(ctx, "Short link $short", 12.5f).apply { maxLines = 1 })
            t.add(K.text(ctx, "really goes to ${expanded.optString(short)}", 13.5f, 600, maxLines = 2))
            r.add(t, 0, K.WRAP, 1f)
            box.add(r)
            card.add(box, t = 10)
        }
        var first = true
        for (f in findings) {
            if (expanded.length() > 0 && f.optString("title") == "Short link unmasked") continue
            val (color, icon) = when (f.optString("severity")) {
                "danger" -> T.FRAUD_TEXT to "GPP_BAD"
                "warning" -> T.WARN to "GPP_MAYBE"
                else -> T.MUTED to "INFO_OUTLINE"
            }
            if (!first) card.add(K.divider(ctx))
            first = false
            val r = K.row(ctx, Gravity.TOP)
            r.setPadding(0, K.dp(ctx, 10), 0, K.dp(ctx, 10))
            r.add(K.squircle(ctx, icon, color, 36), K.dp(ctx, 36), K.dp(ctx, 36), r = 12)
            val t = K.col(ctx)
            t.add(K.text(ctx, f.optString("title"), 14.5f, 700))
            val detail = f.optString("detail")
            if (detail.isNotBlank() && detail != "null") t.add(K.caption(ctx, detail), t = 2)
            val src = f.optString("source")
            t.add(K.text(ctx, SOURCE_NAMES[src] ?: src, 12f, 600, color), t = 2)
            r.add(t, 0, K.WRAP, 1f)
            card.add(r, t = if (card.childCount == 1) 6 else 0)
        }
        return card
    }

    // ---- 6. how FraudLens decided --------------------------------------------------------------------------
    private fun verificationCard(ctx: Context, a: JSONObject): View? {
        val v = a.optJSONObject("verification") ?: JSONObject()
        val breakdown = objects(a.optJSONArray("score_breakdown"))
        if (!v.optBoolean("enabled") && breakdown.isEmpty()) return null
        val card = K.card(ctx)
        card.add(K.sectionTitle(ctx, "How FraudLens decided",
            "Each layer checks something different. Together they make the ${a.optInt("risk_score")}/100.", "INSIGHTS"))
        val bar = K.row(ctx)
        if (breakdown.isEmpty()) bar.add(View(ctx).apply { setBackgroundColor(T.LINE) }, 0, K.MATCH, 1f)
        breakdown.forEachIndexed { i, b ->
            val color = T.LAYER_COLORS[b.optString("source")] ?: T.MUTED
            bar.add(View(ctx).apply { setBackgroundColor(color) }, 0, K.MATCH, b.optInt("points").coerceAtLeast(1).toFloat(),
                l = if (i == 0) 0 else 3)
        }
        K.clipRounded(bar, 6f)
        card.add(bar, K.MATCH, K.dp(ctx, 12), t = 14)
        for (b in breakdown) {
            val src = b.optString("source")
            val color = T.LAYER_COLORS[src] ?: T.MUTED
            val r = K.row(ctx)
            r.add(K.squircle(ctx, T.LAYER_ICONS[src] ?: "SHIELD", color, 36), K.dp(ctx, 36), K.dp(ctx, 36), r = 12)
            val t = K.col(ctx)
            t.add(K.text(ctx, b.optString("label"), 14f, 600))
            val d = b.optString("detail")
            if (d.isNotBlank() && d != "null") t.add(K.caption(ctx, d, 12.5f))
            r.add(t, 0, K.WRAP, 1f)
            r.add(K.pill(ctx, "+${b.optInt("points")}", color, size = 12f), K.WRAP, K.WRAP, l = 8)
            card.add(r, t = 12)
        }
        if (v.has("classifier_probability") && !v.isNull("classifier_probability")) {
            val p = v.optDouble("classifier_probability").toFloat()
            val c = T.LAYER_COLORS.getValue("classifier")
            val box = K.inner(ctx, 12)
            val r = K.row(ctx)
            r.add(K.caption(ctx, "AI language model", 13f), 0, K.WRAP, 1f)
            r.add(K.text(ctx, "${pct(p)} scam-like wording", 13f, 700, c), K.WRAP, K.WRAP)
            box.add(r)
            box.add(BarView(ctx, p, c, T.tint(c, 0.15f)), K.MATCH, K.dp(ctx, 8), t = 8)
            card.add(box, t = 14)
        }
        for (link in objects(v.optJSONArray("links"))) {
            val lp = link.optDouble("phishing_probability").toFloat()
            val r = K.row(ctx)
            r.add(K.icon(ctx, "LINK", 16f, T.LAYER_COLORS.getValue("url")), K.WRAP, K.WRAP, r = 6)
            r.add(K.text(ctx, link.optString("url"), 13f, maxLines = 1), 0, K.WRAP, 1f)
            r.add(K.pill(ctx, "${pct(lp)} phishing", if (lp >= 0.5f) T.LAYER_COLORS.getValue("url") else T.MUTED), K.WRAP, K.WRAP, l = 6)
            card.add(r, t = 12)
        }
        val similar = objects(v.optJSONArray("similar"))
        if (similar.isNotEmpty()) {
            val cards = K.col(ctx)
            for (m in similar.take(3)) {
                val scam = m.optString("label") == "scam"
                val color = if (scam) T.FRAUD_TEXT else T.SAFE_TEXT
                val who = when (m.optString("source")) {
                    "report" -> "reported ${m.optInt("reports")}×"
                    "training" -> "from training data"
                    else -> "curated example"
                }
                val box = K.inner(ctx, 14)
                val top = K.row(ctx)
                top.add(K.pill(ctx, if (scam) "SCAM" else "GENUINE", color), K.WRAP, K.WRAP, r = 8)
                top.add(K.caption(ctx, m.optString("category_label"), 12f).apply { maxLines = 1 }, 0, K.WRAP, 1f)
                top.add(K.text(ctx, "${pct(m.optDouble("similarity").toFloat())} similar", 12.5f, 700, color), K.WRAP, K.WRAP, l = 6)
                box.add(top)
                box.add(K.text(ctx, m.optString("preview"), 13f, maxLines = 2, italic = true), t = 6)
                box.add(K.text(ctx, who, 11.5f, color = T.MUTED), t = 6)
                cards.add(box, t = if (cards.childCount == 0) 0 else 8)
            }
            val topMatch = similar[0]
            card.add(K.divider(ctx), t = 14)
            card.add(K.expandable(ctx, K.squircle(ctx, "MANAGE_SEARCH", T.LAYER_COLORS.getValue("memory"), 36),
                "Closest known messages",
                "Best match ${pct(topMatch.optDouble("similarity").toFloat())} similar · ${topMatch.optString("category_label")}",
                null, 0, cards))
        }
        for (note in strings(v.optJSONArray("notes"))) {
            val r = K.row(ctx, Gravity.TOP)
            r.add(K.icon(ctx, "INFO_OUTLINE", 16f, T.MUTED), K.WRAP, K.WRAP, r = 6)
            r.add(K.caption(ctx, note, 12.5f), 0, K.WRAP, 1f)
            card.add(r, t = 10)
        }
        if (v.optBoolean("enabled")) {
            val mode = if (v.optString("mode") == "learned") "learned weights" else "default weights"
            val ver = v.optString("model_version").takeIf { it.isNotBlank() && it != "null" }
            card.add(K.text(ctx, "Models: ${v.optString("embedder")} · $mode" + (if (ver != null) " · $ver" else ""),
                11.5f, color = T.MUTED), t = 12)
        }
        return card
    }

    // ---- 7. reply & report ---------------------------------------------------------------------------------
    private fun respondCard(ctx: Context, a: JSONObject, actions: ResultActions): View {
        val card = K.card(ctx)
        val reply = a.optString("verification_reply")
        if (a.optString("risk_level", "low") != "low" && reply.isNotBlank() && reply != "null") {
            card.add(K.sectionTitle(ctx, "Reply safely", "A ready-made answer that puts the burden of proof on the sender.",
                "QUICKREPLY"))
            card.add(K.inner(ctx, 14).apply { add(K.text(ctx, reply, 14.5f, italic = true)) }, t = 12)
            card.add(K.button(ctx, "Copy reply", K.Style.SECONDARY, "CONTENT_COPY") { actions.copy(reply, "Reply") },
                K.WRAP, K.WRAP, t = 10)
            card.add(K.divider(ctx), t = 16, b = 16)
        }
        card.add(K.sectionTitle(ctx, "Help FraudLens learn",
            "Confirmed reports join the scam memory, so the next person is warned instantly.", "GROUPS"))
        val row = K.row(ctx)
        val scam = K.button(ctx, "Report scam", K.Style.DANGER, "FLAG") {}
        val genuine = K.button(ctx, "It's genuine", K.Style.SAFE_OUTLINE, "VERIFIED_USER") {}
        fun lock() { listOf(scam, genuine).forEach { it.isEnabled = false; it.isClickable = false; it.alpha = 0.55f } }
        scam.setOnClickListener { lock(); actions.report(a, "scam") }
        genuine.setOnClickListener { lock(); actions.report(a, "legit") }
        row.add(scam, 0, K.WRAP, 1f)
        row.add(genuine, 0, K.WRAP, 1f, l = 10)
        card.add(row, t = 12)
        return card
    }

    // ---- 8. transparency footer ---------------------------------------------------------------------------
    private fun footer(ctx: Context, a: JSONObject, offline: Boolean): View {
        val p = a.optJSONObject("privacy") ?: JSONObject()
        val e = a.optJSONObject("engine") ?: JSONObject()
        val box = K.col(ctx).apply {
            background = K.rounded(ctx, android.graphics.Color.TRANSPARENT, T.R_CARD, T.LINE)
            setPadding(K.dp(ctx, 16), K.dp(ctx, 14), K.dp(ctx, 16), K.dp(ctx, 14))
        }
        fun line(icon: String, color: Int, s: String) {
            val r = K.row(ctx, Gravity.TOP)
            r.add(K.icon(ctx, icon, 15f, color), K.WRAP, K.WRAP, r = 8)
            r.add(K.caption(ctx, s, 12.5f), 0, K.WRAP, 1f)
            box.add(r, t = if (box.childCount == 0) 0 else 8)
        }
        val hidden = p.optInt("redacted_items")
        line("LOCK", T.SAFE, if (hidden > 0) "$hidden personal detail${if (hidden != 1) "s" else ""} hidden before AI analysis"
                             else "No personal details detected in this message")
        val ai = if (p.optBoolean("ai_used")) p.optString("ai_provider") else "off"
        line("MEMORY", T.SAFE, "Engine ${e.optString("version")} · ${e.optInt("rules_fired")} rules fired · AI: $ai · " +
            "${e.optInt("latency_ms")} ms" + if (offline) " · offline demo" else "")
        for (note in strings(e.optJSONArray("trust_notes"))) line("THUMB_UP_ALT_OUTLINED", T.SAFE_TEXT, note)
        return box
    }

    // ---- JSON helpers -----------------------------------------------------------------------------------------
    fun objects(arr: JSONArray?): List<JSONObject> =
        if (arr == null) emptyList() else (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }

    fun strings(arr: JSONArray?): List<String> =
        if (arr == null) emptyList() else (0 until arr.length()).map { arr.optString(it) }.filter { it.isNotBlank() }

    fun pct(p: Float): String = "${(p * 100).roundToInt()}%"

    /** A short "where it came from" line for Shield alerts: "Caught by Shield · WhatsApp · 24 Sep 14:02". */
    fun shieldSource(alert: JSONObject): String {
        val t = java.text.SimpleDateFormat("dd MMM HH:mm", java.util.Locale.getDefault())
            .format(java.util.Date(alert.optLong("time")))
        return "Caught by Shield · ${alert.optString("app")} · $t"
    }
}
