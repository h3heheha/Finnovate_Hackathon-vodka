package com.fraudlens.shield

import android.content.Intent
import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.BackgroundColorSpan
import android.text.style.StyleSpan
import android.text.style.UnderlineSpan
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Toast
import org.json.JSONObject

/**
 * "See why" screen: the Scam X-Ray for an intercepted message or call, built from the API result.
 * Shows highlighted tricks, threat-intelligence findings, how the score was built and what to do.
 */
class DetailActivity : Activity() {

    private lateinit var alert: JSONObject

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        alert = JSONObject(intent.getStringExtra(EXTRA_ALERT) ?: "{}")
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(Ui.dp(this@DetailActivity, 16), Ui.dp(this@DetailActivity, 20),
                Ui.dp(this@DetailActivity, 16), Ui.dp(this@DetailActivity, 32))
        }
        val scroll = ScrollView(this).apply {
            fitsSystemWindows = true
            setBackgroundColor(Color.parseColor(Ui.BG))
            addView(root)
        }
        setContentView(scroll)

        root.addView(header())
        val analysis = alert.optJSONObject("analysis")
        if (analysis != null) {
            root.addView(xray(analysis), Ui.matchWidth(this, 12))
            intelCard(analysis)?.let { root.addView(it, Ui.matchWidth(this, 12)) }
            breakdownCard(analysis)?.let { root.addView(it, Ui.matchWidth(this, 12)) }
            signsCard(analysis)?.let { root.addView(it, Ui.matchWidth(this, 12)) }
            adviceCard(analysis)?.let { root.addView(it, Ui.matchWidth(this, 12)) }
        } else {
            callCard(alert.optJSONObject("call"))?.let { root.addView(it, Ui.matchWidth(this, 12)) }
        }
        root.addView(actions(), Ui.matchWidth(this, 16))
    }

    private fun header(): LinearLayout {
        val level = alert.optString("level", "low")
        val color = Ui.levelText(level)
        val bg = when (level) { "high" -> "#3A1D20"; "medium" -> "#3A2E14"; else -> "#15302A" }
        return Ui.card(this, bg, Ui.levelColor(level)).apply {
            addView(Ui.text(this@DetailActivity, "🛡️ FraudLens · Shield", 12f, true, Ui.MUTED))
            addView(Ui.text(this@DetailActivity, "${alert.optInt("score")}/100", 34f, true, color))
            addView(Ui.text(this@DetailActivity, alert.optString("verdict"), 19f, true))
            addView(Ui.text(this@DetailActivity,
                "From ${alert.optString("sender")} · ${alert.optString("app")}", 13f, false, Ui.MUTED))
            addView(Ui.text(this@DetailActivity, alert.optString("summary"), 14.5f))
        }
    }

    /** The message with every trick highlighted in its tactic colour. */
    private fun xray(analysis: JSONObject): LinearLayout {
        val colors = HashMap<String, Int>()
        val tactics = analysis.optJSONArray("tactics")
        if (tactics != null) for (i in 0 until tactics.length()) {
            val t = tactics.getJSONObject(i)
            colors[t.optString("tactic")] = Color.parseColor(t.optString("color", "#DC2626"))
        }
        val sb = SpannableStringBuilder()
        val segments = analysis.optJSONArray("segments")
        if (segments != null && segments.length() > 0) {
            for (i in 0 until segments.length()) {
                val seg = segments.getJSONObject(i)
                val start = sb.length
                sb.append(seg.optString("text"))
                val tactic = if (seg.isNull("tactic")) null else seg.optString("tactic")
                val c = if (tactic != null) colors[tactic] else null
                if (c != null) {
                    val tint = Color.argb(110, Color.red(c), Color.green(c), Color.blue(c))
                    sb.setSpan(BackgroundColorSpan(tint), start, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                    sb.setSpan(StyleSpan(Typeface.BOLD), start, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                    sb.setSpan(UnderlineSpan(), start, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                }
            }
        } else {
            sb.append(alert.optString("text"))
        }
        return Ui.card(this).apply {
            addView(Ui.text(this@DetailActivity, "Scam X-Ray", 17f, true))
            addView(Ui.text(this@DetailActivity, "Highlighted words are the tricks used in this message.",
                12.5f, false, Ui.MUTED))
            addView(Ui.text(this@DetailActivity, sb, 15.5f))
        }
    }

    private fun intelCard(analysis: JSONObject): LinearLayout? {
        val findings = analysis.optJSONObject("intel")?.optJSONArray("findings") ?: return null
        if (findings.length() == 0) return null
        return Ui.card(this).apply {
            addView(Ui.text(this@DetailActivity, "Threat intelligence", 17f, true))
            for (i in 0 until findings.length()) {
                val f = findings.getJSONObject(i)
                val icon = when (f.optString("severity")) { "danger" -> "⛔"; "warning" -> "⚠️"; else -> "ℹ️" }
                addView(Ui.text(this@DetailActivity, "$icon ${f.optString("title")}", 14.5f, true))
                addView(Ui.text(this@DetailActivity,
                    "${f.optString("detail")}  (${f.optString("source")})", 13f, false, Ui.MUTED))
            }
        }
    }

    private fun breakdownCard(analysis: JSONObject): LinearLayout? {
        val items = analysis.optJSONArray("score_breakdown") ?: return null
        if (items.length() == 0) return null
        return Ui.card(this).apply {
            addView(Ui.text(this@DetailActivity, "How the score was built", 17f, true))
            for (i in 0 until items.length()) {
                val b = items.getJSONObject(i)
                addView(Ui.text(this@DetailActivity, "+${b.optInt("points")}  ${b.optString("label")}", 14.5f, true))
                val d = b.optString("detail")
                if (d.isNotBlank()) addView(Ui.text(this@DetailActivity, d, 12.5f, false, Ui.MUTED))
            }
        }
    }

    private fun signsCard(analysis: JSONObject): LinearLayout? {
        val tactics = analysis.optJSONArray("tactics") ?: return null
        if (tactics.length() == 0) return null
        return Ui.card(this).apply {
            addView(Ui.text(this@DetailActivity, "Warning signs (${tactics.length()})", 17f, true))
            for (i in 0 until tactics.length()) {
                val t = tactics.getJSONObject(i)
                addView(Ui.text(this@DetailActivity, t.optString("label"), 14.5f, true,
                    Ui.lighten(t.optString("color", Ui.RED))))
                addView(Ui.text(this@DetailActivity, t.optString("description"), 13f))
            }
        }
    }

    private fun adviceCard(analysis: JSONObject): LinearLayout? {
        val advice = analysis.optJSONArray("advice") ?: return null
        if (advice.length() == 0) return null
        return Ui.card(this).apply {
            addView(Ui.text(this@DetailActivity, "What to do now", 17f, true))
            for (i in 0 until advice.length()) {
                val a = advice.getJSONObject(i)
                addView(Ui.text(this@DetailActivity, "• ${a.optString("title")}", 14.5f, true))
                addView(Ui.text(this@DetailActivity, a.optString("detail"), 13f, false, Ui.MUTED))
            }
        }
    }

    private fun callCard(call: JSONObject?): LinearLayout? {
        call ?: return null
        val reasons = call.optJSONArray("reasons")
        return Ui.card(this).apply {
            addView(Ui.text(this@DetailActivity, "Why this caller was flagged", 17f, true))
            if (reasons != null) for (i in 0 until reasons.length()) {
                addView(Ui.text(this@DetailActivity, "• ${reasons.optString(i)}", 14f))
            }
            addView(Ui.text(this@DetailActivity,
                "Don't share codes or card details. Hang up and call your bank on the number printed on your card.",
                13f, false, Ui.MUTED))
        }
    }

    private fun actions(): LinearLayout {
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        if (alert.optString("kind") == "message") {
            box.addView(Ui.button(this, "🚩 Report as scam", Ui.RED) { report() }, Ui.matchWidth(this, 0))
        }
        box.addView(Ui.button(this, "Open FraudLens", Ui.TEAL) { openMainApp() }, Ui.matchWidth(this, 8))
        box.addView(Ui.button(this, "Close", Ui.MUTED) { finish() }, Ui.matchWidth(this, 8))
        return box
    }

    private fun report() {
        val prefs = Prefs(this)
        val text = alert.optString("text")
        val sender = alert.optString("sender")
        Thread {
            val msg = try {
                ApiClient(prefs.serverUrl).report(text, sender, prefs.deviceId).optString("message", "Reported")
            } catch (e: Exception) {
                "Couldn't reach the FraudLens server"
            }
            runOnUiThread { Toast.makeText(this, msg, Toast.LENGTH_LONG).show() }
        }.start()
    }

    /** Back to the FraudLens app itself (the same APK), on its main "FraudLens" tab. */
    private fun openMainApp() {
        startActivity(Intent(this, MainActivity::class.java)
            .putExtra(MainActivity.EXTRA_TAB, MainActivity.TAB_APP)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or
                Intent.FLAG_ACTIVITY_SINGLE_TOP))
        finish()
    }

    companion object {
        const val EXTRA_ALERT = "alert_json"
    }
}
