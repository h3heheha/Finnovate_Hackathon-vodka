package com.fraudlens.shield

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.widget.FrameLayout
import android.widget.ScrollView
import com.fraudlens.shield.K.add
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The full result on its own screen, with the same panel as the Scan tab:
 *  - "See why" from a Shield notification or banner (opens on top of whatever app you were in),
 *  - a History item tapped inside the app.
 */
class DetailActivity : Activity() {
    private lateinit var root: FrameLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Repo.init(this)
        @Suppress("DEPRECATION")
        window.statusBarColor = T.BG
        val inApp = intent.getBooleanExtra(EXTRA_IN_APP, false)
        val actions = Actions(this) { Snack.show(root, it, 24) }

        root = FrameLayout(this).apply {
            setBackgroundColor(T.BG)
            fitsSystemWindows = true  // keep clear of the status and navigation bars (Android 15 edge-to-edge)
        }
        val column = K.col(this)
        val bar = K.row(this).apply {
            setPadding(K.dp(context, 12), K.dp(context, 8), K.dp(context, T.GUTTER), K.dp(context, 8))
            add(K.iconButton(context, "ARROW_BACK", 44) { finish() }, K.dp(context, 44), K.dp(context, 44), r = 12)
        }
        val titles = K.col(this)
        bar.add(titles, 0, K.WRAP, 1f)
        column.add(bar)
        val content = K.col(this)
        content.setPadding(K.dp(this, T.GUTTER), K.dp(this, 4), K.dp(this, T.GUTTER), K.dp(this, 32))
        val scroll = ScrollView(this).apply {
            isVerticalScrollBarEnabled = false
            addView(content, FrameLayout.LayoutParams(K.MATCH, K.WRAP))
        }
        column.add(scroll, K.MATCH, 0, 1f)
        root.addView(column, FrameLayout.LayoutParams(K.MATCH, K.MATCH))
        setContentView(root)

        val alert = intent.getStringExtra(EXTRA_ALERT)?.let { runCatching { JSONObject(it) }.getOrNull() }
        val scan = intent.getStringExtra(EXTRA_ANALYSIS)?.let { runCatching { JSONObject(it) }.getOrNull() }
        when {
            scan != null -> {
                titles.add(K.overline(this, "Scam X-Ray"))
                titles.add(K.text(this, "Your check", 17f, 700), t = 2)
                val t = scan.optLong("_time")
                val source = if (t > 0) "You checked · " + SimpleDateFormat("dd MMM HH:mm", Locale.getDefault()).format(Date(t)) else null
                content.add(ResultPanel.build(this, scan, actions, scan.optString("analysis_id").startsWith("offline-"), source))
            }
            alert != null -> {
                titles.add(K.overline(this, "Shield"))
                titles.add(K.text(this, "Why FraudLens warned you", 17f, 700), t = 2)
                val analysis = alert.optJSONObject("analysis")
                if (analysis != null) {
                    // What reporting and "Ask someone you trust" need: the original message and sender.
                    analysis.put("_text", alert.optString("text")).put("_sender", alert.optString("sender"))
                        .put("_time", alert.optLong("time"))
                    content.add(ResultPanel.build(this, analysis, actions, false, ResultPanel.shieldSource(alert)))
                } else {
                    content.add(ResultPanel.buildCall(this, alert, actions, ResultPanel.shieldSource(alert)))
                }
            }
            else -> {
                titles.add(K.text(this, "Nothing to show", 17f, 700))
                content.add(K.caption(this, "This alert is no longer available."))
            }
        }

        if (!inApp) {  // opened from a notification or the banner: offer the way into the app
            content.add(K.button(this, "Open FraudLens", K.Style.PRIMARY, "SHIELD") {
                startActivity(Intent(this, MainActivity::class.java)
                    .putExtra(MainActivity.EXTRA_TAB, "history")
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
                finish()
            }, t = 16)
        }
        content.add(K.button(this, "Close", K.Style.SECONDARY) { finish() }, t = 10)
        titles.gravity = Gravity.CENTER_VERTICAL
    }

    override fun finish() {
        super.finish()
        if (intent.getBooleanExtra(EXTRA_IN_APP, false)) {
            @Suppress("DEPRECATION")
            overridePendingTransition(android.R.anim.fade_in, android.R.anim.slide_out_right)
        }
    }

    companion object {
        const val EXTRA_ALERT = "alert_json"
        const val EXTRA_ANALYSIS = "analysis_json"
        const val EXTRA_IN_APP = "in_app"

        /** Opens a History entry inside the app (same task, back returns to History). */
        fun forEntry(ctx: Context, e: Entry): Intent {
            val i = Intent(ctx, DetailActivity::class.java).putExtra(EXTRA_IN_APP, true)
            return if (e.fromShield) i.putExtra(EXTRA_ALERT, e.data.toString()) else i.putExtra(EXTRA_ANALYSIS, e.data.toString())
        }
    }
}
