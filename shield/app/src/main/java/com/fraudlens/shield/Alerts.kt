package com.fraudlens.shield

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.Icon
import android.provider.Settings
import org.json.JSONObject

/** Shows the warning: a heads-up notification always, plus the overlay banner when allowed. */
object Alerts {
    private const val CHANNEL_HIGH = "fraudlens_scam_alerts"
    private const val CHANNEL_LOW = "fraudlens_caution"

    fun ensureChannels(ctx: Context) {
        val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(NotificationChannel(CHANNEL_HIGH, "Scam alerts",
            NotificationManager.IMPORTANCE_HIGH).apply {
            description = "Warnings about messages and calls that look like scams"
            enableVibration(true)
        })
        nm.createNotificationChannel(NotificationChannel(CHANNEL_LOW, "Be careful",
            NotificationManager.IMPORTANCE_DEFAULT).apply {
            description = "Messages with some warning signs"
        })
    }

    /** Called with the /analyze result for an intercepted message. */
    fun showMessageAlert(ctx: Context, analysis: JSONObject, text: String, sender: String?, app: String) {
        val score = analysis.optInt("risk_score")
        val level = analysis.optString("risk_level", "low")
        val alert = JSONObject()
            .put("time", System.currentTimeMillis())
            .put("kind", "message")
            .put("app", app)
            .put("sender", sender ?: "Unknown sender")
            .put("text", text)
            .put("score", score)
            .put("level", level)
            .put("verdict", analysis.optString("verdict"))
            .put("summary", analysis.optString("summary"))
            .put("analysis", analysis)
        Prefs(ctx).addAlert(alert)

        val title = if (level == "high") "⚠️ Likely scam from ${sender ?: "unknown sender"}"
                    else "Be careful: message from ${sender ?: "unknown sender"}"
        val body = "Risk $score/100 · ${topReason(analysis)}"
        notify(ctx, alert, title, body, analysis.optString("summary"), level)
        if (level == "high" && canOverlay(ctx)) {
            OverlayBanner.show(ctx, title, body, alert)
        }
    }

    /** Called by the call screener with the /intel/phone result while the phone is ringing. */
    fun showCallAlert(ctx: Context, number: String, result: JSONObject) {
        val level = result.optString("risk_level", "low")
        val reasons = result.optJSONArray("reasons")
        val reason = if (reasons != null && reasons.length() > 0) reasons.optString(0) else "Reported as suspicious"
        val alert = JSONObject()
            .put("time", System.currentTimeMillis())
            .put("kind", "call")
            .put("app", "Phone call")
            .put("sender", number)
            .put("text", "Incoming call from $number")
            .put("score", (result.optDouble("score", 0.0) * 100).toInt())
            .put("level", level)
            .put("verdict", result.optString("headline"))
            .put("summary", reason)
            .put("call", result)
        Prefs(ctx).addAlert(alert)
        val title = "📞 ${result.optString("headline", "Suspicious caller")}"
        val body = "$number · $reason"
        notify(ctx, alert, title, body, body, level)
        if (level == "high" && canOverlay(ctx)) OverlayBanner.show(ctx, title, body, alert)
    }

    fun canOverlay(ctx: Context): Boolean = Settings.canDrawOverlays(ctx)

    fun detailIntent(ctx: Context, alert: JSONObject): Intent =
        Intent(ctx, DetailActivity::class.java)
            .putExtra(DetailActivity.EXTRA_ALERT, alert.toString())
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)

    private fun notify(ctx: Context, alert: JSONObject, title: String, body: String, big: String, level: String) {
        ensureChannels(ctx)
        val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val id = (alert.optLong("time") % Int.MAX_VALUE).toInt()
        val pi = PendingIntent.getActivity(ctx, id, detailIntent(ctx, alert),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val channel = if (level == "high") CHANNEL_HIGH else CHANNEL_LOW
        val n = Notification.Builder(ctx, channel)  // minSdk 26, so channels always exist
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(Notification.BigTextStyle().bigText("$body\n\n$big"))
            .setColor(Color.parseColor(Ui.levelColor(level)))
            .setContentIntent(pi)
            .addAction(Notification.Action.Builder(
                Icon.createWithResource(ctx, android.R.drawable.ic_menu_view), "See why", pi).build())
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_MESSAGE)
            .build()
        try {
            nm.notify(id, n)
        } catch (e: SecurityException) {
            // POST_NOTIFICATIONS not granted (Android 13+): the overlay/app history still work
        }
    }

    private fun topReason(analysis: JSONObject): String {
        val intel = analysis.optJSONObject("intel")?.optJSONArray("findings")
        if (intel != null) {
            for (i in 0 until intel.length()) {
                val f = intel.getJSONObject(i)
                if (f.optString("severity") == "danger") return f.optString("title")
            }
        }
        val tactics = analysis.optJSONArray("tactics")
        if (tactics != null && tactics.length() > 0) return tactics.getJSONObject(0).optString("label")
        return analysis.optString("category_label", "Suspicious message")
    }
}
