package com.fraudlens.shield

import android.content.Context
import android.graphics.PixelFormat
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import org.json.JSONObject

/**
 * Red warning banner drawn on top of whatever app is open (needs "Display over other apps").
 * Disappears by itself after 15 seconds, or when the user taps a button.
 */
object OverlayBanner {
    private val main = Handler(Looper.getMainLooper())
    private var current: View? = null

    fun show(ctx: Context, title: String, body: String, alert: JSONObject) {
        main.post { showOnMain(ctx.applicationContext, title, body, alert) }
    }

    private fun showOnMain(ctx: Context, title: String, body: String, alert: JSONObject) {
        val wm = ctx.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        dismiss(wm)

        val banner = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            background = Ui.rounded(Ui.RED, 18, ctx)
            setPadding(Ui.dp(ctx, 18), Ui.dp(ctx, 14), Ui.dp(ctx, 18), Ui.dp(ctx, 12))
            elevation = Ui.dp(ctx, 8).toFloat()
        }
        banner.addView(Ui.text(ctx, "🛡️ FraudLens · Shield", 12f, true, "#FECACA"))
        banner.addView(Ui.text(ctx, title, 17f, true, "#FFFFFF"))
        banner.addView(Ui.text(ctx, body, 14f, false, "#FFFFFF"))
        banner.addView(Ui.text(ctx, "Don't reply, tap links or pay until you've checked.", 13f, false, "#FEE2E2"))

        val buttons = Ui.row(ctx)
        val see = Ui.button(ctx, "See why", "#7F1D1D") {
            ctx.startActivity(Alerts.detailIntent(ctx, alert))
            dismiss(wm)
        }
        val close = Ui.button(ctx, "Dismiss", "#991B1B") { dismiss(wm) }
        val lp = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
            rightMargin = Ui.dp(ctx, 8)
        }
        buttons.addView(see, lp)
        buttons.addView(close, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        banner.addView(buttons, Ui.matchWidth(ctx, 8))

        val type = WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY  // minSdk 26
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            type,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT,
        ).apply {
            gravity = Gravity.TOP
            y = Ui.dp(ctx, 48)
            horizontalMargin = 0.03f
        }
        try {
            wm.addView(banner, params)
            current = banner
            main.postDelayed({ if (current === banner) dismiss(wm) }, 15_000)
        } catch (e: Exception) {
            // Permission revoked or window not allowed: the notification is still shown.
        }
    }

    private fun dismiss(wm: WindowManager) {
        val v = current ?: return
        current = null
        try {
            wm.removeView(v)
        } catch (e: Exception) {
            // already gone
        }
    }
}
