package com.fraudlens.shield

import android.Manifest
import android.app.role.RoleManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.widget.Switch
import com.fraudlens.shield.K.add

/** Which Shield permissions are on. `running` = Shield will actually check new messages. */
class ShieldStatus(ctx: Context) {
    val listener: Boolean = listenerEnabled(ctx)
    val notifications: Boolean = Build.VERSION.SDK_INT < 33 ||
        ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
    val overlay: Boolean = Settings.canDrawOverlays(ctx)
    val callRole: Boolean = callRoleHeld(ctx)
    val protectionOn: Boolean = Prefs(ctx).protectionOn
    val total: Int = 2 + (if (Build.VERSION.SDK_INT >= 33) 1 else 0) + (if (Build.VERSION.SDK_INT >= 29) 1 else 0)
    val done: Int = listOf(listener, overlay).count { it } +
        (if (Build.VERSION.SDK_INT >= 33 && notifications) 1 else 0) + (if (Build.VERSION.SDK_INT >= 29 && callRole) 1 else 0)
    val running: Boolean get() = listener && protectionOn

    companion object {
        fun listenerEnabled(ctx: Context): Boolean {
            val flat = Settings.Secure.getString(ctx.contentResolver, "enabled_notification_listeners") ?: return false
            val me = ComponentName(ctx, ShieldNotificationListener::class.java).flattenToString()
            return flat.split(":").any { it == me }
        }

        fun callRoleHeld(ctx: Context): Boolean {
            if (Build.VERSION.SDK_INT < 29) return false
            val rm = ctx.getSystemService(RoleManager::class.java) ?: return false
            return rm.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)
        }
    }
}

// =====================================================================================================
// Shield: background protection, set up and tested from inside the app.
// =====================================================================================================
class ShieldTab(app: MainActivity) : Tab(app) {
    override fun onShow() { dirty = false; render() }

    override fun render() {
        content.removeAllViews()
        val s = ShieldStatus(ctx)
        content.add(K.pageHeader(ctx, "Shield", "Warns you about scam messages and calls the moment they arrive, even " +
            "when FraudLens is closed.", "Protection"))
        content.add(hero(s), t = 18)
        content.add(setup(s), t = T.GAP)
        content.add(tryIt(), t = T.GAP)
        content.add(recent(), t = T.GAP)
        content.add(howItWorks(), t = T.GAP)
        content.add(server(), t = T.GAP)
    }

    // ---- status ------------------------------------------------------------------------------------------
    private fun hero(s: ShieldStatus): View {
        val (label, color) = when {
            s.running -> "Running in background" to T.SAFE_TEXT
            !s.protectionOn -> "Paused" to T.MUTED
            else -> "Setup needed" to T.WARN
        }
        val card = K.card(ctx, 18, T.SURFACE, T.tint(color, 0.35f))
        val top = K.row(ctx)
        top.add(K.squircle(ctx, "SHIELD", if (s.running) T.ON_ACCENT else color, 52,
            if (s.running) T.SAFE else T.tint(color, 0.12f), false), K.dp(ctx, 52), K.dp(ctx, 52), r = 14)
        val t = K.col(ctx)
        t.add(K.statusChip(ctx, label, color), K.WRAP, K.WRAP)
        t.add(K.text(ctx, if (s.running) "You're protected" else if (!s.protectionOn) "Protection is paused"
            else "${s.done} of ${s.total} steps done", 17f, 700), t = 8)
        top.add(t, 0, K.WRAP, 1f)
        card.add(top)
        card.add(K.caption(ctx, "Checks SMS, WhatsApp, email and other chat notifications, and incoming calls while " +
            "they ring. Ordinary chats are filtered on the phone and never sent anywhere.", 13.5f), t = 14)
        val sw = Switch(ctx).apply {
            text = "Protection on"
            textSize = 15f
            typeface = T.font(ctx, 600)
            setTextColor(T.TEXT)
            isChecked = s.protectionOn
            val states = arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf())
            thumbTintList = ColorStateList(states, intArrayOf(T.SAFE, T.MUTED))
            trackTintList = ColorStateList(states, intArrayOf(T.tint(T.SAFE, 0.45f), T.SURFACE_2))
            setOnCheckedChangeListener { _, on ->
                Prefs(ctx).protectionOn = on
                app.snack(if (on) "Shield is on." else "Shield is paused. Nothing is checked until you turn it back on.")
                render()
                app.refreshDock()
            }
        }
        card.add(K.divider(ctx), t = 14)
        card.add(sw, t = 6)
        return card
    }

    // ---- permissions ---------------------------------------------------------------------------------------
    private fun setup(s: ShieldStatus): View {
        val card = K.card(ctx)
        card.add(K.sectionTitle(ctx, "Setup", "Turn on each item once. Come back here after each step.", "CHECKLIST", T.SAFE_TEXT))
        var n = 1
        card.add(step(n++, "NOTIFICATIONS_OUTLINED", "Read notifications", "Lets Shield see new SMS, WhatsApp and email " +
            "alerts. Switch FraudLens on. Greyed out? Settings → Apps → FraudLens → ⋮ → Allow restricted settings.",
            s.listener) {
            app.startSafely(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
        })
        if (Build.VERSION.SDK_INT >= 33) {
            card.add(step(n++, "NOTIFICATIONS_ACTIVE_OUTLINED", "Show warnings", "Allows FraudLens to post scam alerts.",
                s.notifications) {
                val prefs = Prefs(ctx)
                if (prefs.askedNotifications && !app.shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS)) {
                    // Android won't ask again after a denial: open FraudLens's notification settings instead.
                    app.startSafely(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                        .putExtra(Settings.EXTRA_APP_PACKAGE, app.packageName))
                } else {
                    prefs.askedNotifications = true
                    app.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), MainActivity.REQ_NOTIF)
                }
            })
        }
        card.add(step(n++, "PICTURE_IN_PICTURE_ALT_OUTLINED", "Display over other apps",
            "Shows the red warning banner on top of any app.", s.overlay) {
            app.startSafely(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:${app.packageName}")))
        })
        if (Build.VERSION.SDK_INT >= 29) {
            card.add(step(n++, "PHONE_IN_TALK_OUTLINED", "Check incoming calls", "Warns while a known scam number is ringing.",
                s.callRole) {
                val rm = app.getSystemService(RoleManager::class.java)
                if (rm != null && rm.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING)) {
                    @Suppress("DEPRECATION")
                    app.startActivityForResult(rm.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING), MainActivity.REQ_ROLE)
                } else {
                    app.snack("Call screening isn't available on this phone.")
                }
            })
        }
        card.add(step(n, "BATTERY_SAVER_OUTLINED", "Battery (optional)",
            "Choose FraudLens → \"Unrestricted\" so the phone never stops Shield.", null) {
            app.startSafely(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
        })
        return card
    }

    private fun step(n: Int, icon: String, title: String, desc: String, done: Boolean?, action: () -> Unit): View {
        val row = K.row(ctx)
        row.setPadding(0, K.dp(ctx, 14), 0, 0)
        val color = when (done) { true -> T.SAFE_TEXT; false -> T.WARN; null -> T.MUTED }
        val badge = android.widget.FrameLayout(ctx).apply {
            background = K.rounded(ctx, T.tint(color, 0.12f), 11f)
            addView(K.icon(ctx, if (done == true) "CHECK_CIRCLE" else icon, 20f, color),
                android.widget.FrameLayout.LayoutParams(K.MATCH, K.MATCH))
        }
        row.add(badge, K.dp(ctx, 40), K.dp(ctx, 40), r = 12)
        val t = K.col(ctx)
        t.add(K.text(ctx, "$n. $title", 14.5f, 600))
        t.add(K.caption(ctx, if (done == true) "On" else desc, 12.5f, if (done == true) T.SAFE_TEXT else T.MUTED), t = 2)
        row.add(t, 0, K.WRAP, 1f)
        if (done != true) {
            row.add(K.button(ctx, if (done == null) "Open" else "Enable", if (done == null) K.Style.SECONDARY else K.Style.PRIMARY) {
                action()
            }.apply { minimumHeight = K.dp(ctx, 40); setPadding(K.dp(ctx, 14), K.dp(ctx, 8), K.dp(ctx, 14), K.dp(ctx, 8)) },
                K.WRAP, K.WRAP, l = 8)
        }
        return row
    }

    // ---- tests ---------------------------------------------------------------------------------------------
    private fun tryIt(): View {
        val card = K.card(ctx)
        card.add(K.sectionTitle(ctx, "Try it", "Best demo: have someone send you a scam SMS or WhatsApp. These buttons " +
            "test the same path without one.", "SCIENCE_OUTLINED"))
        card.add(K.button(ctx, "Send a test scam alert", K.Style.DANGER, "WARNING_AMBER_ROUNDED") { testAlert() }, t = 12)
        if (Build.VERSION.SDK_INT >= 29) {
            card.add(K.button(ctx, "Test a caller check", K.Style.SECONDARY, "CALL_OUTLINED") { testCall() }, t = 10)
        }
        return card
    }

    private fun testAlert() {
        app.snack("Checking a sample scam SMS…")
        val url = Prefs(ctx).serverUrl
        val appCtx = ctx.applicationContext
        Bg.run({ ApiClient(url).analyze(SAMPLE_SCAM, SAMPLE_SENDER, "sms") }) { r ->
            val a = r.getOrNull()
            if (a != null) {
                Alerts.showMessageAlert(appCtx, a, SAMPLE_SCAM, SAMPLE_SENDER, "Messages (test)")
                render()
            } else app.snack(friendlyError(r.exceptionOrNull()))
        }
    }

    private fun testCall() {
        val url = Prefs(ctx).serverUrl
        val appCtx = ctx.applicationContext
        Bg.run({ ApiClient(url).checkPhone(SAMPLE_SENDER) }) { r ->
            val res = r.getOrNull()
            when {
                res == null -> app.snack(friendlyError(r.exceptionOrNull()))
                res.optString("risk_level") == "low" ->
                    app.snack("Caller check works: ${res.optString("headline")}. Send the test scam alert first to make this number known.")
                else -> { Alerts.showCallAlert(appCtx, SAMPLE_SENDER, res); render() }
            }
        }
    }

    // ---- recent Shield alerts ------------------------------------------------------------------------------
    private fun recent(): View {
        val card = K.card(ctx)
        val alerts = Prefs(ctx).recentAlerts()
        card.add(K.sectionTitle(ctx, "Recent alerts", if (alerts.isEmpty()) "Nothing yet. Shield is watching quietly." else null,
            "HISTORY"))
        for (a in alerts.take(3)) {
            val e = Entry(a, true)
            val r = T.risk(e.level)
            val row = K.row(ctx)
            row.setPadding(0, K.dp(ctx, 12), 0, 0)
            row.add(K.squircle(ctx, if (e.isCall) "CALL_OUTLINED" else "SMS_OUTLINED", r.color, 36, r.bg, false),
                K.dp(ctx, 36), K.dp(ctx, 36), r = 12)
            val t = K.col(ctx)
            t.add(K.text(ctx, "${e.score}/100 · ${a.optString("verdict")}", 14f, 600, maxLines = 1))
            t.add(K.caption(ctx, "${a.optString("sender")} · ${a.optString("app")}", 12f).apply { maxLines = 1 }, t = 2)
            row.add(t, 0, K.WRAP, 1f)
            row.add(K.icon(ctx, "CHEVRON_RIGHT", 20f, T.FAINT), K.WRAP, K.WRAP)
            K.pressable(row, 8f) { app.openEntry(e) }
            card.add(row)
        }
        if (alerts.isNotEmpty()) {
            card.add(K.button(ctx, "See all in History", K.Style.LINK, "ARROW_FORWARD") { app.showTab("history") },
                K.WRAP, K.WRAP, t = 8)
        }
        return card
    }

    // ---- explainer -------------------------------------------------------------------------------------------
    private fun howItWorks(): View {
        val steps = listOf(
            Triple("NOTIFICATIONS_ACTIVE_OUTLINED", "Sleeps until something arrives",
                "Android hands Shield each new SMS, WhatsApp or email notification, and every ringing call."),
            Triple("FILTER_ALT_OUTLINED", "Quick filter on the phone",
                "Obviously harmless messages are skipped; suspicious ones go to the FraudLens server."),
            Triple("LAYERS_OUTLINED", "Same five-layer check",
                "Rules, AI language model, scam memory, link model and security databases."),
            Triple("WARNING_AMBER_ROUNDED", "Warns before you act",
                "A heads-up notification, a red banner over the current app, and a \"See why\" Scam X-Ray."),
        )
        val body = K.col(ctx)
        steps.forEachIndexed { i, (icon, title, detail) ->
            val row = K.row(ctx, Gravity.TOP)
            val rail = K.col(ctx).apply { gravity = Gravity.CENTER_HORIZONTAL }
            rail.add(K.squircle(ctx, icon, T.SAFE_TEXT, 36, T.tint(T.SAFE, 0.10f)), K.dp(ctx, 36), K.dp(ctx, 36))
            if (i < steps.size - 1) rail.add(View(ctx).apply { setBackgroundColor(T.LINE) }, K.dp(ctx, 1), K.dp(ctx, 18), t = 4)
            row.add(rail, K.WRAP, K.WRAP, r = 12)
            val t = K.col(ctx)
            t.add(K.text(ctx, title, 14.5f, 600))
            t.add(K.caption(ctx, detail, 12.5f), t = 2)
            row.add(t, 0, K.WRAP, 1f)
            body.add(row, t = if (i == 0) 0 else 4)
        }
        val card = K.card(ctx)
        card.add(K.expandable(ctx, K.squircle(ctx, "RADAR", T.SAFE_TEXT, 36), "How Shield works",
            "Private by design, no battery drain", null, 0, body))
        return card
    }

    private fun server(): View {
        val online = Repo.online
        val (label, color) = when (online) {
            true -> "Connected" to T.SAFE_TEXT
            false -> "Can't reach" to T.WARN
            null -> "Connecting" to T.MUTED
        }
        return K.row(ctx).apply {
            background = K.rounded(ctx, T.SURFACE, T.R_CARD, T.LINE)
            K.pad(this, 14)
            add(K.squircle(ctx, "DNS_OUTLINED", color, 40), K.dp(ctx, 40), K.dp(ctx, 40), r = 12)
            val t = K.col(ctx)
            t.add(K.text(ctx, "FraudLens server · $label", 14f, 600, color))
            t.add(K.mono(ctx, Prefs(ctx).serverUrl, 11.5f, T.MUTED), t = 3)
            add(t, 0, K.WRAP, 1f)
            add(K.button(ctx, "Change", K.Style.LINK) { app.openSettings() }, K.WRAP, K.WRAP, l = 8)
        }
    }

    companion object {
        const val SAMPLE_SENDER = "+230 5821 4470"
        const val SAMPLE_SCAM = "MCB ALERT: Your account has been suspended due to unusual activity. " +
            "Verify within 2 hours to avoid closure: http://mcb-secure-verify.com/login " +
            "Reply with the OTP you receive to confirm."
    }
}
