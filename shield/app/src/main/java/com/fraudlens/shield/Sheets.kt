package com.fraudlens.shield

import android.app.Activity
import android.app.Dialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.net.Uri
import android.os.Build
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import com.fraudlens.shield.K.add
import org.json.JSONObject

/** Small message that slides up above the dock and disappears by itself. */
object Snack {
    fun show(host: FrameLayout, msg: String, bottomDp: Int = 104, sidePx: Pair<Int, Int> = 0 to 0) {
        val ctx = host.context
        host.findViewWithTag<View>("snack")?.let { host.removeView(it) }
        val bar = K.row(ctx).apply {
            tag = "snack"
            background = K.rounded(ctx, T.SURFACE_2, T.R_CARD, T.LINE)
            setPadding(K.dp(ctx, 16), K.dp(ctx, 13), K.dp(ctx, 16), K.dp(ctx, 13))
            elevation = K.dpf(ctx, 8)
            add(K.text(ctx, msg, 14f, 500), 0, K.WRAP, 1f)
        }
        val lp = FrameLayout.LayoutParams(K.MATCH, K.WRAP, Gravity.BOTTOM).apply {
            setMargins(K.dp(ctx, 16) + sidePx.first, 0, K.dp(ctx, 16) + sidePx.second, K.dp(ctx, bottomDp))
        }
        host.addView(bar, lp)
        K.enter(bar)
        bar.postDelayed({
            bar.animate().alpha(0f).setDuration(200).withEndAction { host.removeView(bar) }.start()
        }, 3200)
    }
}

/**
 * Bottom sheets (official contacts, ask someone you trust, settings) and the shared result actions.
 * Used by the main app and by the "See why" screen, so both behave the same.
 */
object Sheets {
    /** The sheet on screen, if any (messages then go above it, not behind it). Weak: never keeps a screen alive. */
    private var openRef: java.lang.ref.WeakReference<Dialog>? = null

    val isOpen: Boolean
        get() {
            val d = openRef?.get() ?: return false
            val owner = d.ownerActivity
            return d.isShowing && owner != null && !owner.isFinishing && !owner.isDestroyed
        }

    /** Shows `content` in a sheet that slides up from the bottom. */
    fun show(act: Activity, content: View): Dialog {
        val ctx: Context = act
        val d = Dialog(act)
        d.requestWindowFeature(Window.FEATURE_NO_TITLE)
        val box = K.col(ctx).apply {
            background = K.corners(ctx, T.SURFACE, T.R_HERO, T.R_HERO, 0f, 0f)
            setPadding(K.dp(ctx, 22), K.dp(ctx, 10), K.dp(ctx, 22), K.dp(ctx, 26))
        }
        val handle = View(ctx).apply { background = K.rounded(ctx, T.LINE, 2f) }
        box.add(handle, K.dp(ctx, 36), K.dp(ctx, 4), gravity = Gravity.CENTER_HORIZONTAL, b = 14)
        val scroll = ScrollView(ctx).apply {
            isVerticalScrollBarEnabled = false
            addView(content, ViewGroup.LayoutParams(K.MATCH, K.WRAP))
        }
        box.add(scroll)
        d.setContentView(box)
        d.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setLayout(K.MATCH, K.WRAP)
            setGravity(Gravity.BOTTOM)
            setWindowAnimations(android.R.style.Animation_InputMethod)
            addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
            setDimAmount(0.6f)
            setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        }
        d.setOwnerActivity(act)
        d.setOnDismissListener { if (openRef?.get() === d) openRef = null }
        d.show()
        openRef = java.lang.ref.WeakReference(d)
        return d
    }

    /** Icon + centred title at the top of a sheet. */
    fun header(ctx: Context, iconName: String, title: String, subtitle: String? = null, color: Int = T.SAFE): LinearLayout =
        K.col(ctx).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            add(K.squircle(ctx, iconName, color, 48, T.tint(color, 0.12f)), K.dp(ctx, 48), K.dp(ctx, 48),
                gravity = Gravity.CENTER_HORIZONTAL)
            add(K.text(ctx, title, 18f, 700).apply { gravity = Gravity.CENTER }, t = 12)
            if (subtitle != null) add(K.caption(ctx, subtitle, 13f).apply { gravity = Gravity.CENTER }, t = 6)
        }

    // ---- verified contacts -----------------------------------------------------------------------------
    fun officialContacts(act: Activity, orgId: String?, actions: Actions) {
        val ctx: Context = act
        val all = Repo.organisations()
        val chosen = (if (!orgId.isNullOrBlank()) all.filter { it.optString("id") == orgId } else emptyList())
            .ifEmpty { all.sortedBy { if (it.optString("type") == "bank") 0 else 1 } }
        val content = K.col(ctx)
        content.add(header(ctx, "VERIFIED_USER", "Verified contacts",
            "From FraudLens's verified directory, never from the message you received. Tap a number to call."))
        if (chosen.isEmpty()) {
            content.add(K.caption(ctx, "The directory loads when the app connects to the FraudLens server."), t = 14)
        }
        for (o in chosen) {
            val card = K.inner(ctx, 14)
            val top = K.row(ctx, Gravity.TOP)
            top.add(K.squircle(ctx, "VERIFIED", T.SAFE_TEXT, 38), K.dp(ctx, 38), K.dp(ctx, 38), r = 12)
            val info = K.col(ctx)
            info.add(K.text(ctx, o.optString("name"), 15f, 700))
            val phones = mutableListOf<String>()
            o.optString("phone").takeIf { it.isNotBlank() && it != "null" }?.let { phones.add(it) }
            o.optJSONArray("phones")?.let { arr -> for (i in 0 until arr.length()) arr.optString(i).takeIf { it.isNotBlank() }?.let { phones.add(it) } }
            if (phones.isEmpty()) {
                info.add(K.caption(ctx, "Phone: use the number on the back of your card", 13f), t = 4)
            }
            for (ph in phones.distinct()) {
                info.add(K.button(ctx, ph, K.Style.LINK, "CALL") { actions.dial(ph) }, K.WRAP, K.WRAP, t = 2)
            }
            val site = o.optString("website")
            if (site.isNotBlank() && site != "null") {
                info.add(K.button(ctx, site.removePrefix("https://").removePrefix("http://"), K.Style.LINK, "OPEN_IN_NEW") {
                    actions.openUrl(site)
                }, K.WRAP, K.WRAP)
            }
            top.add(info, 0, K.WRAP, 1f)
            card.add(top)
            content.add(card, t = 10)
        }
        show(act, content)
    }

    // ---- ask someone you trust -------------------------------------------------------------------------
    fun guardian(act: Activity, analysis: JSONObject?, actions: Actions) {
        val ctx: Context = act
        val prefs = Prefs(ctx)
        val name = prefs.guardianName
        val phone = prefs.guardianPhone
        val first = name.split(" ").firstOrNull { it.isNotBlank() }
        val hi = if (first != null) "Hi $first" else "Hi"
        val msg = if (analysis != null) {
            val quote = analysis.optString("_text").trim().take(300)
            "$hi, I got a message FraudLens rated ${analysis.optInt("risk_score")}/100 " +
                "(${analysis.optString("category_label")}). Can you look at it with me before I reply or pay?" +
                if (quote.isNotEmpty()) "\n\nThe message:\n\"$quote\"" else ""
        } else {
            "$hi, can you help me check a message before I reply or pay?"
        }
        val content = K.col(ctx)
        content.add(header(ctx, "GROUPS", "Ask someone you trust"))
        val who = K.row(ctx)
        who.add(K.squircle(ctx, "PERSON", T.SAFE_TEXT, 38, T.tint(T.SAFE, 0.12f)), K.dp(ctx, 38), K.dp(ctx, 38), r = 10)
        val whoText = K.col(ctx)
        whoText.add(K.caption(ctx, "Your trusted contact", 12f))
        whoText.add(K.text(ctx, if (name.isNotBlank()) name + (if (phone.isNotBlank()) " · $phone" else "") else "Not set yet",
            14.5f, 700))
        who.add(whoText, 0, K.WRAP, 1f)
        content.add(who, t = 16)
        content.add(K.inner(ctx, 14).apply { add(K.text(ctx, msg, 14.5f, italic = true)) }, t = 12)
        content.add(K.caption(ctx, "A second opinion stops most scams. Scammers ask for secrecy for this reason.", 12.5f), t = 10)
        var dialog: Dialog? = null
        if (phone.isNotBlank()) {
            content.add(K.button(ctx, "Send by SMS", K.Style.PRIMARY, "SMS") {
                actions.startSafely(Intent(Intent.ACTION_SENDTO, Uri.parse("smsto:" + Uri.encode(phone))).putExtra("sms_body", msg))
            }, t = 14)
        }
        val row = K.row(ctx)
        row.add(K.button(ctx, "Share…", if (phone.isBlank()) K.Style.PRIMARY else K.Style.SECONDARY, "SHARE") {
            val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, msg)
            actions.startSafely(Intent.createChooser(send, "Ask someone you trust"))
        }, 0, K.WRAP, 1f)
        row.add(K.button(ctx, "Copy", K.Style.SECONDARY, "CONTENT_COPY") { actions.copy(msg, "Message") }, 0, K.WRAP, 1f, l = 10)
        content.add(row, t = 10)
        if (name.isBlank() || phone.isBlank()) {
            content.add(K.button(ctx, "Set your trusted contact", K.Style.LINK, "PERSON") {
                dialog?.dismiss()
                settings(act, actions)
            }, K.WRAP, K.WRAP, t = 8, gravity = Gravity.CENTER_HORIZONTAL)
        }
        dialog = show(act, content)
    }

    // ---- settings -------------------------------------------------------------------------------------------
    fun settings(act: Activity, actions: Actions, onSaved: (() -> Unit)? = null) {
        val ctx: Context = act
        val prefs = Prefs(ctx)
        val content = K.col(ctx)
        content.add(header(ctx, "TUNE", "Settings"))

        content.add(K.sectionHeader(ctx, "FraudLens server"), t = 18)
        val url = K.field(ctx, "http://192.168.1.20:8000", prefs.serverUrl, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
        content.add(url, t = 8)
        val hints = K.inner(ctx, 12)
        for ((k, v) in listOf("Phone on the same Wi-Fi or hotspot" to "http://<laptop-IP>:8000",
                              "Android emulator" to Prefs.DEFAULT_SERVER)) {
            val r = K.row(ctx)
            r.add(K.caption(ctx, k, 12f), 0, K.WRAP, 1f)
            r.add(K.mono(ctx, v, 11.5f, T.TEXT), K.WRAP, K.WRAP, l = 8)
            hints.add(r, t = if (hints.childCount > 0) 6 else 0)
        }
        content.add(hints, t = 8)
        val result = K.text(ctx, statusLine(), 13f, 400, if (Repo.online == true) T.SAFE_TEXT else T.MUTED)
        content.add(K.button(ctx, "Save & test", K.Style.PRIMARY, "DNS_OUTLINED") {
            prefs.serverUrl = url.text.toString()
            url.setText(prefs.serverUrl)
            result.text = "Connecting…"
            result.setTextColor(T.MUTED)
            Repo.refresh(ctx) { ok ->
                result.text = if (ok) statusLine() else "Can't reach ${prefs.serverUrl}. Is run_backend.bat running, and are " +
                    "the phone and laptop on the same Wi-Fi? Examples still work offline."
                result.setTextColor(if (ok) T.SAFE_TEXT else T.FRAUD_TEXT)
                onSaved?.invoke()
            }
        }, t = 10)
        content.add(result, t = 10)

        content.add(K.sectionHeader(ctx, "Trusted contact"), t = 22)
        content.add(K.caption(ctx, "Used by \"Ask someone you trust\". Stays on this phone.", 12.5f), t = 4)
        val gName = K.field(ctx, "Name, e.g. Ravi (son)", prefs.guardianName, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS)
        val gPhone = K.field(ctx, "Phone number", prefs.guardianPhone, InputType.TYPE_CLASS_PHONE)
        content.add(gName, t = 8)
        content.add(gPhone, t = 8)
        val saved = K.text(ctx, "", 13f, 400, T.SAFE_TEXT)
        content.add(K.button(ctx, "Save contact", K.Style.SECONDARY, "PERSON") {
            prefs.guardianName = gName.text.toString()
            prefs.guardianPhone = gPhone.text.toString()
            saved.text = if (prefs.guardianName.isBlank() && prefs.guardianPhone.isBlank()) "Trusted contact removed."
                         else "Saved: ${prefs.guardianName} ${prefs.guardianPhone}".trim()
        }, t = 10)
        content.add(saved, t = 8)

        content.add(K.mono(ctx, "FRAUDLENS ${appVersion(ctx)} · ${prefs.deviceId.uppercase()}", 10f, T.FAINT, spacing = 0.06f)
            .apply { gravity = Gravity.CENTER }, t = 18)
        show(act, content)
    }

    fun statusLine(): String {
        val h = Repo.health ?: return when (Repo.online) {
            false -> "Offline demo: the server can't be reached."
            null -> "Connecting…"
            else -> "Connected."
        }
        val ml = h.optJSONObject("ml")
        val mem = ml?.optJSONObject("memory")
        val intel = h.optJSONObject("intel")
        val providers = if (intel == null) "off" else
            listOf("safe_browsing" to "Safe Browsing", "urlhaus" to "URLhaus", "ipqs" to "IPQS", "telesign" to "Telesign")
                .filter { intel.optBoolean(it.first) }.joinToString(", ") { it.second }.ifEmpty { "no keys" }
        return "Connected (v${h.optString("version")}). AI: ${ml?.optString("embedder") ?: "rules only"} · " +
            "memory: ${mem?.optInt("size") ?: 0} messages · threat intel: $providers"
    }

    private fun appVersion(ctx: Context): String = try {
        ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: ""
    } catch (e: Exception) { "" }

    /** Yes / no question in a sheet. */
    fun confirm(act: Activity, title: String, detail: String, yes: String, onYes: () -> Unit) {
        val ctx: Context = act
        val content = K.col(ctx)
        content.add(header(ctx, "DELETE_OUTLINE", title, detail, T.FRAUD_TEXT))
        var d: Dialog? = null
        val row = K.row(ctx)
        row.add(K.button(ctx, "Cancel", K.Style.SECONDARY) { d?.dismiss() }, 0, K.WRAP, 1f)
        row.add(K.button(ctx, yes, K.Style.DANGER) { d?.dismiss(); onYes() }, 0, K.WRAP, 1f, l = 10)
        content.add(row, t = 18)
        d = show(act, content)
    }
}

/** Result actions shared by every screen that shows a result (Scan tab, History, "See why"). */
class Actions(private val act: Activity, private val snackFn: (String) -> Unit) : ResultActions {
    /** In-app message; while a sheet is open a toast is used, because the sheet would cover the message. */
    fun snack(msg: String) {
        if (Sheets.isOpen) android.widget.Toast.makeText(act, msg, android.widget.Toast.LENGTH_LONG).show()
        else snackFn(msg)
    }

    fun startSafely(i: Intent) {
        try {
            act.startActivity(i)
        } catch (e: Exception) {
            snack("No app on this phone can do that.")
        }
    }

    fun dial(number: String) = startSafely(Intent(Intent.ACTION_DIAL, Uri.parse("tel:" + number.filter { it.isDigit() || it == '+' })))

    override fun openUrl(url: String) = startSafely(Intent(Intent.ACTION_VIEW, Uri.parse(url)))

    override fun officialContact(orgId: String?) = Sheets.officialContacts(act, orgId, this)

    override fun askGuardian(analysis: JSONObject?) = Sheets.guardian(act, analysis, this)

    override fun copy(text: String, what: String) {
        val cm = act.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("FraudLens", text))
        if (Build.VERSION.SDK_INT < 33) snack("$what copied.")  // Android 13+ shows its own confirmation
    }

    override fun report(analysis: JSONObject, label: String) {
        snack(if (label == "scam") "Reporting…" else "Sending…")
        Repo.report(act, analysis, label) { snack(it) }
    }
}
