package com.fraudlens.shield

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface

/**
 * "Clean Dark Slate" design tokens, the same as the web version (mobile/DESIGN_SPEC.md).
 * Every colour, radius and font in the app comes from here.
 */
object T {
    // ---- colour ----------------------------------------------------------------------------------
    val BG = c("#121417")
    val SURFACE = c("#1C1E23")
    val SURFACE_2 = c("#24272D")
    val LINE = c("#2C3037")
    val TEXT = c("#F3F4F6")
    val MUTED = c("#8E95A2")
    val FAINT = c("#5E6470")          // icons / decoration only, never text
    val SAFE = c("#10B981")
    val SAFE_TEXT = c("#34D399")
    val FRAUD = c("#EF4444")
    val FRAUD_TEXT = c("#F87171")
    val WARN = c("#F59E0B")
    val ON_ACCENT = c("#0B0D10")      // text on emerald buttons

    // ---- shape / spacing (dp) ----------------------------------------------------------------------
    const val R_HERO = 18f
    const val R_CARD = 14f
    const val R_INNER = 10f
    const val GAP = 12
    const val PAD = 16
    const val GUTTER = 20

    fun c(hex: String): Int = Color.parseColor(hex)

    /** The colour with the given opacity (0..1). */
    fun tint(color: Int, alpha: Float): Int =
        Color.argb((alpha.coerceIn(0f, 1f) * 255).toInt(), Color.red(color), Color.green(color), Color.blue(color))

    /** Mix a colour toward white so data colours from the API stay readable on dark slate. */
    fun lighten(color: Int, amount: Float = 0.35f): Int {
        fun mix(v: Int) = (v + (255 - v) * amount).toInt().coerceIn(0, 255)
        return Color.rgb(mix(Color.red(color)), mix(Color.green(color)), mix(Color.blue(color)))
    }

    fun parse(hex: String?, fallback: Int = FRAUD): Int =
        try { if (hex.isNullOrBlank()) fallback else Color.parseColor(hex) } catch (e: IllegalArgumentException) { fallback }

    class Risk(val color: Int, val fill: Int, val bg: Int, val label: String, val icon: String, val word: String)

    private val LOW = Risk(SAFE_TEXT, SAFE, tint(SAFE, 0.10f), "Low risk", "VERIFIED_USER", "SAFE")
    private val MEDIUM = Risk(WARN, WARN, tint(WARN, 0.10f), "Medium risk", "GPP_MAYBE", "CHECK")
    private val HIGH = Risk(FRAUD_TEXT, FRAUD, tint(FRAUD, 0.10f), "High risk", "GPP_BAD", "SCAM")

    fun risk(level: String?): Risk = when (level) {
        "high" -> HIGH
        "medium" -> MEDIUM
        else -> LOW
    }

    // ---- fonts ---------------------------------------------------------------------------------------
    private val fonts = HashMap<String, Typeface>()

    private fun load(ctx: Context, file: String): Typeface = synchronized(fonts) {
        fonts.getOrPut(file) {
            try {
                Typeface.createFromAsset(ctx.applicationContext.assets, "fonts/$file")
            } catch (e: RuntimeException) {
                Typeface.DEFAULT
            }
        }
    }

    /** Inter at a CSS-style weight: 400, 500, 600, 700 or 800. */
    fun font(ctx: Context, weight: Int = 400): Typeface = load(ctx, when {
        weight >= 800 -> "Inter-ExtraBold.ttf"
        weight >= 700 -> "Inter-Bold.ttf"
        weight >= 600 -> "Inter-SemiBold.ttf"
        weight >= 500 -> "Inter-Medium.ttf"
        else -> "Inter-Regular.ttf"
    })

    /** JetBrains Mono, for scores, counts, statuses and labels. */
    fun mono(ctx: Context, bold: Boolean = false): Typeface =
        load(ctx, if (bold) "JetBrainsMono-Bold.ttf" else "JetBrainsMono-Medium.ttf")

    fun icons(ctx: Context): Typeface = load(ctx, "MaterialIcons.ttf")

    // ---- icons for data the API sends ------------------------------------------------------------------
    val ADVICE_ICONS = mapOf(
        "no_codes" to "PASSWORD", "no_link" to "LINK_OFF", "verify_person" to "PHONE_CALLBACK",
        "pause_payment" to "PAUSE_CIRCLE", "check_fsc" to "POLICY", "tell_someone" to "GROUPS",
        "report" to "REPORT", "stay_alert" to "VISIBILITY", "known_scam" to "GPP_BAD",
    )
    /** One muted hue per verification layer (data colours, readable on dark slate). */
    val LAYER_COLORS = mapOf(
        "rules" to c("#60A5FA"), "classifier" to c("#A78BFA"), "memory" to c("#38BDF8"),
        "url" to c("#FB923C"), "community" to c("#F472B6"), "intel" to FRAUD_TEXT,
    )
    val LAYER_ICONS = mapOf(
        "rules" to "RULE", "classifier" to "PSYCHOLOGY", "memory" to "MANAGE_SEARCH",
        "url" to "LINK", "community" to "GROUPS", "intel" to "GPP_BAD",
    )
}
