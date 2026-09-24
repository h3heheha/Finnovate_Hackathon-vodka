package com.fraudlens.shield

import android.content.Context
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Tiny helpers to build screens in code (no XML layouts needed, so nothing can go out of sync). */
object Ui {
    // "Clean Dark Slate", the same tokens as the FraudLens app (mobile/DESIGN_SPEC.md)
    const val BG = "#121417"
    const val SURFACE = "#1C1E23"
    const val SURFACE_2 = "#24272D"
    const val LINE = "#2C3037"
    const val TEXT = "#F3F4F6"
    const val MUTED = "#8E95A2"
    const val NAVY = "#24272D"   // neutral button
    const val TEAL = "#047857"   // emerald, dark enough for white button text
    const val SAFE = "#10B981"
    const val RED = "#DC2626"
    const val AMBER = "#D97706"
    const val GREEN = "#16A34A"

    fun dp(ctx: Context, v: Int): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), ctx.resources.displayMetrics).toInt()

    fun levelColor(level: String?): String = when (level) {
        "high" -> RED
        "medium" -> AMBER
        else -> GREEN
    }

    /** Level colour bright enough to read as text on the dark surfaces. */
    fun levelText(level: String?): String = when (level) {
        "high" -> "#F87171"
        "medium" -> "#FBBF24"
        else -> "#34D399"
    }

    /** Mix a colour with white so saturated accents stay readable on dark backgrounds. */
    fun lighten(color: String, amount: Float = 0.35f): String {
        val c = try { Color.parseColor(color) } catch (e: IllegalArgumentException) { Color.parseColor(RED) }
        fun mix(v: Int) = (v + (255 - v) * amount).toInt().coerceIn(0, 255)
        return String.format("#%02X%02X%02X", mix(Color.red(c)), mix(Color.green(c)), mix(Color.blue(c)))
    }

    fun rounded(color: String, radiusDp: Int, ctx: Context, stroke: String? = null): GradientDrawable =
        GradientDrawable().apply {
            setColor(Color.parseColor(color))
            cornerRadius = dp(ctx, radiusDp).toFloat()
            if (stroke != null) setStroke(dp(ctx, 1), Color.parseColor(stroke))
        }

    fun text(ctx: Context, s: CharSequence, sizeSp: Float = 15f, bold: Boolean = false,
             color: String = TEXT): TextView = TextView(ctx).apply {
        text = s
        textSize = sizeSp
        setTextColor(Color.parseColor(color))
        typeface = T.font(ctx, if (bold) 700 else 400)
        setPadding(0, dp(ctx, 3), 0, dp(ctx, 3))
    }

    fun button(ctx: Context, label: String, color: String = NAVY, onClick: (View) -> Unit): Button =
        Button(ctx).apply {
            text = label
            setAllCaps(false)
            setTextColor(Color.WHITE)
            typeface = T.font(ctx, 600)
            background = rounded(color, 16, ctx)
            setPadding(dp(ctx, 16), dp(ctx, 12), dp(ctx, 16), dp(ctx, 12))
            setOnClickListener(onClick)
        }

    fun card(ctx: Context, bg: String = SURFACE, stroke: String = LINE): LinearLayout =
        LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            background = rounded(bg, 22, ctx, stroke)
            setPadding(dp(ctx, 18), dp(ctx, 16), dp(ctx, 18), dp(ctx, 16))
        }

    fun vspace(ctx: Context, h: Int): View = View(ctx).apply {
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(ctx, h))
    }

    fun row(ctx: Context): LinearLayout = LinearLayout(ctx).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
    }

    fun matchWidth(ctx: Context, topMarginDp: Int = 10): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            .apply { topMargin = dp(ctx, topMarginDp) }
}
