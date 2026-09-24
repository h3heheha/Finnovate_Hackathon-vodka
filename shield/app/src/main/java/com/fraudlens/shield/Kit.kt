package com.fraudlens.shield

import android.animation.ValueAnimator
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Outline
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.os.Build
import android.text.TextPaint
import android.text.TextUtils
import android.text.style.MetricAffectingSpan
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.ViewOutlineProvider
import android.view.animation.DecelerateInterpolator
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView

/**
 * The FraudLens component kit, built from plain Android views (no libraries):
 * text styles, cards, squircles, pills, buttons, expandable rows, score ring, bars and a flow layout.
 */
object K {
    const val MATCH = ViewGroup.LayoutParams.MATCH_PARENT
    const val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT

    fun dp(ctx: Context, v: Number): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), ctx.resources.displayMetrics).toInt()

    fun dpf(ctx: Context, v: Number): Float =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), ctx.resources.displayMetrics)

    // ---- drawables ---------------------------------------------------------------------------------
    fun rounded(ctx: Context, color: Int, radiusDp: Float, stroke: Int? = null, strokeDp: Float = 1f): GradientDrawable =
        GradientDrawable().apply {
            setColor(color)
            cornerRadius = dpf(ctx, radiusDp)
            if (stroke != null) setStroke(dp(ctx, strokeDp).coerceAtLeast(1), stroke)
        }

    fun corners(ctx: Context, color: Int, tl: Float, tr: Float, br: Float, bl: Float, stroke: Int? = null): GradientDrawable =
        GradientDrawable().apply {
            setColor(color)
            val a = dpf(ctx, tl); val b = dpf(ctx, tr); val c = dpf(ctx, br); val d = dpf(ctx, bl)
            cornerRadii = floatArrayOf(a, a, b, b, c, c, d, d)
            if (stroke != null) setStroke(dp(ctx, 1), stroke)
        }

    /** Touch ripple on top of any view, clipped to its rounded shape. */
    fun pressable(v: View, radiusDp: Float, rippleColor: Int = T.tint(Color.WHITE, 0.10f), onClick: (View) -> Unit) {
        val mask = rounded(v.context, Color.WHITE, radiusDp)
        v.foreground = RippleDrawable(ColorStateList.valueOf(rippleColor), null, mask)
        v.isClickable = true
        v.isFocusable = true
        v.setOnClickListener { onClick(it) }
    }

    fun clipRounded(v: View, radiusDp: Float) {
        val r = dpf(v.context, radiusDp)
        v.outlineProvider = object : ViewOutlineProvider() {
            override fun getOutline(view: View, outline: Outline) {
                outline.setRoundRect(0, 0, view.width, view.height, r)
            }
        }
        v.clipToOutline = true
    }

    // ---- text ------------------------------------------------------------------------------------------
    fun text(ctx: Context, s: CharSequence, size: Float = 14.5f, weight: Int = 400, color: Int = T.TEXT,
             maxLines: Int = 0, italic: Boolean = false): TextView = TextView(ctx).apply {
        text = s
        textSize = size
        setTextColor(color)
        typeface = if (italic) Typeface.create(T.font(ctx, weight), Typeface.ITALIC) else T.font(ctx, weight)
        setLineSpacing(0f, 1.18f)
        includeFontPadding = false
        if (maxLines > 0) {
            this.maxLines = maxLines
            ellipsize = TextUtils.TruncateAt.END
        }
    }

    fun mono(ctx: Context, s: CharSequence, size: Float = 12f, color: Int = T.MUTED, bold: Boolean = false,
             spacing: Float = 0.03f): TextView = TextView(ctx).apply {
        text = s
        textSize = size
        setTextColor(color)
        typeface = T.mono(ctx, bold)
        letterSpacing = spacing
        includeFontPadding = false
        maxLines = 1
        ellipsize = TextUtils.TruncateAt.END
    }

    fun h1(ctx: Context, s: String) = text(ctx, s, 22f, 700).apply { letterSpacing = -0.015f }
    fun h2(ctx: Context, s: String) = text(ctx, s, 16f, 600)
    fun display(ctx: Context, s: String) = text(ctx, s, 28f, 700).apply {
        letterSpacing = -0.02f
        setLineSpacing(0f, 1.08f)
    }
    fun body(ctx: Context, s: CharSequence, size: Float = 14.5f, color: Int = T.TEXT) = text(ctx, s, size, 400, color)
    fun caption(ctx: Context, s: CharSequence, size: Float = 13f, color: Int = T.MUTED) = text(ctx, s, size, 400, color)
    fun overline(ctx: Context, s: String, color: Int = T.MUTED) = mono(ctx, s.uppercase(), 11f, color, spacing = 0.07f)

    fun icon(ctx: Context, name: String, sizeDp: Float = 20f, color: Int = T.TEXT): TextView = TextView(ctx).apply {
        text = Icons.glyph(name)
        typeface = T.icons(ctx)
        setTextSize(TypedValue.COMPLEX_UNIT_DIP, sizeDp)
        setTextColor(color)
        includeFontPadding = false
        gravity = Gravity.CENTER
    }

    /** Span that switches a run of text to another font (works on every Android version). */
    class FontSpan(private val tf: Typeface) : MetricAffectingSpan() {
        override fun updateDrawState(tp: TextPaint) { tp.typeface = tf }
        override fun updateMeasureState(tp: TextPaint) { tp.typeface = tf }
    }

    /** Coloured underline (colour and thickness on Android 10+, plain underline before). */
    class UnderlineColorSpan(private val color: Int, private val thicknessPx: Float) : android.text.style.CharacterStyle() {
        override fun updateDrawState(tp: TextPaint) {
            tp.isUnderlineText = true
            if (Build.VERSION.SDK_INT >= 29) {
                tp.underlineColor = color
                tp.underlineThickness = thicknessPx
            }
        }
    }

    // ---- layout helpers --------------------------------------------------------------------------------
    fun col(ctx: Context): LinearLayout = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }

    fun row(ctx: Context, gravity: Int = Gravity.CENTER_VERTICAL): LinearLayout = LinearLayout(ctx).apply {
        orientation = LinearLayout.HORIZONTAL
        this.gravity = gravity
    }

    /** "Use the size the view already has" (e.g. a 1dp divider or a 40dp squircle), else MATCH × WRAP. */
    const val KEEP = -3

    /**
     * Adds a child with margins in dp. In a vertical list, `t` is the gap above; in a row, `l` the gap before.
     * Sizes are in px (use dp()) or MATCH / WRAP; margins the view already has are kept and added to.
     */
    fun LinearLayout.add(v: View, w: Int = KEEP, h: Int = KEEP, weight: Float = 0f,
                         l: Int = 0, t: Int = 0, r: Int = 0, b: Int = 0, gravity: Int = -1): View {
        val old = v.layoutParams
        val lp = LinearLayout.LayoutParams(
            if (w != KEEP) w else old?.width ?: MATCH,
            if (h != KEEP) h else old?.height ?: WRAP,
            weight)
        val om = old as? ViewGroup.MarginLayoutParams
        lp.setMargins(dp(context, l) + (om?.leftMargin ?: 0), dp(context, t) + (om?.topMargin ?: 0),
            dp(context, r) + (om?.rightMargin ?: 0), dp(context, b) + (om?.bottomMargin ?: 0))
        if (gravity != -1) lp.gravity = gravity
        addView(v, lp)
        return v
    }

    fun space(ctx: Context): View = View(ctx)

    fun pad(v: View, h: Int, vtc: Int = h) {
        v.setPadding(dp(v.context, h), dp(v.context, vtc), dp(v.context, h), dp(v.context, vtc))
    }

    // ---- containers ---------------------------------------------------------------------------------------
    fun card(ctx: Context, padDp: Int = T.PAD, bg: Int = T.SURFACE, border: Int = T.LINE): LinearLayout = col(ctx).apply {
        background = rounded(ctx, bg, T.R_CARD, border)
        pad(this, padDp)
    }

    fun inner(ctx: Context, padDp: Int = 12, bg: Int = T.SURFACE_2): LinearLayout = col(ctx).apply {
        background = rounded(ctx, bg, T.R_INNER)
        pad(this, padDp)
    }

    /** Rounded-square icon holder. */
    fun squircle(ctx: Context, iconName: String, color: Int = T.TEXT, sizeDp: Int = 40, bg: Int = T.SURFACE_2,
                 border: Boolean = true): FrameLayout = FrameLayout(ctx).apply {
        background = rounded(ctx, bg, sizeDp * 0.28f, if (border) T.LINE else null)
        addView(icon(ctx, iconName, sizeDp * 0.5f, color), FrameLayout.LayoutParams(MATCH, MATCH))
        layoutParams = ViewGroup.LayoutParams(dp(ctx, sizeDp), dp(ctx, sizeDp))
    }

    fun dot(ctx: Context, color: Int, sizeDp: Int = 7): View = View(ctx).apply {
        background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(color) }
        layoutParams = LinearLayout.LayoutParams(dp(ctx, sizeDp), dp(ctx, sizeDp))
    }

    fun pill(ctx: Context, s: String, color: Int, bg: Int? = null, size: Float = 11f, iconName: String? = null): LinearLayout =
        row(ctx).apply {
            background = rounded(ctx, bg ?: T.tint(color, 0.12f), 6f)
            setPadding(dp(ctx, 9), dp(ctx, 4), dp(ctx, 9), dp(ctx, 4))
            if (iconName != null) add(icon(ctx, iconName, size + 3, color), WRAP, WRAP, r = 5)
            add(mono(ctx, s, size, color, bold = true, spacing = 0.03f), WRAP, WRAP)
        }

    fun statusChip(ctx: Context, label: String, color: Int): LinearLayout = row(ctx).apply {
        background = rounded(ctx, T.tint(color, 0.10f), 999f, T.tint(color, 0.25f))
        setPadding(dp(ctx, 10), dp(ctx, 6), dp(ctx, 10), dp(ctx, 6))
        add(dot(ctx, color), dp(ctx, 7), dp(ctx, 7))
        add(mono(ctx, label.uppercase(), 10.5f, color, bold = true, spacing = 0.05f), WRAP, WRAP, l = 6)
    }

    fun divider(ctx: Context, leftDp: Int = 0): View = View(ctx).apply {
        setBackgroundColor(T.LINE)
        layoutParams = LinearLayout.LayoutParams(MATCH, dp(ctx, 1)).apply { leftMargin = dp(ctx, leftDp) }
    }

    fun skeleton(ctx: Context, hDp: Int, wDp: Int? = null, radius: Float = 6f): View = View(ctx).apply {
        background = rounded(ctx, T.SURFACE_2, radius)
        layoutParams = LinearLayout.LayoutParams(if (wDp == null) MATCH else dp(ctx, wDp), dp(ctx, hDp))
        val anim = ValueAnimator.ofFloat(1f, 0.45f).apply {
            duration = 900
            repeatMode = ValueAnimator.REVERSE
            repeatCount = ValueAnimator.INFINITE
            addUpdateListener { alpha = it.animatedValue as Float }
        }
        addOnAttachStateChangeListener(object : View.OnAttachStateChangeListener {
            override fun onViewAttachedToWindow(v: View) = anim.start()
            override fun onViewDetachedFromWindow(v: View) = anim.cancel()
        })
    }

    // ---- headings ------------------------------------------------------------------------------------------
    fun pageHeader(ctx: Context, title: String, subtitle: String, label: String? = null): LinearLayout = col(ctx).apply {
        if (label != null) add(overline(ctx, label), b = 6)
        add(h1(ctx, title))
        add(caption(ctx, subtitle, 13.5f), t = 6)
    }

    fun sectionTitle(ctx: Context, title: String, subtitle: String? = null, iconName: String? = null,
                     iconColor: Int = T.TEXT, trailing: View? = null): LinearLayout = row(ctx, Gravity.TOP).apply {
        if (iconName != null) add(squircle(ctx, iconName, iconColor, 34), dp(ctx, 34), dp(ctx, 34), r = 12)
        val texts = col(ctx)
        texts.add(h2(ctx, title))
        if (subtitle != null) texts.add(caption(ctx, subtitle, 12.5f), t = 2)
        add(texts, 0, WRAP, 1f)
        if (trailing != null) add(trailing, WRAP, WRAP, l = 8)
    }

    fun sectionHeader(ctx: Context, s: String): View = overline(ctx, s).apply {
        setPadding(dp(ctx, 2), dp(ctx, 8), 0, 0)
    }

    // ---- buttons --------------------------------------------------------------------------------------------
    enum class Style { PRIMARY, DANGER, SECONDARY, LINK, SAFE_OUTLINE }

    fun button(ctx: Context, label: String, style: Style = Style.PRIMARY, iconName: String? = null,
               onClick: (View) -> Unit): LinearLayout = row(ctx, Gravity.CENTER).apply {
        val (fg, bg, border) = when (style) {
            Style.PRIMARY -> Triple(T.ON_ACCENT, T.SAFE, null)
            Style.DANGER -> Triple(T.FRAUD_TEXT, T.tint(T.FRAUD, 0.14f), T.tint(T.FRAUD, 0.5f))
            Style.SECONDARY -> Triple(T.TEXT, T.SURFACE_2, T.LINE)
            Style.SAFE_OUTLINE -> Triple(T.SAFE_TEXT, T.SURFACE_2, T.LINE)
            Style.LINK -> Triple(T.SAFE_TEXT, Color.TRANSPARENT, null)
        }
        background = rounded(ctx, bg, T.R_INNER, border)
        if (style == Style.LINK) setPadding(dp(ctx, 4), dp(ctx, 6), dp(ctx, 4), dp(ctx, 6))
        else setPadding(dp(ctx, 16), dp(ctx, 14), dp(ctx, 16), dp(ctx, 14))
        if (iconName != null) add(icon(ctx, iconName, if (style == Style.LINK) 16f else 18f, fg), WRAP, WRAP, r = 8)
        add(text(ctx, label, if (style == Style.LINK) 13.5f else 14.5f, 600, fg, maxLines = 1), WRAP, WRAP)
        minimumHeight = dp(ctx, if (style == Style.LINK) 36 else 48)
        pressable(this, T.R_INNER,
            if (style == Style.PRIMARY) T.tint(T.ON_ACCENT, 0.15f) else T.tint(Color.WHITE, 0.10f), onClick)
    }

    fun iconButton(ctx: Context, iconName: String, sizeDp: Int = 48, onClick: (View) -> Unit): FrameLayout =
        FrameLayout(ctx).apply {
            background = rounded(ctx, T.SURFACE_2, T.R_INNER, T.LINE)
            addView(icon(ctx, iconName, 20f, T.TEXT), FrameLayout.LayoutParams(MATCH, MATCH))
            pressable(this, T.R_INNER, onClick = onClick)
            layoutParams = LinearLayout.LayoutParams(dp(ctx, sizeDp), dp(ctx, sizeDp))
        }

    // ---- expandable row (warning signs, lessons, closest messages) ------------------------------------
    /**
     * A row that opens to show more. `header` is the always-visible part; a chevron is added at the end.
     * `trailing` sits before the chevron (e.g. a points pill).
     */
    fun expandable(ctx: Context, leading: View?, title: String, subtitle: String?, trailing: View?,
                   bodyIndentDp: Int, body: View, startOpen: Boolean = false): LinearLayout {
        val box = col(ctx)
        val head = row(ctx, Gravity.CENTER_VERTICAL)
        head.setPadding(0, dp(ctx, 10), 0, dp(ctx, 10))
        if (leading != null) head.add(leading, leading.layoutParams?.width ?: WRAP, leading.layoutParams?.height ?: WRAP, r = 14)
        val texts = col(ctx)
        texts.add(text(ctx, title, 14.5f, 700))
        if (!subtitle.isNullOrBlank()) texts.add(caption(ctx, subtitle, 12.5f), t = 2)
        head.add(texts, 0, WRAP, 1f)
        if (trailing != null) head.add(trailing, WRAP, WRAP, l = 8)
        val chevron = icon(ctx, "EXPAND_MORE", 20f, T.FAINT)
        head.add(chevron, WRAP, WRAP, l = 4)
        val bodyWrap = col(ctx).apply {
            setPadding(dp(ctx, bodyIndentDp), 0, dp(ctx, 4), dp(ctx, 12))
            addView(body, LinearLayout.LayoutParams(MATCH, WRAP))
            visibility = if (startOpen) View.VISIBLE else View.GONE
        }
        chevron.rotation = if (startOpen) 180f else 0f
        pressable(head, 8f) {
            val open = bodyWrap.visibility != View.VISIBLE
            bodyWrap.visibility = if (open) View.VISIBLE else View.GONE
            chevron.animate().rotation(if (open) 180f else 0f).setDuration(180).start()
            if (open) {
                bodyWrap.alpha = 0f
                bodyWrap.animate().alpha(1f).setDuration(200).start()
            }
        }
        box.add(head)
        box.add(bodyWrap)
        return box
    }

    /** Text field in the app style: filled slate, emerald outline while focused. */
    fun field(ctx: Context, hint: String, value: String = "", inputType: Int = android.text.InputType.TYPE_CLASS_TEXT,
              multiLine: Boolean = false, bordered: Boolean = true): android.widget.EditText =
        android.widget.EditText(ctx).apply {
            setText(value)
            this.hint = hint
            textSize = 15f
            typeface = T.font(ctx, 400)
            setTextColor(T.TEXT)
            setHintTextColor(T.MUTED)
            highlightColor = T.tint(T.SAFE, 0.35f)
            this.inputType = if (multiLine) inputType or android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE else inputType
            if (!multiLine) setSingleLine(true)
            gravity = Gravity.TOP or Gravity.START
            if (bordered) {
                val states = android.graphics.drawable.StateListDrawable()
                states.addState(intArrayOf(android.R.attr.state_focused), rounded(ctx, T.SURFACE_2, T.R_INNER, T.SAFE))
                states.addState(intArrayOf(), rounded(ctx, T.SURFACE_2, T.R_INNER, T.LINE))
                background = states
                setPadding(dp(ctx, 14), dp(ctx, 12), dp(ctx, 14), dp(ctx, 12))
            } else {
                background = null
            }
            if (Build.VERSION.SDK_INT >= 29) {
                textCursorDrawable = GradientDrawable().apply { setColor(T.SAFE); setSize(dp(ctx, 2), dp(ctx, 20)) }
            }
        }

    /** Fades and lifts a view in (used when results and screens appear). */
    fun enter(v: View, delayMs: Long = 0) {
        v.alpha = 0f
        v.translationY = dpf(v.context, 10)
        v.animate().alpha(1f).translationY(0f).setStartDelay(delayMs).setDuration(260)
            .setInterpolator(DecelerateInterpolator()).start()
    }
}

/** Circular score gauge: a thin track and an arc that fills to `value` (0..1). */
class RingView(ctx: Context, private val strokeDp: Float = 5f) : View(ctx) {
    private val track = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
    private val arc = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeCap = Paint.Cap.ROUND }
    private val box = RectF()
    private var target = 0f
    private var shown = 0f
    var color: Int = T.SAFE
        set(v) { field = v; invalidate() }
    var trackColor: Int = T.SURFACE_2
        set(v) { field = v; invalidate() }

    fun setValue(v: Float, animate: Boolean = true) {
        target = v.coerceIn(0.02f, 1f)
        if (!animate) { shown = target; invalidate(); return }
        ValueAnimator.ofFloat(0f, target).apply {
            duration = 700
            interpolator = DecelerateInterpolator()
            addUpdateListener { shown = it.animatedValue as Float; invalidate() }
            start()
        }
    }

    override fun onDraw(canvas: Canvas) {
        val sw = K.dpf(context, strokeDp)
        track.strokeWidth = sw; arc.strokeWidth = sw
        track.color = trackColor; arc.color = color
        box.set(sw / 2, sw / 2, width - sw / 2, height - sw / 2)
        canvas.drawOval(box, track)
        canvas.drawArc(box, -90f, 360f * shown, false, arc)
    }
}

/** Rounded horizontal bar filled to `value` (0..1). */
class BarView(ctx: Context, private var value: Float, private val color: Int, private val track: Int) : View(ctx) {
    private val p = Paint(Paint.ANTI_ALIAS_FLAG)
    private val r = RectF()
    override fun onDraw(canvas: Canvas) {
        val rad = height / 2f
        p.color = track
        r.set(0f, 0f, width.toFloat(), height.toFloat())
        canvas.drawRoundRect(r, rad, rad, p)
        p.color = color
        r.set(0f, 0f, (width * value.coerceIn(0f, 1f)).coerceAtLeast(height.toFloat()), height.toFloat())
        canvas.drawRoundRect(r, rad, rad, p)
    }
}

/** Lays children out left to right and wraps onto new lines (chips, legends). */
class FlowLayout(ctx: Context, hGapDp: Int = 6, vGapDp: Int = 6) : ViewGroup(ctx) {
    private val hGap = K.dp(ctx, hGapDp)
    private val vGap = K.dp(ctx, vGapDp)

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val maxW = MeasureSpec.getSize(widthMeasureSpec) - paddingLeft - paddingRight
        var x = 0; var y = 0; var lineH = 0; var widest = 0
        for (i in 0 until childCount) {
            val c = getChildAt(i)
            if (c.visibility == GONE) continue
            measureChild(c, MeasureSpec.makeMeasureSpec(maxW, MeasureSpec.AT_MOST), heightMeasureSpec)
            if (x > 0 && x + c.measuredWidth > maxW) { x = 0; y += lineH + vGap; lineH = 0 }
            x += c.measuredWidth + hGap
            widest = maxOf(widest, x - hGap)
            lineH = maxOf(lineH, c.measuredHeight)
        }
        val w = if (MeasureSpec.getMode(widthMeasureSpec) == MeasureSpec.EXACTLY) MeasureSpec.getSize(widthMeasureSpec)
                else widest + paddingLeft + paddingRight
        setMeasuredDimension(w, y + lineH + paddingTop + paddingBottom)
    }

    override fun onLayout(changed: Boolean, l: Int, t: Int, r: Int, b: Int) {
        val maxW = r - l - paddingLeft - paddingRight
        var x = 0; var y = 0; var lineH = 0
        for (i in 0 until childCount) {
            val c = getChildAt(i)
            if (c.visibility == GONE) continue
            if (x > 0 && x + c.measuredWidth > maxW) { x = 0; y += lineH + vGap; lineH = 0 }
            c.layout(paddingLeft + x, paddingTop + y, paddingLeft + x + c.measuredWidth, paddingTop + y + c.measuredHeight)
            x += c.measuredWidth + hGap
            lineH = maxOf(lineH, c.measuredHeight)
        }
    }
}
