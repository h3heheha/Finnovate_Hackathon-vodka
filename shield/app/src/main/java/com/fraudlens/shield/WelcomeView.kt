package com.fraudlens.shield

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.FrameLayout
import android.widget.ScrollView
import android.widget.TextView
import com.fraudlens.shield.K.add

/** Breathing rings behind the shield: Shield quietly working in the background. */
class PulseView(ctx: Context) : View(ctx) {
    private val ring = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
    private val glow = Paint(Paint.ANTI_ALIAS_FLAG)
    private var phase = 0f
    private val anim = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = 1600
        repeatMode = ValueAnimator.REVERSE
        repeatCount = ValueAnimator.INFINITE
        interpolator = AccelerateDecelerateInterpolator()
        addUpdateListener { phase = it.animatedValue as Float; invalidate() }
    }

    override fun onAttachedToWindow() { super.onAttachedToWindow(); anim.start() }
    override fun onDetachedFromWindow() { anim.cancel(); super.onDetachedFromWindow() }

    override fun onDraw(canvas: Canvas) {
        val cx = width / 2f
        val cy = height / 2f
        glow.color = T.tint(T.SAFE, 0.10f)
        canvas.drawCircle(cx, cy, K.dpf(context, 60) * (0.9f + 0.35f * phase), glow)
        ring.strokeWidth = K.dpf(context, 1)
        listOf(105f to 0.18f, 75f to 0.30f, 48f to 0.5f).forEachIndexed { i, (r, a) ->
            val scale = 1f + (0.12f + i * 0.04f) * phase
            ring.color = T.tint(T.SAFE, a * (1f - 0.65f * phase))
            canvas.drawCircle(cx, cy, K.dpf(context, r) * scale, ring)
        }
    }
}

/**
 * Landing screen. It shows the part of FraudLens people never see: Shield checking SMS, WhatsApp, email and
 * calls in the background. A breathing shield and a live feed tell that story while content loads behind it.
 */
class WelcomeView(private val ctx: Context, private val onStart: () -> Unit) : FrameLayout(ctx) {
    private val feed = K.col(ctx)
    private val status: TextView = K.mono(ctx, "CONNECTING…", 10.5f, T.MUTED, spacing = 0.08f).apply { gravity = Gravity.CENTER }
    private var tick = 0
    private var running = true
    private val column = K.col(ctx)

    private val items = listOf(
        Feed("SMS_OUTLINED", "SMS", "MCB ALERT: account suspended…", "high", "92"),
        Feed("CALL_OUTLINED", "Call", "+230 5821 4470 ringing", "high", "88"),
        Feed("MAIL_OUTLINE", "Email", "Your OTP for Rs 1,250 at DARTY", "low", "06"),
        Feed("CHAT_OUTLINED", "WhatsApp", "Hi Mum, this is my new number", "high", "81"),
        Feed("SMS_OUTLINED", "SMS", "Parcel held: pay Rs 45 release fee", "medium", "54"),
        Feed("CHAT_OUTLINED", "WhatsApp", "See you at 6 for dinner?", "low", "03"),
    )

    private class Feed(val icon: String, val channel: String, val preview: String, val level: String, val score: String)

    init {
        isClickable = true  // nothing underneath reacts while the landing screen is up
        background = GradientDrawable().apply {
            gradientType = GradientDrawable.RADIAL_GRADIENT
            colors = intArrayOf(T.tint(T.SAFE, 0.08f), T.BG)
            setGradientCenter(0.5f, 0.2f)
            gradientRadius = K.dpf(ctx, 420)
        }
        val scroll = ScrollView(ctx).apply { isVerticalScrollBarEnabled = false; isFillViewport = true }
        val content = K.col(ctx)
        content.setPadding(K.dp(ctx, 20), K.dp(ctx, 16), K.dp(ctx, 20), K.dp(ctx, 12))
        scroll.addView(content)

        val head = K.row(ctx)
        head.add(FrameLayout(ctx).apply {
            background = K.rounded(ctx, T.SAFE, 9f)
            addView(K.icon(ctx, "SHIELD", 16f, T.ON_ACCENT), LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT))
        }, K.dp(ctx, 30), K.dp(ctx, 30), r = 10)
        head.add(K.text(ctx, "FraudLens", 17f, 700), K.WRAP, K.WRAP)
        head.add(K.space(ctx), 0, 1, 1f)
        head.add(K.statusChip(ctx, "Shield", T.SAFE), K.WRAP, K.WRAP)
        content.add(head)

        val pulse = FrameLayout(ctx)
        pulse.addView(PulseView(ctx), LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT))
        pulse.addView(FrameLayout(ctx).apply {
            background = K.rounded(ctx, T.SAFE, 20f)
            elevation = K.dpf(ctx, 6)
            addView(K.icon(ctx, "SHIELD", 30f, T.ON_ACCENT), LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT))
        }, LayoutParams(K.dp(ctx, 64), K.dp(ctx, 64), Gravity.CENTER))
        fun chip(icon: String, label: String, g: Int, l: Int, t: Int, r: Int, b: Int) {
            val c = K.row(ctx).apply {
                background = K.rounded(ctx, T.SURFACE, 8f, T.LINE)
                setPadding(K.dp(ctx, 9), K.dp(ctx, 6), K.dp(ctx, 9), K.dp(ctx, 6))
                add(K.icon(ctx, icon, 14f, T.TEXT), K.WRAP, K.WRAP, r = 5)
                add(K.mono(ctx, label.uppercase(), 10f, T.TEXT, bold = true), K.WRAP, K.WRAP)
            }
            pulse.addView(c, LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT, g).apply {
                setMargins(K.dp(ctx, l), K.dp(ctx, t), K.dp(ctx, r), K.dp(ctx, b))
            })
        }
        chip("SMS_OUTLINED", "SMS", Gravity.TOP or Gravity.START, 8, 36, 0, 0)
        chip("CHAT_OUTLINED", "WhatsApp", Gravity.TOP or Gravity.END, 0, 22, 0, 0)
        chip("MAIL_OUTLINE", "Email", Gravity.BOTTOM or Gravity.START, 0, 0, 0, 34)
        chip("CALL_OUTLINED", "Calls", Gravity.BOTTOM or Gravity.END, 0, 0, 16, 18)
        val tall = ctx.resources.displayMetrics.heightPixels / ctx.resources.displayMetrics.density >= 760
        content.add(pulse, K.MATCH, K.dp(ctx, if (tall) 230 else 190), t = 12)

        content.add(K.display(ctx, "Scam protection\nthat never clocks off."), t = 14)
        content.add(K.text(ctx, "Shield checks SMS, WhatsApp, email and calls the moment they arrive, and warns you before " +
            "you reply or pay. Or check any message yourself.", 14.5f, color = T.MUTED), t = 12)

        val feedCard = K.col(ctx).apply { background = K.rounded(ctx, T.SURFACE, T.R_CARD, T.LINE) }
        K.clipRounded(feedCard, T.R_CARD)
        val fh = K.row(ctx)
        fh.setPadding(K.dp(ctx, 12), K.dp(ctx, 11), K.dp(ctx, 12), K.dp(ctx, 9))
        fh.add(K.dot(ctx, T.SAFE), K.dp(ctx, 7), K.dp(ctx, 7), r = 8)
        fh.add(K.mono(ctx, "SHIELD · RUNNING IN BACKGROUND", 10.5f, T.SAFE_TEXT, bold = true, spacing = 0.06f), 0, K.WRAP, 1f)
        fh.add(K.mono(ctx, "LIVE", 10.5f, T.MUTED, spacing = 0.08f), K.WRAP, K.WRAP, l = 8)
        feedCard.add(fh)
        feedCard.add(K.divider(ctx))
        feedCard.add(feed)
        renderFeed()
        content.add(feedCard, t = 22)

        val points = K.row(ctx)
        for ((ic, s) in listOf("LOCK_OUTLINE" to "Personal details hidden", "LAYERS_OUTLINED" to "5 checks per message")) {
            points.add(K.icon(ctx, ic, 14f, T.MUTED), K.WRAP, K.WRAP, r = 5, l = if (points.childCount > 0) 16 else 0)
            points.add(K.caption(ctx, s, 12f), K.WRAP, K.WRAP)
        }
        content.add(points, t = 18)

        column.add(scroll, K.MATCH, 0, 1f)
        val cta = K.col(ctx)
        cta.setPadding(K.dp(ctx, 20), K.dp(ctx, 10), K.dp(ctx, 20), K.dp(ctx, 18))
        cta.add(K.button(ctx, "Get started", K.Style.PRIMARY, "ARROW_FORWARD") { start() }, K.MATCH, K.dp(ctx, 52))
        cta.add(status, t = 10)
        column.add(cta)
        addView(column, LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT))
        postDelayed(::advance, 3200)
    }

    /** Padding for the status and navigation bars (and side bars or cutouts in landscape). */
    fun setInsets(top: Int, bottom: Int, left: Int = 0, right: Int = 0) = column.setPadding(left, top, right, bottom)

    fun setReady(online: Boolean?) {
        val (s, c) = when (online) {
            true -> "CONNECTED · READY" to T.SAFE_TEXT
            false -> "OFFLINE DEMO · EXAMPLES STILL WORK" to T.WARN
            null -> "CONNECTING…" to T.MUTED
        }
        status.text = s
        status.setTextColor(c)
    }

    private fun renderFeed() {
        feed.removeAllViews()
        for (i in 0 until 3) {
            if (i > 0) feed.add(K.divider(ctx))
            val f = items[(tick + i) % items.size]
            val r = T.risk(f.level)
            val row = K.row(ctx)
            row.setPadding(K.dp(ctx, 12), K.dp(ctx, 9), K.dp(ctx, 12), K.dp(ctx, 9))
            row.add(K.squircle(ctx, f.icon, T.MUTED, 32, T.SURFACE_2, false), K.dp(ctx, 32), K.dp(ctx, 32), r = 10)
            val t = K.col(ctx)
            t.add(K.mono(ctx, f.channel.uppercase(), 10f, T.MUTED, spacing = 0.08f))
            t.add(K.text(ctx, f.preview, 13f, 500, maxLines = 1), t = 2)
            row.add(t, 0, K.WRAP, 1f)
            val v = K.row(ctx).apply {
                background = K.rounded(ctx, r.bg, 6f)
                setPadding(K.dp(ctx, 8), K.dp(ctx, 5), K.dp(ctx, 8), K.dp(ctx, 5))
                add(K.dot(ctx, r.fill, 6), K.dp(ctx, 6), K.dp(ctx, 6), r = 5)
                add(K.mono(ctx, "${r.word} ${f.score}", 10.5f, r.color, bold = true), K.WRAP, K.WRAP)
            }
            row.add(v, K.WRAP, K.WRAP, l = 8)
            feed.add(row)
        }
    }

    private fun advance() {
        if (!running) return
        feed.animate().alpha(0f).setDuration(200).withEndAction {
            tick++
            renderFeed()
            feed.animate().alpha(1f).setDuration(350).start()
        }.start()
        postDelayed(::advance, 3200)
    }

    private fun start() {
        if (!running) return
        running = false
        animate().alpha(0f).setDuration(260).withEndAction { onStart() }.start()
    }

    fun stop() { running = false }
}
