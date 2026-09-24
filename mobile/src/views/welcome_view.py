"""Landing screen.

It shows the part of FraudLens people never see: Shield quietly checking SMS, WhatsApp, email
and calls in the background. A breathing shield and a live feed of checks tell that story, while
examples, lessons and the quiz load behind it.
"""
import asyncio

import flet as ft

import theme as T

W6, W7 = ft.FontWeight.W_600, ft.FontWeight.W_700

# Illustrative feed items (sample messages from the demo set, shown as they'd appear in Shield).
FEED = [
    (ft.Icons.SMS_OUTLINED, "SMS", "MCB ALERT: account suspended…", "high", "92"),
    (ft.Icons.CALL_OUTLINED, "Call", "+230 5821 4470 ringing", "high", "88"),
    (ft.Icons.MAIL_OUTLINE, "Email", "Your OTP for Rs 1,250 at DARTY", "low", "06"),
    (ft.Icons.CHAT_OUTLINED, "WhatsApp", "Hi Mum, this is my new number", "high", "81"),
    (ft.Icons.SMS_OUTLINED, "SMS", "Parcel held: pay Rs 45 release fee", "medium", "54"),
    (ft.Icons.CHAT_OUTLINED, "WhatsApp", "See you at 6 for dinner?", "low", "03"),
]


def _channel(icon_name, label: str) -> ft.Control:
    return ft.Container(
        ft.Row([ft.Icon(icon_name, size=14, color=T.TEXT), T.mono(label.upper(), 10, T.TEXT, bold=True)],
               spacing=5, tight=True),
        padding=ft.Padding.symmetric(horizontal=9, vertical=6), border_radius=8, bgcolor=T.SURFACE,
        border=ft.Border.all(1, T.LINE),
    )


def _feed_row(item) -> ft.Control:
    icon_name, channel, preview, level, score = item
    r = T.RISK[level]
    verdict = {"high": "SCAM", "medium": "CHECK", "low": "SAFE"}[level]
    return ft.Container(
        ft.Row([
            ft.Container(ft.Icon(icon_name, size=16, color=T.MUTED), width=32, height=32, border_radius=8,
                         bgcolor=T.SURFACE_2, alignment=ft.Alignment.CENTER),
            ft.Column([T.mono(channel.upper(), 10, T.MUTED, spacing=1),
                       T.text(preview, 13, ft.FontWeight.W_500, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS)],
                      spacing=1, expand=True),
            ft.Container(ft.Row([T.dot(r["fill"], 6), T.mono(f"{verdict} {score}", 10.5, r["color"], bold=True)],
                                spacing=5, tight=True),
                         padding=ft.Padding.symmetric(horizontal=8, vertical=5), border_radius=6, bgcolor=r["bg"]),
        ], spacing=10),
        padding=ft.Padding.symmetric(horizontal=12, vertical=9),
    )


class WelcomeView:
    def __init__(self, on_start):
        self.running = True
        self._tick = 0
        self.status = T.mono("LOADING EXAMPLES…", 10.5, T.MUTED, spacing=1)

        # ---- shield pulse ----------------------------------------------------------------------
        def ring(size: int, opacity: float) -> ft.Container:
            return ft.Container(width=size, height=size, border_radius=size / 2,
                                border=ft.Border.all(1, T.tint(T.SAFE, opacity)),
                                animate_scale=ft.Animation(1500, ft.AnimationCurve.EASE_IN_OUT),
                                animate_opacity=ft.Animation(1500, ft.AnimationCurve.EASE_IN_OUT))
        self.rings = [ring(210, 0.18), ring(150, 0.30), ring(96, 0.5)]
        self.glow = ft.Container(width=120, height=120, border_radius=60, bgcolor=T.tint(T.SAFE, 0.10),
                                 animate_scale=ft.Animation(1500, ft.AnimationCurve.EASE_IN_OUT))
        core = ft.Container(ft.Icon(ft.Icons.SHIELD, size=30, color=T.ON_ACCENT), width=64, height=64,
                            border_radius=20, bgcolor=T.SAFE, alignment=ft.Alignment.CENTER)

        def centered(c):
            return ft.Container(c, alignment=ft.Alignment.CENTER, left=0, right=0, top=0, bottom=0)

        pulse = ft.Stack(
            [centered(self.glow), *[centered(r) for r in self.rings], centered(core),
             ft.Container(_channel(ft.Icons.SMS_OUTLINED, "SMS"), left=8, top=36),
             ft.Container(_channel(ft.Icons.CHAT_OUTLINED, "WhatsApp"), right=0, top=22),
             ft.Container(_channel(ft.Icons.MAIL_OUTLINE, "Email"), left=0, bottom=34),
             ft.Container(_channel(ft.Icons.CALL_OUTLINED, "Calls"), right=16, bottom=18)],
            height=230,
        )

        # ---- live feed -------------------------------------------------------------------------
        self.feed = ft.Column(spacing=0)
        self.feed_switch = ft.AnimatedSwitcher(self.feed, transition=ft.AnimatedSwitcherTransition.FADE,
                                               duration=350, reverse_duration=200)
        self._render_feed()
        feed_card = ft.Container(
            ft.Column([
                ft.Container(ft.Row([T.dot(T.SAFE), T.mono("SHIELD · RUNNING IN BACKGROUND", 10.5, T.SAFE_TEXT,
                                                            bold=True, spacing=1),
                                     ft.Container(expand=True), T.mono("LIVE", 10.5, T.MUTED, spacing=1)],
                                    spacing=8),
                             padding=ft.Padding.only(left=12, right=12, top=11, bottom=9)),
                ft.Divider(height=1, thickness=1, color=T.LINE),
                self.feed_switch,
            ], spacing=0),
            bgcolor=T.SURFACE, border_radius=T.R_CARD, border=ft.Border.all(1, T.LINE),
            clip_behavior=ft.ClipBehavior.HARD_EDGE,
        )

        self.start_btn = ft.FilledButton(
            content=ft.Row([T.text("Get started", 15, W6, T.ON_ACCENT),
                            ft.Icon(ft.Icons.ARROW_FORWARD, color=T.ON_ACCENT, size=18)],
                           alignment=ft.MainAxisAlignment.CENTER, spacing=8),
            style=T.primary_style(), on_click=lambda e: self._start(on_start), height=52,
        )
        self.points = ft.Row([
            ft.Row([ft.Icon(ft.Icons.LOCK_OUTLINE, size=14, color=T.MUTED),
                    T.caption("Personal details hidden", size=12)], spacing=5, tight=True),
            ft.Row([ft.Icon(ft.Icons.LAYERS_OUTLINED, size=14, color=T.MUTED),
                    T.caption("5 checks per message", size=12)], spacing=5, tight=True),
        ], spacing=16, wrap=True)

        content = ft.Column(
            [
                ft.Row([ft.Container(ft.Icon(ft.Icons.SHIELD, color=T.ON_ACCENT, size=16), width=30, height=30,
                                     border_radius=9, bgcolor=T.SAFE, alignment=ft.Alignment.CENTER),
                        T.text("FraudLens", 17, W7), ft.Container(expand=True),
                        T.status_chip("Shield", T.SAFE)], spacing=10),
                pulse,
                ft.Column([
                    T.display("Scam protection\nthat never clocks off."),
                    T.text("Shield checks SMS, WhatsApp, email and calls the moment they arrive, and warns "
                           "you before you reply or pay. Or paste any message to check it yourself.",
                           14.5, color=T.MUTED),
                ], spacing=12),
                feed_card,
                self.points,
            ],
            spacing=22, scroll=ft.ScrollMode.AUTO, horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
            expand=True,
        )
        # "Get started" stays pinned at the bottom on every screen height; the story scrolls above it.
        cta = ft.Container(
            ft.Column([self.start_btn, ft.Row([self.status], alignment=ft.MainAxisAlignment.CENTER)],
                      spacing=10, horizontal_alignment=ft.CrossAxisAlignment.STRETCH),
            padding=ft.Padding.only(top=12, bottom=18),
            gradient=ft.LinearGradient(colors=[ft.Colors.with_opacity(0, T.BG), T.BG, T.BG],
                                       begin=ft.Alignment.TOP_CENTER, end=ft.Alignment.BOTTOM_CENTER),
        )
        self.pulse = pulse
        self.body = ft.Container(ft.Column([content, cta], spacing=0, expand=True),
                                 padding=ft.Padding.only(left=20, right=20, top=24))
        self.root = ft.Container(
            ft.Row([self.body], alignment=ft.MainAxisAlignment.CENTER,
                   vertical_alignment=ft.CrossAxisAlignment.STRETCH, expand=True),
            gradient=ft.RadialGradient(colors=[T.tint(T.SAFE, 0.07), T.BG], center=ft.Alignment(0, -0.62),
                                       radius=0.9),
            bgcolor=T.BG, expand=True,
        )

    # ---- animation --------------------------------------------------------------------------
    def _render_feed(self) -> None:
        n = len(FEED)
        rows = []
        for i in range(3):
            if i:
                rows.append(ft.Divider(height=1, thickness=1, color=T.LINE))
            rows.append(_feed_row(FEED[(self._tick + i) % n]))
        # A new Column each time so the AnimatedSwitcher cross-fades between feeds.
        self.feed = ft.Column(rows, spacing=0, key=f"feed{self._tick}")
        self.feed_switch.content = self.feed

    async def animate(self, page: ft.Page) -> None:
        """Breathing rings + a feed that keeps moving, until the user taps Get started."""
        grow = True
        while self.running:
            for i, r in enumerate(self.rings):
                r.scale = (1.12 + i * 0.04) if grow else 1.0
                r.opacity = 0.35 if grow else 1.0
            self.glow.scale = 1.25 if grow else 0.9
            if not grow:
                self._tick += 1
                self._render_feed()
            grow = not grow
            try:
                page.update()
            except Exception:
                return
            await asyncio.sleep(1.6)

    def _start(self, on_start) -> None:
        self.running = False
        on_start()

    # ---- layout / state ---------------------------------------------------------------------
    def set_size(self, w: float, h: float) -> None:
        self.body.width = min(w, 480)
        self.points.visible = h >= 860
        self.pulse.height = 230 if h >= 800 else 190

    def set_ready(self, online: bool | None) -> None:
        self.status.value = ("CONNECTED · READY" if online else "OFFLINE DEMO · EXAMPLES STILL WORK")
        self.status.color = T.SAFE_TEXT if online else T.WARN
