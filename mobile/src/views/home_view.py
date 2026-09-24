"""Home tab: a menu of everything FraudLens can do.

Each feature is a button: icon, name, and a one-line description in small text underneath.
Tapping it opens the page (or panel) where that feature already lives. Nothing new is added here.
"""
import flet as ft

import theme as T

W5, W6, W7 = ft.FontWeight.W_500, ft.FontWeight.W_600, ft.FontWeight.W_700


class HomeView:
    def __init__(self, app):
        self.app = app
        self.samples: list[dict] = []
        self.summary = ft.Row(spacing=0)
        self.example_hint = T.caption("Real scams and genuine texts to test", size=12.5)
        self.root = ft.Column(
            [
                T.page_header("What would you like to do?",
                              "Pick a feature. Everything runs through the same five-layer scam check.",
                              "FraudLens"),
                self._primary(),
                self.summary,
                T.section_header("Check"),
                self._group([
                    (ft.Icons.CONTENT_PASTE, "Paste and scan", "Check your clipboard in one tap",
                     lambda e: self.app.page.run_task(self.app.paste_and_check)),
                    (ft.Icons.BOLT_OUTLINED, "Try a real example", self.example_hint,
                     lambda e: self.app.go_to_examples()),
                ]),
                T.section_header("Learn"),
                self._group([
                    (ft.Icons.QUIZ_OUTLINED, "Spot-the-scam quiz", "Find the red flag in real messages",
                     lambda e: self.app.show_tab("learn")),
                    (ft.Icons.MENU_BOOK_OUTLINED, "Scam tricks", "30-second lessons on each trick",
                     lambda e: self.app.go_to_lessons()),
                ]),
                T.section_header("Protection"),
                self._group([
                    (ft.Icons.RADAR, "Shield in the background",
                     "How messages and calls are checked as they arrive",
                     lambda e: self.app.show_shield_info()),
                    (ft.Icons.HISTORY, "History", "Everything you've checked, on this device",
                     lambda e: self.app.show_tab("history")),
                    (ft.Icons.VERIFIED_OUTLINED, "Verified contacts",
                     "Official numbers, never from a message",
                     lambda e: self.app.show_official_contact({})),
                    (ft.Icons.GROUPS_OUTLINED, "Ask someone you trust",
                     "Message your trusted contact first",
                     lambda e: self.app.share_with_guardian()),
                    (ft.Icons.DNS_OUTLINED, "Server settings", "Connect to your FraudLens server",
                     self.app.open_settings),
                ]),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH, spacing=T.GAP,
        )
        self.refresh()

    # ---- building blocks ------------------------------------------------------------------
    def _primary(self) -> ft.Control:
        """The main feature, one size up: scan a message."""
        return ft.Container(
            ft.Row([
                ft.Container(ft.Icon(ft.Icons.DOCUMENT_SCANNER_OUTLINED, color=T.ON_ACCENT, size=24), width=48,
                             height=48, border_radius=13, bgcolor=T.SAFE, alignment=ft.Alignment.CENTER),
                ft.Column([T.text("Scan a message", 16.5, W7),
                           T.caption("Paste an SMS, WhatsApp or email. See every trick highlighted, "
                                     "and what to do next.", size=12.5)], spacing=3, expand=True),
                ft.Container(ft.Icon(ft.Icons.ARROW_FORWARD, color=T.ON_ACCENT, size=18), width=34, height=34,
                             border_radius=10, bgcolor=T.SAFE, alignment=ft.Alignment.CENTER),
            ], spacing=14),
            padding=16, border_radius=T.R_CARD, bgcolor=T.tint(T.SAFE, 0.08),
            border=ft.Border.all(1, T.tint(T.SAFE, 0.35)), ink=True,
            on_click=lambda e: self.app.go_to_check(),
        )

    def _feature(self, icon_name, name: str, desc, on_click) -> ft.Control:
        desc_ctl = desc if isinstance(desc, ft.Control) else T.caption(desc, size=12.5)
        return ft.Container(
            ft.Row([
                T.squircle(icon_name, T.TEXT, 38),
                ft.Column([T.text(name, 14.5, W6), desc_ctl], spacing=2, expand=True),
                ft.Icon(ft.Icons.CHEVRON_RIGHT, color=T.FAINT, size=20),
            ], spacing=14),
            padding=ft.Padding.symmetric(horizontal=14, vertical=12), ink=True, on_click=on_click,
        )

    def _group(self, items) -> ft.Control:
        rows = []
        for i, it in enumerate(items):
            if i:
                rows.append(ft.Container(T.divider(), padding=ft.Padding.only(left=66)))
            rows.append(self._feature(*it))
        return ft.Container(ft.Column(rows, spacing=0), bgcolor=T.SURFACE, border_radius=T.R_CARD,
                            border=ft.Border.all(1, T.LINE), clip_behavior=ft.ClipBehavior.HARD_EDGE)

    # ---- data ---------------------------------------------------------------------------------
    def set_samples(self, samples: list[dict]) -> None:
        self.samples = samples
        if samples:
            scams = sum(1 for s in samples if s.get("expected") != "legit")
            self.example_hint.value = f"{scams} real scams and {len(samples) - scams} genuine texts to test"

    def refresh(self) -> None:
        st = self.app.state
        safe = sum(1 for h in st.history if h.get("risk_level") == "low")

        def stat(value: int, label: str, color: str) -> ft.Control:
            return ft.Container(
                ft.Column([T.mono(f"{value:02d}", 20, color, bold=True, spacing=0),
                           T.mono(label.upper(), 9.5, T.MUTED, spacing=1)], spacing=2),
                expand=True, padding=ft.Padding.symmetric(horizontal=14, vertical=10),
                on_click=lambda e: self.app.show_tab("history"),
            )
        sep = ft.Container(width=1, height=34, bgcolor=T.LINE)
        self.summary.controls = [ft.Container(
            ft.Row([stat(len(st.history), "Checked", T.TEXT), sep,
                    stat(st.scams_caught, "Scams", T.FRAUD_TEXT), sep,
                    stat(safe, "Safe", T.SAFE_TEXT)], spacing=0),
            bgcolor=T.SURFACE, border_radius=T.R_CARD, border=ft.Border.all(1, T.LINE), expand=True,
        )]
