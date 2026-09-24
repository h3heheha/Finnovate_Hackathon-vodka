"""Check tab: paste a message, scan it, see the Scam X-Ray result."""
import flet as ft

import theme as T
from components import result_panel
from services.api_client import OfflineError, RateLimitedError

W6, W7 = ft.FontWeight.W_600, ft.FontWeight.W_700


class CheckView:
    def __init__(self, app):
        self.app = app
        self.input = ft.TextField(
            multiline=True, min_lines=5, max_lines=9, border=ft.InputBorder.NONE, text_size=15,
            text_style=T.style(15, color=T.TEXT), cursor_color=T.SAFE,
            hint_text="Paste an SMS, WhatsApp or email message here…", hint_style=T.style(15, color=T.HINT),
            content_padding=ft.Padding.only(left=18, right=18, top=6, bottom=10),
        )
        self.sender = ft.TextField(
            hint_text="Sender (optional), e.g. MCB or +230 5821 4470", border=ft.InputBorder.NONE,
            hint_style=T.style(14, color=T.HINT), text_style=T.style(14, color=T.TEXT), text_size=14, dense=True, expand=True,
            cursor_color=T.PRIMARY, content_padding=ft.Padding.symmetric(horizontal=4, vertical=12),
        )
        self.scan_btn = ft.FilledButton(
            "Scan message", icon=ft.Icons.DOCUMENT_SCANNER, on_click=self.on_scan, style=T.primary_style(),
            expand=True,
        )
        self.samples_grid = ft.ResponsiveRow(spacing=10, run_spacing=10)
        self._show_sample_skeletons()
        self.loading = ft.Container(content=self._loading_card(), visible=False)
        self.error = ft.Container(visible=False)
        self.results = ft.Column(spacing=T.GAP, horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
                                 key=ft.ScrollKey("results"))
        # Everything above the result. Its measured height tells the app how far to scroll
        # so the verdict lands at the top of the screen, whatever the screen width.
        self.top_height = 460.0
        self.examples_block = ft.Column(
            [ft.Row([T.overline("Or try an example"), ft.Container(expand=True),
                     T.caption("Tap to scan", size=12)]),
             self.samples_grid],
            spacing=10, key=ft.ScrollKey("examples"),
        )
        self.top = ft.Column(
            [
                T.page_header("Check a message", "Paste a suspicious text, WhatsApp or email. FraudLens shows "
                              "you the tricks before you reply or pay.", "Scam X-Ray"),
                self._input_card(),
                self.examples_block,
            ],
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH, spacing=18,
            on_size_change=self._on_top_size, size_change_interval=100,
        )
        self.root = ft.Column(
            [self.top, self.loading, self.error, self.results],
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH, spacing=18,
        )

    def _input_card(self) -> ft.Control:
        return T.card(
            ft.Column(
                [
                    ft.Container(ft.Row([T.dot(T.SAFE), T.mono("MESSAGE", 10.5, T.TEXT, bold=True, spacing=1.2),
                                         ft.Container(expand=True),
                                         T.mono("SMS · WHATSAPP · EMAIL", 10, T.MUTED, spacing=1)], spacing=8),
                                 padding=ft.Padding.only(left=16, right=16, top=14, bottom=4)),
                    self.input,
                    ft.Container(
                        ft.Row([ft.Icon(ft.Icons.PERSON_OUTLINE, color=T.FAINT, size=20), self.sender],
                               spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                        margin=ft.Margin.symmetric(horizontal=12), padding=ft.Padding.symmetric(horizontal=8),
                        bgcolor=T.SUBTLE, border_radius=T.R_INNER,
                    ),
                    ft.Container(
                        ft.Row([
                            ft.IconButton(ft.Icons.CONTENT_PASTE, tooltip="Paste from clipboard", icon_color=T.TEXT,
                                          on_click=self.on_paste, style=T.tool_style()),
                            ft.IconButton(ft.Icons.CLEAR, tooltip="Clear", icon_color=T.TEXT, on_click=self.on_clear,
                                          style=T.tool_style()),
                            self.scan_btn,
                        ], spacing=8),
                        padding=ft.Padding.all(12),
                    ),
                ],
                spacing=0,
            ),
            padding=0,
        )

    def _loading_card(self) -> ft.Control:
        steps = [(ft.Icons.RULE, "Warning signs"), (ft.Icons.PSYCHOLOGY, "AI layers"),
                 (ft.Icons.PUBLIC, "Security databases")]
        return T.card(ft.Column([
            ft.Row([ft.ProgressRing(width=26, height=26, stroke_width=3, color=T.PRIMARY,
                                    bgcolor=T.PRIMARY_SOFT),
                    ft.Column([T.text("Checking this message…", 15.5, W7),
                               T.caption("This usually takes a second or two.", size=12.5)],
                              spacing=1, expand=True)], spacing=14),
            ft.Row([ft.Container(ft.Row([ft.Icon(i, size=15, color=T.PRIMARY), T.text(t, 12, W6, T.PRIMARY)],
                                        spacing=5, tight=True),
                                 padding=ft.Padding.symmetric(horizontal=10, vertical=6), border_radius=999,
                                 bgcolor=T.PRIMARY_SOFT) for i, t in steps], wrap=True, spacing=6, run_spacing=6),
            T.skeleton(12, None), T.skeleton(12, 220),
        ], spacing=14), padding=20)

    def _on_top_size(self, e) -> None:
        if getattr(e, "height", None):
            self.top_height = e.height

    # ---- data -----------------------------------------------------------------
    def _show_sample_skeletons(self) -> None:
        self.samples_grid.controls = [
            ft.Container(ft.Row([T.skeleton(34, 34, 11), ft.Column([T.skeleton(12, 110), T.skeleton(10, 60)],
                                                                   spacing=6)], spacing=10),
                         padding=12, bgcolor=T.SURFACE, border_radius=T.R_INNER, border=ft.Border.all(1, T.BORDER),
                         col={"xs": 6})
            for _ in range(4)
        ]

    def set_samples(self, samples: list[dict]) -> None:
        def tile(s: dict) -> ft.Control:
            legit = s.get("expected") == "legit"
            level = T.RISK["low" if legit else "high"]
            return ft.Container(
                content=ft.Row([
                    T.squircle(ft.Icons.CHECK_CIRCLE_OUTLINE if legit else ft.Icons.SMS_FAILED_OUTLINED,
                               level["color"], 36, level["bg"]),
                    ft.Column([T.text(s["title"], 13.5, W6, max_lines=2, overflow=ft.TextOverflow.ELLIPSIS),
                               T.text("Genuine" if legit else "Scam", 11.5, W7, level["color"])],
                              spacing=1, expand=True, alignment=ft.MainAxisAlignment.CENTER),
                ], spacing=10),
                height=82, padding=ft.Padding.symmetric(horizontal=10), border_radius=T.R_INNER,
                bgcolor=T.SURFACE, border=ft.Border.all(1, T.BORDER), ink=True, col={"xs": 6},
                on_click=lambda e, s=s: self.app.page.run_task(self.use_sample, s),
            )
        self.samples_grid.controls = [tile(s) for s in samples]

    async def use_sample(self, sample: dict) -> None:
        self.input.value = sample["text"]
        self.sender.value = sample.get("sender") or ""
        self.app.page.update()
        await self.on_scan(None)

    def show_analysis(self, analysis: dict, offline: bool = False) -> None:
        self.input.value = analysis.get("_text", self.input.value)
        self.sender.value = analysis.get("_sender") or ""
        self.results.controls = [result_panel.build(analysis, self.app, offline)]
        self.error.visible = False

    # ---- events --------------------------------------------------------------
    async def on_scan(self, e) -> None:
        text = (self.input.value or "").strip()
        if not text:
            self.app.toast("Paste a message first.")
            return
        self.loading.visible = True
        self.scan_btn.disabled = True
        self.error.visible = False
        self.results.controls = []
        self.app.page.update()
        # Bring the progress card into view, right where the verdict will appear.
        self.app.page.run_task(self.app.scroll_to_results)
        try:
            sender = (self.sender.value or "").strip() or None
            analysis, offline = await self.app.state.api.analyze(text, sender=sender)
            self.app.state.add_analysis(analysis, text, sender)
            self.show_analysis(self.app.state.current, offline)
            self.app.refresh_status()
            self.loading.visible = False
            self.app.page.update()
            await self.app.scroll_to_results()
        except OfflineError as exc:
            medium = T.RISK["medium"]
            self.error.content = T.card(
                ft.Row([T.squircle(ft.Icons.CLOUD_OFF, medium["color"], 40, T.SURFACE),
                        T.body(str(exc) + " The examples above still work offline.", size=13.5, expand=True)],
                       spacing=12),
                bgcolor=medium["bg"], border_color=T.tint(medium["color"], 0.3),
            )
            self.error.visible = True
            self.app.refresh_status()
        except RateLimitedError as exc:
            self.error.content = T.card(T.body(str(exc), size=13.5))
            self.error.visible = True
        except Exception as exc:  # keep the demo alive whatever happens
            self.error.content = T.card(T.body(f"Something went wrong: {exc}", size=13.5))
            self.error.visible = True
        finally:
            self.loading.visible = False
            self.scan_btn.disabled = False
            self.app.page.update()
        if self.error.visible:  # the error card sits below the examples, so bring it into view
            await self.app.scroll_to_results()

    async def on_paste(self, e) -> None:
        try:
            value = await ft.Clipboard().get()
        except Exception:
            value = None
        if value:
            self.input.value = value
            self.app.page.update()
        elif self.app.in_android_app():
            # Web paste needs HTTPS; the Android app has a native one in the Shield tab.
            self.app.toast("Long-press the message box → Paste, or use Shield tab → Check copied text.")
        else:
            self.app.toast("Clipboard is empty.")

    def on_clear(self, e) -> None:
        self.input.value = ""
        self.sender.value = ""
        self.results.controls = []
        self.error.visible = False
