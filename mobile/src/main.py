"""FraudLens mobile app (Flet).

Run on desktop:        flet run src/main.py            (from the mobile/ folder)
Run in a browser:      flet run --web src/main.py
Run on your phone:     flet run --android / --ios  (Flet companion app)
Build an APK:          flet build apk

The app is a thin client: all detection happens in the FastAPI backend.
"""
import asyncio

import flet as ft

import theme as T
from config import APP_NAME, DEFAULT_API_URL, GUARDIAN
from services.api_client import ApiClient
from state import AppState
from views.check_view import CheckView
from views.history_view import HistoryView
from views.home_view import HomeView
from views.learn_view import LearnView
from views.welcome_view import WelcomeView

TABS = ["home", "check", "learn", "history"]


class FraudLensApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.state = AppState(api=ApiClient(DEFAULT_API_URL))
        self.directory: dict = {}
        self.current_tab = "home"

        self.welcome = WelcomeView(self.enter_app)
        self.check = CheckView(self)
        self.learn = LearnView(self)
        self.history = HistoryView(self)
        self.home = HomeView(self)
        self.views = {"home": self.home, "check": self.check, "learn": self.learn, "history": self.history}

        self.status = ft.Container()
        # Tabs cross-fade instead of jumping (AnimatedSwitcher), for a smoother feel.
        self.switcher = ft.AnimatedSwitcher(
            content=self.home.root, transition=ft.AnimatedSwitcherTransition.FADE, duration=220,
            reverse_duration=120, switch_in_curve=ft.AnimationCurve.EASE_OUT,
            switch_out_curve=ft.AnimationCurve.EASE_IN,
        )
        # Bottom padding leaves room for the floating dock.
        self.body = ft.Container(self.switcher, padding=ft.Padding.only(left=T.GUTTER, right=T.GUTTER, top=4,
                                                                        bottom=112))
        self.scroller = ft.Column([ft.Row([self.body], alignment=ft.MainAxisAlignment.CENTER)],
                                  scroll=ft.ScrollMode.AUTO, expand=True)
        self.dock_items: dict[str, ft.Container] = {}
        self.dock = ft.Container(
            ft.Row([self._dock_item(n, i, l) for n, i, l in [
                ("home", ft.Icons.GRID_VIEW_ROUNDED, "Home"), ("check", ft.Icons.DOCUMENT_SCANNER_OUTLINED, "Check"),
                ("learn", ft.Icons.SCHOOL_OUTLINED, "Learn"), ("history", ft.Icons.HISTORY, "History")]],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            padding=6, border_radius=999, bgcolor=T.SURFACE, border=ft.Border.all(1, T.LINE),
            shadow=ft.BoxShadow(blur_radius=30, spread_radius=0, color=ft.Colors.with_opacity(0.5, "#000000"),
                                offset=ft.Offset(0, 10)),
        )
        self.dock_holder = ft.Container(ft.Row([self.dock], alignment=ft.MainAxisAlignment.CENTER),
                                        left=0, right=0, bottom=18)
        self.shell = ft.Stack([ft.Container(self.scroller, left=0, right=0, top=0, bottom=0), self.dock_holder],
                              expand=True)
        self.appbar = ft.AppBar(
            leading=ft.Container(
                ft.Container(ft.Icon(ft.Icons.SHIELD, color=T.ON_ACCENT, size=16), width=30, height=30,
                             border_radius=9, bgcolor=T.SAFE, alignment=ft.Alignment.CENTER),
                padding=ft.Padding.only(left=T.GUTTER), alignment=ft.Alignment.CENTER_LEFT),
            leading_width=56, title_spacing=6,
            title=T.text("FraudLens", 17, ft.FontWeight.W_700),
            bgcolor=T.BG, elevation=0, elevation_on_scroll=0, toolbar_height=58,
            actions=[self.status,
                     ft.Container(ft.IconButton(ft.Icons.TUNE, icon_color=T.TEXT, icon_size=20,
                                                tooltip="Server settings", on_click=self.open_settings,
                                                style=ft.ButtonStyle(bgcolor=T.SURFACE,
                                                                     side=ft.BorderSide(1, T.LINE),
                                                                     shape=ft.RoundedRectangleBorder(radius=10))),
                                  padding=ft.Padding.only(left=8, right=T.GUTTER - 4))],
        )

    def _dock_item(self, name: str, icon_name, label: str) -> ft.Container:
        item = ft.Container(
            ft.Row([ft.Icon(icon_name, size=20, color=T.MUTED), T.text(label, 13, ft.FontWeight.W_600, T.SAFE_TEXT,
                                                                      visible=False)],
                   spacing=7, tight=True, alignment=ft.MainAxisAlignment.CENTER),
            padding=ft.Padding.symmetric(horizontal=16, vertical=11), border_radius=999, ink=True,
            animate=ft.Animation(220, ft.AnimationCurve.EASE_OUT), tooltip=label,
            on_click=lambda e, n=name: self.show_tab(n),
        )
        self.dock_items[name] = item
        return item

    def _paint_dock(self, active: str) -> None:
        for name, item in self.dock_items.items():
            on = name == active
            ic, lbl = item.content.controls
            ic.color = T.SAFE_TEXT if on else T.MUTED
            lbl.visible = on
            item.bgcolor = T.tint(T.SAFE, 0.14) if on else None

    # ---- setup ----------------------------------------------------------------
    async def start(self) -> None:
        p = self.page
        self.state.api.client_ip = getattr(p, "client_ip", None) or None
        p.title = APP_NAME
        p.fonts = T.FONTS
        p.theme = T.app_theme()
        p.dark_theme = T.app_theme()
        p.theme_mode = ft.ThemeMode.DARK
        p.bgcolor = T.BG
        p.padding = 0
        p.spacing = 0
        p.on_resize = self._fit_width
        # The landing screen shows first; content loads behind it so the app is ready on "Get started".
        p.add(self.welcome.root)
        self._fit_width()
        self.refresh_status()
        # Stop the landing animation when the browser tab goes away (web mode), so nothing sends to a closed socket.
        p.on_disconnect = p.on_close = lambda e: setattr(self.welcome, "running", False)
        p.run_task(self.welcome.animate, p)
        await self.load_content()

    def enter_app(self) -> None:
        p = self.page
        p.controls.clear()
        p.appbar = self.appbar
        p.add(self.shell)
        self.show_tab("home")

    def _fit_width(self, e=None) -> None:
        # Phone-sized column on big screens (browser demo); full width on phones.
        w = self.page.width or 400
        self.body.width = min(w, 520)
        self.dock.width = min(w - 32, 400)
        self.welcome.set_size(w, self.page.height or 800)
        self.page.update()

    async def load_content(self) -> None:
        api = self.state.api
        await api.health()
        # Independent requests run side by side, so a slow or offline server costs one wait, not five.
        (samples, _), (tactics, _), (quiz, _), (self.directory, _) = await asyncio.gather(
            api.samples(), api.tactics(), api.quiz(), api.directory())
        self.state.samples = samples
        self.check.set_samples(samples)
        self.home.set_samples(samples)
        self.learn.set_content(tactics, quiz)
        self.welcome.set_ready(api.online)
        self.refresh_status()
        self.page.update()

    # ---- navigation -----------------------------------------------------------
    def show_tab(self, name: str) -> None:
        if name == "history":
            self.history.refresh()
        if name == "home":
            self.home.refresh()
        changed = name != self.current_tab
        self.current_tab = name
        self._paint_dock(name)
        self.switcher.content = self.views[name].root
        self.page.update()
        if changed:
            self.page.run_task(self._scroll_top)

    async def _scroll_top(self) -> None:
        try:
            await self.scroller.scroll_to(offset=0, duration=0)
        except Exception:
            pass

    def open_analysis(self, analysis: dict) -> None:
        self.state.current = analysis
        self.check.show_analysis(analysis)
        self.show_tab("check")
        self.page.run_task(self.scroll_to_results)

    async def scroll_to_results(self) -> None:
        try:
            await asyncio.sleep(0.05)  # let the tab switch settle first
            # Bring the verdict to the top of the screen: skip the input area (measured) + padding + gap.
            await self.scroller.scroll_to(offset=self.check.top_height + 18 + 8 - 4, duration=450)
        except Exception as exc:  # scrolling is a nicety; never break the flow
            print("scroll_to failed:", exc)

    # Shortcuts from the Home tab. Each one opens an existing screen; none adds new behaviour.
    def go_to_check(self) -> None:
        self.show_tab("check")
        self.page.run_task(self._focus_input)

    async def _focus_input(self) -> None:
        try:
            await asyncio.sleep(0.25)
            await self.check.input.focus()
        except Exception:
            pass

    def go_to_examples(self) -> None:
        self.show_tab("check")
        self.page.run_task(self._scroll_to_key, "examples")

    def go_to_lessons(self) -> None:
        self.show_tab("learn")
        self.page.run_task(self._scroll_to_key, "lessons")

    async def _scroll_to_key(self, key: str) -> None:
        try:
            await asyncio.sleep(0.25)
            await self.scroller.scroll_to(scroll_key=key, duration=400)
        except Exception as exc:
            print("scroll_to failed:", exc)

    def run_example(self, sample: dict) -> None:
        self.show_tab("check")
        self.page.run_task(self.check.use_sample, sample)

    async def paste_and_check(self) -> None:
        self.show_tab("check")
        await self.check.on_paste(None)
        if (self.check.input.value or "").strip():
            await self.check.on_scan(None)

    # ---- shared actions (used by components) -----------------------------------
    def refresh_status(self) -> None:
        online = self.state.api.online
        label, color = (("Online", T.SAFE_TEXT) if online else ("Offline demo", T.WARN) if online is False
                        else ("Connecting", T.MUTED))
        self.status.content = T.status_chip(label, color)
        self.page.update()

    def show_shield_info(self) -> None:
        """Explains the Android companion that works in the background (no new behaviour here)."""
        steps = [
            (ft.Icons.NOTIFICATIONS_ACTIVE_OUTLINED, "Sleeps until something arrives",
             "Android hands Shield each new SMS, WhatsApp or email notification, and every ringing call."),
            (ft.Icons.FILTER_ALT_OUTLINED, "Quick filter on the phone",
             "Obviously harmless messages are skipped; suspicious ones go to the FraudLens server."),
            (ft.Icons.LAYERS_OUTLINED, "Same five-layer check",
             "Rules, AI language model, scam memory, link model and security databases."),
            (ft.Icons.WARNING_AMBER_ROUNDED, "Warns before you act",
             "A heads-up notification, a red banner over the current app, and a 'See why' Scam X-Ray."),
        ]
        rows = []
        for i, (ic, title, detail) in enumerate(steps):
            rows.append(ft.Row([
                ft.Column([T.squircle(ic, T.SAFE_TEXT, 36, T.tint(T.SAFE, 0.10)),
                           ft.Container(width=1, height=18, bgcolor=T.LINE, visible=i < len(steps) - 1)],
                          spacing=4, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                ft.Column([T.text(title, 14.5, ft.FontWeight.W_600), T.caption(detail, size=12.5)],
                          spacing=2, expand=True),
            ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.START))
        sheet = ft.BottomSheet(
            ft.Container(ft.Column([
                ft.Row([ft.Container(width=36, height=4, border_radius=2, bgcolor=T.LINE)],
                       alignment=ft.MainAxisAlignment.CENTER),
                ft.Row([T.status_chip("Runs in background", T.SAFE)]),
                T.text("FraudLens Shield", 20, ft.FontWeight.W_700),
                T.caption("Built into the FraudLens Android app. It works while you use your phone normally, "
                          "even when FraudLens is closed.", size=13.5),
                ft.Column(rows, spacing=4),
                T.inner(ft.Row([ft.Icon(ft.Icons.INFO_OUTLINE, size=16, color=T.MUTED),
                                T.caption(self.shield_setup_hint(), size=12.5, expand=True)], spacing=8)),
            ], spacing=14, tight=True),
                padding=ft.Padding.only(left=22, right=22, top=12, bottom=28), width=520),
            bgcolor=T.SURFACE, show_drag_handle=False, scrollable=True, draggable=True,
            shape=ft.RoundedRectangleBorder(radius=ft.BorderRadius.only(top_left=T.R_HERO, top_right=T.R_HERO)),
        )
        self.page.show_dialog(sheet)

    def in_android_app(self) -> bool:
        """True when this UI is shown inside the FraudLens Android app (its WebView adds this marker)."""
        return "FraudLensApp" in (getattr(self.page, "client_user_agent", None) or "")

    def shield_setup_hint(self) -> str:
        if self.in_android_app():
            return "Turn it on once in the Shield tab at the bottom of this app."
        return "Install the FraudLens Android app and turn it on once in its Shield tab (guide: shield/README.md)."

    def toast(self, message: str) -> None:
        self.page.show_dialog(ft.SnackBar(T.text(message, 14, ft.FontWeight.W_500, T.TEXT), bgcolor=T.SURFACE_2,
                                         behavior=ft.SnackBarBehavior.FLOATING,
                                         shape=ft.RoundedRectangleBorder(radius=14)))

    def close_dialog(self, dialog: ft.DialogControl) -> None:
        dialog.open = False
        dialog.update()

    # Sync wrappers so they can be used from lambdas; the work runs as a task.
    def copy(self, text: str) -> None:
        self.page.run_task(self._copy, text)

    def open_url(self, url: str) -> None:
        self.page.run_task(self._open_url, url)

    def send_feedback(self, analysis: dict, answer: str) -> None:
        self.page.run_task(self._send_feedback, analysis, answer)

    def report(self, analysis: dict, label: str) -> None:
        self.page.run_task(self._report, analysis, label)

    async def _report(self, analysis: dict, label: str) -> None:
        from services.api_client import OfflineError
        try:
            res = await self.state.api.report(
                analysis.get("_text", ""), label, self.state.reporter_id, analysis.get("_sender"),
                analysis.get("category") if label == "scam" and analysis.get("category") not in ("none", None)
                else None)
            self.toast(res.get("message", "Thanks for your report."))
        except OfflineError as exc:
            self.toast(str(exc))

    async def _copy(self, text: str) -> None:
        try:
            await ft.Clipboard().set(text)
            self.toast("Copied to clipboard.")
            self.page.update()
        except Exception:
            self.toast("Couldn't access the clipboard.")

    async def _open_url(self, url: str) -> None:
        await ft.UrlLauncher().launch_url(url)

    def show_official_contact(self, payload: dict) -> None:
        orgs = self.directory.get("organisations", [])
        org_id = payload.get("org_id")
        chosen = [o for o in orgs if o["id"] == org_id] if org_id else [o for o in orgs if o["type"] == "bank"]
        rows = []
        for o in chosen:
            phone = o.get("phone")
            rows.append(ft.Container(
                content=ft.Row([
                    T.squircle(ft.Icons.VERIFIED, T.PRIMARY, 38),
                    ft.Column([
                        T.body(o["name"], size=15, weight=ft.FontWeight.W_700),
                        T.caption(f"Phone: {phone}" if phone else "Phone: use the number on the back of your card",
                                  size=13),
                        ft.TextButton(o["website"], icon=ft.Icons.OPEN_IN_NEW, style=T.link_style(),
                                      on_click=lambda e, u=o["website"]: self.open_url(u)),
                    ], spacing=0, expand=True),
                ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.START),
                padding=14, border_radius=T.R_INNER, border=ft.Border.all(1, T.BORDER), bgcolor=T.SUBTLE,
            ))
        dlg = T.dialog(
            "Verified contacts", icon_name=ft.Icons.VERIFIED_USER,
            content=ft.Column([
                T.caption("These come from FraudLens's verified directory, never from the message you received.",
                          size=13, text_align=ft.TextAlign.CENTER),
                *rows,
            # Scroll only when the list is long; otherwise the dialog hugs its content.
            ], tight=True, spacing=10, scroll=ft.ScrollMode.AUTO if len(rows) > 2 else None, width=400),
            actions=[ft.TextButton("Close", on_click=lambda e: self.close_dialog(dlg))],
        )
        self.page.show_dialog(dlg)

    def share_with_guardian(self) -> None:
        a = self.state.current
        if a:
            text = (f"Hi {GUARDIAN['name'].split()[0]}, I got a message FraudLens rated {a['risk_score']}/100 "
                    f"({a['category_label']}). Can you look at it with me before I reply or pay?")
        else:
            text = "Can you help me check a message before I reply or pay?"
        dlg = T.dialog(
            "Ask someone you trust", icon_name=ft.Icons.GROUPS,
            content=ft.Column([
                ft.Row([T.icon_badge(ft.Icons.PERSON, T.PRIMARY, 38),
                        ft.Column([T.caption("Your trusted contact", size=12),
                                   T.body(GUARDIAN["name"], size=14.5, weight=ft.FontWeight.W_700)],
                                  spacing=0)], spacing=10),
                T.inner(T.text(text, 14.5, italic=True)),
                T.caption("A second opinion stops most scams. Scammers ask for secrecy for this reason."),
            ], tight=True, spacing=12, width=400),
            actions=[ft.TextButton("Close", on_click=lambda e: self.close_dialog(dlg)),
                     ft.FilledButton("Copy message", icon=ft.Icons.COPY, style=T.primary_style(),
                                     on_click=lambda e: self.copy(text))],
        )
        self.page.show_dialog(dlg)

    async def _send_feedback(self, analysis: dict, answer: str) -> None:
        said_scam = analysis["risk_level"] != "low"
        verdict = ("scam" if said_scam else "legit") if answer == "correct" else ("legit" if said_scam else "scam")
        ok = await self.state.api.feedback(analysis["analysis_id"], verdict)
        self.toast("Thanks! Your feedback helps FraudLens learn." if ok else "Saved for later (offline).")

    def open_settings(self, e) -> None:
        field = ft.TextField(label="Server address", value=self.state.api.base_url, autofocus=True,
                             prefix_icon=ft.Icons.DNS_OUTLINED, **T.field_style())
        result = T.text("", 13)

        async def test(ev):
            self.state.api.set_base_url(field.value or DEFAULT_API_URL)
            info = await self.state.api.health()
            if info:
                ml = info.get("ml") or {}
                mem = ml.get("memory") or {}
                result.value = (f"Connected. Embedder: {ml.get('embedder', 'off')} · classifier: "
                                f"{'yes' if ml.get('classifier') else 'not trained'} · link model: "
                                f"{'yes' if ml.get('url_model') else 'no'} · memory: {mem.get('size', 0)} messages")
            else:
                result.value = "Can't reach the server. Demo messages will use offline results."
            result.color = T.RISK["low"]["color"] if info else T.RISK["high"]["color"]
            self.refresh_status()
            if info:
                await self.load_content()

        hints = [("Laptop", "http://127.0.0.1:8000"), ("Android emulator", "http://10.0.2.2:8000"),
                 ("Phone on Wi-Fi", "http://<laptop-IP>:8000")]
        dlg = T.dialog(
            "Server settings", icon_name=ft.Icons.DNS_OUTLINED,
            content=ft.Column([
                field,
                T.inner(ft.Column([ft.Row([T.caption(k, size=12, expand=True),
                                           T.text(v, 12, ft.FontWeight.W_500)])
                                   for k, v in hints], spacing=6), padding=12),
                result,
            ], tight=True, spacing=12, width=400),
            actions=[ft.TextButton("Close", on_click=lambda ev: self.close_dialog(dlg)),
                     ft.FilledButton("Save & test", on_click=test, style=T.primary_style())],
        )
        self.page.show_dialog(dlg)


async def main(page: ft.Page) -> None:
    await FraudLensApp(page).start()


if __name__ == "__main__":
    ft.run(main)
