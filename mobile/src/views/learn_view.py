"""Learn tab: spot-the-scam quiz plus 30-second lessons for every tactic."""
import flet as ft

import theme as T

W6, W7, W8 = ft.FontWeight.W_600, ft.FontWeight.W_700, ft.FontWeight.W_800


class LearnView:
    def __init__(self, app):
        self.app = app
        self.quiz: list[dict] = []
        self.q_index = 0
        self.score = 0
        self.answered = False
        self.quiz_box = ft.Column(spacing=14, horizontal_alignment=ft.CrossAxisAlignment.STRETCH)
        self.lessons = ft.Column(spacing=0)
        self._show_skeletons()
        self.root = ft.Column(
            [
                T.page_header("Train your scam radar",
                              "Every scam uses the same few tricks. Learn to spot them in 30 seconds each.",
                              "Learn"),
                T.card(self.quiz_box, padding=20),
                ft.Column([
                    T.section_header("The tricks scammers use"),
                    T.card(ft.Column([T.caption("Tap a trick to open its lesson.", size=13), self.lessons], spacing=4),
                           padding=ft.Padding.only(left=18, right=18, top=14, bottom=8)),
                ], spacing=T.GAP, key=ft.ScrollKey("lessons")),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH, spacing=T.GAP,
        )

    def _show_skeletons(self) -> None:
        self.quiz_box.controls = [T.skeleton(18, 140), T.skeleton(6, None, 3), T.skeleton(70, None, 16),
                                  T.skeleton(48, None, 14), T.skeleton(48, None, 14)]
        self.lessons.controls = [
            ft.Container(ft.Row([T.skeleton(40, 40, 13), ft.Column([T.skeleton(12, 140), T.skeleton(10, 200)],
                                                                   spacing=6)], spacing=12),
                         padding=ft.Padding.symmetric(vertical=10))
            for _ in range(3)
        ]

    def set_content(self, tactics: list[dict], quiz: list[dict]) -> None:
        self.quiz = quiz
        self.q_index, self.score = 0, 0
        self._render_question()
        tiles = []
        for i, t in enumerate(tactics):
            if i:
                tiles.append(T.divider())
            tiles.append(self._lesson_tile(t))
        self.lessons.controls = tiles

    # ---- lessons -------------------------------------------------------------
    def _lesson_tile(self, t: dict) -> ft.Control:
        examples = ", ".join(f"“{x}”" for x in t.get("examples", []))
        return ft.ExpansionTile(
            leading=T.squircle(T.icon(t["icon"]), T.lighten(t["color"]), 40),
            title=T.text(t["label"], 15, W7),
            subtitle=T.caption(t["short"], size=12.5),
            tile_padding=ft.Padding.symmetric(horizontal=0, vertical=4),
            controls_padding=ft.Padding.only(left=54, right=4, bottom=14),
            expanded_cross_axis_alignment=ft.CrossAxisAlignment.START,
            shape=ft.RoundedRectangleBorder(radius=0), collapsed_shape=ft.RoundedRectangleBorder(radius=0),
            icon_color=T.SAFE_TEXT, collapsed_icon_color=T.MUTED,
            controls=[ft.Column([
                T.body(t["lesson"], size=14),
                T.inner(ft.Row([ft.Icon(ft.Icons.CHECK_CIRCLE, color=T.RISK["low"]["color"], size=18),
                                T.text(t["safe_action"], 13.5, W6, expand=True)],
                               spacing=8, vertical_alignment=ft.CrossAxisAlignment.START),
                        bgcolor=T.RISK["low"]["bg"], padding=12),
                T.text(f"Sounds like: {examples}", 12.5, color=T.MUTED, italic=True) if examples
                else ft.Container(),
            ], spacing=10)],
        )

    # ---- quiz ----------------------------------------------------------------
    def _render_question(self) -> None:
        if not self.quiz:
            self.quiz_box.controls = [ft.Row([T.squircle(ft.Icons.CLOUD_OFF, T.MUTED, 40),
                                              T.body("Quiz unavailable offline.", color=T.MUTED, expand=True)],
                                             spacing=12)]
            return
        if self.q_index >= len(self.quiz):
            self.quiz_box.controls = [
                ft.Row([T.squircle(ft.Icons.EMOJI_EVENTS, T.SAFE_TEXT, 52, T.tint(T.SAFE, 0.12)),
                        ft.Column([T.h2("Quiz complete!"),
                                   T.text(f"You scored {self.score} / {len(self.quiz)}.", 15, W7, T.SAFE_TEXT)],
                                  spacing=2, expand=True)], spacing=14),
                T.caption("Scammers change their words, not their tricks. Keep an eye out for urgency, "
                          "secrecy and requests for codes.", size=13.5),
                ft.Row([ft.OutlinedButton("Play again", icon=ft.Icons.REPLAY, on_click=self._restart,
                                          style=T.secondary_style())]),
            ]
            return
        q = self.quiz[self.q_index]
        self.answered = False
        self.feedback = ft.Container(visible=False, animate_opacity=T.ANIM)
        self.option_buttons = [
            ft.OutlinedButton(
                content=ft.Row([
                    ft.Container(T.mono("ABCDEFG"[i], 12, T.TEXT, bold=True, spacing=0), width=28, height=28,
                                 border_radius=7, bgcolor=T.SURFACE_2, border=ft.Border.all(1, T.LINE),
                                 alignment=ft.Alignment.CENTER),
                    T.text(opt, 14.5, ft.FontWeight.W_500, expand=True),
                ], spacing=12),
                on_click=lambda e, i=i: self._answer(i), width=10_000, style=self._option_style())
            for i, opt in enumerate(q["options"])
        ]
        self.quiz_box.controls = [
            T.section_title("Spot the scam", "Read the message, then pick the biggest red flag.",
                            trailing=T.pill(f"{self.q_index + 1:02d}/{len(self.quiz):02d}", T.SAFE_TEXT)),
            ft.ProgressBar(value=(self.q_index + 1) / len(self.quiz), color=T.SAFE, bgcolor=T.SURFACE_2,
                           bar_height=4, border_radius=2),
            ft.Container(T.body(q["message"], size=14.5), padding=16, bgcolor=T.SUBTLE,
                         border=ft.Border.all(1, T.BORDER),
                         border_radius=ft.BorderRadius.only(top_left=2, top_right=12, bottom_left=12,
                                                            bottom_right=12)),
            T.text(q["question"], 15.5, W7),
            ft.Column(self.option_buttons, spacing=10),
            self.feedback,
        ]

    def _answer(self, i: int) -> None:
        if self.answered:
            return
        self.answered = True
        q = self.quiz[self.q_index]
        correct = i == q["answer"]
        self.score += int(correct)
        for idx, btn in enumerate(self.option_buttons):
            if idx == q["answer"]:
                btn.style = self._option_style(T.RISK["low"])
            elif idx == i:
                btn.style = self._option_style(T.RISK["high"])
        level = T.RISK["low" if correct else "high"]
        self.feedback.content = T.inner(
            ft.Column([
                ft.Row([ft.Icon(ft.Icons.CHECK_CIRCLE if correct else ft.Icons.CANCEL, color=level["color"], size=22),
                        T.text("Correct!" if correct else "Not quite.", 16, W8, level["color"])], spacing=8),
                T.body(q["explanation"], size=14),
                ft.Row([ft.FilledButton("Next", icon=ft.Icons.ARROW_FORWARD, on_click=self._next,
                                        style=T.primary_style())], alignment=ft.MainAxisAlignment.END),
            ], spacing=10),
            bgcolor=level["bg"], padding=16,
        )
        self.feedback.visible = True

    @staticmethod
    def _option_style(level: dict | None = None) -> ft.ButtonStyle:
        return ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=T.R_INNER), color=T.TEXT,
            padding=ft.Padding.symmetric(horizontal=12, vertical=12),
            bgcolor=level["bg"] if level else T.SURFACE_2,
            side=ft.BorderSide(1.5, level["fill"]) if level else ft.BorderSide(1, T.LINE),
        )

    def _next(self, e) -> None:
        self.q_index += 1
        self._render_question()

    def _restart(self, e) -> None:
        self.q_index, self.score = 0, 0
        self._render_question()
