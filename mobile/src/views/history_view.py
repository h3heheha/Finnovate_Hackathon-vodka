"""History tab: personal impact stats and past scans."""
from datetime import datetime

import flet as ft

import theme as T

W6, W7, W8 = ft.FontWeight.W_600, ft.FontWeight.W_700, ft.FontWeight.W_800


def _time(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).astimezone().strftime("%d %b, %H:%M")
    except ValueError:
        return ""


class HistoryView:
    def __init__(self, app):
        self.app = app
        self.root = ft.Column(spacing=T.GAP, horizontal_alignment=ft.CrossAxisAlignment.STRETCH)

    def _stat(self, value: str, label: str, color: str, icon) -> ft.Control:
        return T.card(
            ft.Column([
                ft.Row([ft.Icon(icon, color=color, size=16), ft.Container(expand=True), T.dot(color, 6)]),
                T.mono(value.zfill(2), 26, T.TEXT, bold=True, spacing=0),
                T.mono(label.upper(), 9.5, T.MUTED, spacing=1),
            ], spacing=6),
            padding=14, expand=True,
        )

    def refresh(self) -> None:
        st = self.app.state
        safe = sum(1 for h in st.history if h.get("risk_level") == "low")
        stats = ft.Row([
            self._stat(str(len(st.history)), "Checked", T.MUTED, ft.Icons.DOCUMENT_SCANNER_OUTLINED),
            self._stat(str(st.scams_caught), "Scams found", T.FRAUD_TEXT, ft.Icons.GPP_BAD_OUTLINED),
            self._stat(str(safe), "Looked safe", T.SAFE_TEXT, ft.Icons.VERIFIED_USER_OUTLINED),
        ], spacing=10)

        rows: list[ft.Control] = []
        for a in st.history:
            level = T.RISK[a["risk_level"]]
            if rows:
                rows.append(T.divider())
            rows.append(ft.Container(
                content=ft.Row([
                    ft.Stack([
                        ft.ProgressRing(value=max(a["risk_score"], 2) / 100, width=46, height=46, stroke_width=3,
                                        color=level["fill"], bgcolor=T.SURFACE_2),
                        ft.Container(T.mono(str(a["risk_score"]), 13, level["color"], bold=True, spacing=0), width=46, height=46,
                                     alignment=ft.Alignment.CENTER),
                    ], width=46, height=46),
                    ft.Column([
                        ft.Row([T.text(a["category_label"], 14.5, W7, expand=True, max_lines=1,
                                       overflow=ft.TextOverflow.ELLIPSIS),
                                T.mono(_time(a.get("created_at")).upper(), 10, T.MUTED, spacing=0.5)]),
                        T.caption(a.get("_text", "")[:80] + ("…" if len(a.get("_text", "")) > 80 else ""),
                                  size=12.5, max_lines=2),
                        T.pill(level["label"], level["color"], level["bg"], size=10.5),
                    ], spacing=4, expand=True),
                    ft.Icon(ft.Icons.CHEVRON_RIGHT, color=T.FAINT),
                ], spacing=14),
                padding=ft.Padding.symmetric(horizontal=2, vertical=12), border_radius=T.R_INNER,
                on_click=lambda e, a=a: self.app.open_analysis(a), ink=True,
            ))
        if rows:
            recent = ft.Column([
                T.section_header("Recent checks"),
                T.card(ft.Column([T.caption("Tap a check to open its full result.", size=13),
                                  ft.Column(rows, spacing=0)], spacing=4),
                       padding=ft.Padding.only(left=16, right=16, top=14, bottom=6)),
            ], spacing=T.GAP)
        else:
            recent = T.card(ft.Column([
                T.squircle(ft.Icons.HISTORY, T.MUTED, 52),
                T.text("No checks yet", 16, W7),
                T.caption("Messages you check appear here. Your history stays on this device.", size=13.5,
                          text_align=ft.TextAlign.CENTER),
                ft.FilledButton("Check a message", icon=ft.Icons.DOCUMENT_SCANNER, style=T.primary_style(),
                                on_click=lambda e: self.app.go_to_check()),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10), padding=28)

        self.root.controls = [T.page_header("Your protection", "What FraudLens has done for you so far.",
                                            "History"),
                              stats, recent]
