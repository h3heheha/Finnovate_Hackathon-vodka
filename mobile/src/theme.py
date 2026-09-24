"""Design tokens and style helpers: "Clean Dark Slate".

The full spec (intent, tokens, components, anti-patterns) is in mobile/DESIGN_SPEC.md.
Every colour, size and font in the app comes from here.
"""
import flet as ft

# ---- fonts ----------------------------------------------------------------------------------------
# Flet loads one file per family, so each weight is its own family. `fam()` / `mono()` pick the file.
FONTS = {
    "Inter": "fonts/Inter-Regular.ttf",
    "Inter Medium": "fonts/Inter-Medium.ttf",
    "Inter SemiBold": "fonts/Inter-SemiBold.ttf",
    "Inter Bold": "fonts/Inter-Bold.ttf",
    "Inter ExtraBold": "fonts/Inter-ExtraBold.ttf",
    "Mono": "fonts/JetBrainsMono-Medium.ttf",
    "Mono Bold": "fonts/JetBrainsMono-Bold.ttf",
}
_W = ft.FontWeight
_FAMILY = {_W.W_500: "Inter Medium", _W.W_600: "Inter SemiBold", _W.W_700: "Inter Bold", _W.BOLD: "Inter Bold",
           _W.W_800: "Inter ExtraBold", _W.W_900: "Inter ExtraBold"}


def fam(weight=None) -> str:
    return _FAMILY.get(weight, "Inter")


# ---- colour ---------------------------------------------------------------------------------------
BG = "#121417"
SURFACE = "#1C1E23"
SURFACE_2 = "#24272D"
LINE = "#2C3037"
TEXT = "#F3F4F6"
MUTED = "#8E95A2"
FAINT = "#5E6470"           # icons / decoration only, never text
SAFE = "#10B981"
SAFE_TEXT = "#34D399"
FRAUD = "#EF4444"
FRAUD_TEXT = "#F87171"
WARN = "#F59E0B"
ON_ACCENT = "#0B0D10"       # text on emerald buttons (7.7:1)

# Names the screens use
PRIMARY = SAFE
INK = BG
SUBTLE = SURFACE_2
BORDER = LINE
HINT = MUTED
ON_DARK, ON_DARK_MUTED = TEXT, MUTED
PRIMARY_SOFT = ft.Colors.with_opacity(0.14, SAFE)
NAVY = NAVY_2 = INK
TEAL = TEAL_LIGHT = SAFE
PRIMARY_DARK = SAFE


def tint(color: str, opacity: float = 0.12) -> str:
    return ft.Colors.with_opacity(opacity, color)


def lighten(color: str, amount: float = 0.35) -> str:
    """Mix a hex colour toward white so data colours from the API stay readable on dark slate."""
    try:
        h = color.lstrip("#")[-6:]
        r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    except (ValueError, AttributeError):
        return color
    r, g, b = (int(c + (255 - c) * amount) for c in (r, g, b))
    return f"#{r:02X}{g:02X}{b:02X}"


RISK = {
    "low": {"color": SAFE_TEXT, "fill": SAFE, "bg": tint(SAFE, 0.10), "icon": ft.Icons.VERIFIED_USER,
            "label": "Low risk"},
    "medium": {"color": WARN, "fill": WARN, "bg": tint(WARN, 0.10), "icon": ft.Icons.GPP_MAYBE,
               "label": "Medium risk"},
    "high": {"color": FRAUD_TEXT, "fill": FRAUD, "bg": tint(FRAUD, 0.10), "icon": ft.Icons.GPP_BAD,
             "label": "High risk"},
}

ADVICE_ICONS = {
    "no_codes": ft.Icons.PASSWORD,
    "no_link": ft.Icons.LINK_OFF,
    "verify_person": ft.Icons.PHONE_CALLBACK,
    "pause_payment": ft.Icons.PAUSE_CIRCLE,
    "check_fsc": ft.Icons.POLICY,
    "tell_someone": ft.Icons.GROUPS,
    "report": ft.Icons.REPORT,
    "stay_alert": ft.Icons.VISIBILITY,
}

# ---- spacing / shape / motion ---------------------------------------------------------------------
GAP = 12
PAD = 16
GUTTER = 20
R_HERO, R_CARD, R_INNER = 18, 14, 10
ANIM = ft.Animation(220, ft.AnimationCurve.EASE_OUT)


def icon(name: str | None, fallback=ft.Icons.WARNING_AMBER):
    """Map an icon name sent by the API (e.g. 'TIMER') to a Flet icon."""
    return getattr(ft.Icons, name, fallback) if name else fallback


# ---- text -----------------------------------------------------------------------------------------
def text(value: str, size: float = 14.5, weight=None, color: str = TEXT, **kw) -> ft.Text:
    """Every UI label goes through here, so the right Inter weight file is used."""
    return ft.Text(value, size=size, weight=weight, color=color, font_family=fam(weight), **kw)


def mono(value: str, size: float = 12, color: str = MUTED, bold: bool = False, spacing: float = 0.3,
         **kw) -> ft.Text:
    """JetBrains Mono for scores, counts, statuses and labels."""
    return ft.Text(value, size=size, color=color, font_family="Mono Bold" if bold else "Mono",
                   style=ft.TextStyle(letter_spacing=spacing), **kw)


def style(size: float = 14.5, weight=None, color: str | None = None, **kw) -> ft.TextStyle:
    return ft.TextStyle(size=size, weight=weight, color=color, font_family=fam(weight), **kw)


def display(value: str, color: str = TEXT, size: float = 28) -> ft.Text:
    return text(value, size, _W.W_700, color, style=ft.TextStyle(height=1.12, letter_spacing=-0.6))


def h1(value: str, color: str = TEXT) -> ft.Text:
    return text(value, 22, _W.W_700, color, style=ft.TextStyle(letter_spacing=-0.4))


def h2(value: str, color: str = TEXT) -> ft.Text:
    return text(value, 16, _W.W_600, color)


def body(value: str, color: str = TEXT, size: float = 14.5, **kw) -> ft.Text:
    return text(value, size, kw.pop("weight", None), color, **kw)


def caption(value: str, color: str = MUTED, size: float = 13, **kw) -> ft.Text:
    return text(value, size, kw.pop("weight", None), color, **kw)


def overline(value: str, color: str = MUTED) -> ft.Text:
    return mono(value.upper(), 11, color, spacing=0.8)


# ---- containers -----------------------------------------------------------------------------------
def card(content: ft.Control, padding=PAD, bgcolor: str = SURFACE, border_color: str | None = None,
         **kwargs) -> ft.Container:
    kwargs.pop("shadow", None)  # borders, not shadows
    return ft.Container(content=content, padding=padding, bgcolor=bgcolor, border_radius=R_CARD,
                        border=ft.Border.all(1, border_color or LINE), **kwargs)


def inner(content: ft.Control, bgcolor: str = SURFACE_2, padding: int = 12, **kwargs) -> ft.Container:
    return ft.Container(content=content, padding=padding, bgcolor=bgcolor, border_radius=R_INNER, **kwargs)


def squircle(icon_name, color: str = TEXT, size: int = 40, bg: str | None = None) -> ft.Container:
    """Rounded-square icon holder."""
    return ft.Container(ft.Icon(icon_name, color=color, size=size * 0.5), width=size, height=size,
                        border_radius=size * 0.28, bgcolor=bg or SURFACE_2, alignment=ft.Alignment.CENTER,
                        border=ft.Border.all(1, LINE))


def icon_badge(icon_name, color: str, size: int = 36) -> ft.Container:
    return squircle(icon_name, color, size, tint(color, 0.12))


def section_title(value: str, subtitle: str | None = None, trailing: ft.Control | None = None,
                  icon_name=None, color: str = TEXT) -> ft.Control:
    col = ft.Column([h2(value)] + ([caption(subtitle, size=12.5)] if subtitle else []), spacing=2, expand=True)
    row = [col]
    if icon_name:
        row.insert(0, squircle(icon_name, color, 34))
    if trailing:
        row.append(trailing)
    if len(row) == 1:
        return col
    return ft.Row(row, spacing=12, vertical_alignment=ft.CrossAxisAlignment.START)


def section_header(value: str, action: str | None = None, on_click=None) -> ft.Control:
    row = [overline(value), ft.Container(expand=True)]
    if action:
        row.append(ft.TextButton(action, on_click=on_click, style=link_style()))
    return ft.Container(ft.Row(row, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                        padding=ft.Padding.only(left=2, top=8))


def pill(value: str, color: str, bg: str | None = None, icon_name=None, size: float = 11) -> ft.Container:
    row = [mono(value, size, color, bold=True, spacing=0.4)]
    if icon_name:
        row.insert(0, ft.Icon(icon_name, size=size + 3, color=color))
    return ft.Container(content=ft.Row(row, spacing=5, tight=True),
                        padding=ft.Padding.symmetric(horizontal=9, vertical=4),
                        bgcolor=bg or tint(color, 0.12), border_radius=6)


def dot(color: str, size: int = 7) -> ft.Container:
    return ft.Container(width=size, height=size, border_radius=size, bgcolor=color)


def status_chip(label: str, color: str) -> ft.Container:
    return ft.Container(ft.Row([dot(color), mono(label.upper(), 10.5, color, bold=True, spacing=0.6)],
                               spacing=6, tight=True),
                        padding=ft.Padding.symmetric(horizontal=10, vertical=6), border_radius=999,
                        bgcolor=tint(color, 0.10), border=ft.Border.all(1, tint(color, 0.25)))


def divider() -> ft.Divider:
    return ft.Divider(height=1, thickness=1, color=LINE)


def gradient(colors: list[str] | None = None) -> ft.LinearGradient:
    return ft.LinearGradient(colors=colors or [SURFACE, BG], begin=ft.Alignment.TOP_LEFT,
                             end=ft.Alignment.BOTTOM_RIGHT)


def page_header(title: str, subtitle: str, label: str | None = None) -> ft.Control:
    """Title block at the top of every tab."""
    parts = ([overline(label)] if label else []) + [h1(title), caption(subtitle, size=13.5)]
    return ft.Column(parts, spacing=6)


def hero(title: str, value: str, icon_name, colors=None, extra: list[ft.Control] | None = None) -> ft.Control:
    return card(ft.Row([squircle(icon_name, SAFE, 44, tint(SAFE, 0.12)),
                        ft.Column([h2(title), caption(value)], spacing=3, expand=True)], spacing=14,
                       vertical_alignment=ft.CrossAxisAlignment.START), padding=18)


def skeleton(height: float = 12, width: float | None = None, radius: float = 6, **kw) -> ft.Container:
    return ft.Container(height=height, width=width, border_radius=radius, bgcolor=SURFACE_2, **kw)


# ---- buttons --------------------------------------------------------------------------------------
def _btn_text(size: float = 14.5) -> ft.TextStyle:
    return ft.TextStyle(size=size, weight=_W.W_600, font_family=fam(_W.W_600))


def primary_style(color: str = SAFE) -> ft.ButtonStyle:
    """Emerald button, dark text. Pass FRAUD for the red outline style."""
    if color in (FRAUD, FRAUD_TEXT, RISK["high"]["color"]):
        return ft.ButtonStyle(bgcolor=tint(FRAUD, 0.14), color=FRAUD_TEXT, side=ft.BorderSide(1, tint(FRAUD, 0.5)),
                              shape=ft.RoundedRectangleBorder(radius=R_INNER), elevation=0,
                              padding=ft.Padding.symmetric(horizontal=18, vertical=15), text_style=_btn_text())
    return ft.ButtonStyle(bgcolor=SAFE, color=ON_ACCENT, shape=ft.RoundedRectangleBorder(radius=R_INNER),
                          padding=ft.Padding.symmetric(horizontal=18, vertical=15), text_style=_btn_text(),
                          elevation=0, overlay_color=tint(ON_ACCENT, 0.08))


def secondary_style(color: str = TEXT) -> ft.ButtonStyle:
    return ft.ButtonStyle(color=color, side=ft.BorderSide(1, LINE), shape=ft.RoundedRectangleBorder(radius=R_INNER),
                          padding=ft.Padding.symmetric(horizontal=16, vertical=14), bgcolor=SURFACE_2,
                          text_style=_btn_text(14), elevation=0)


light_style = primary_style


def link_style(color: str = SAFE_TEXT) -> ft.ButtonStyle:
    return ft.ButtonStyle(color=color, padding=ft.Padding.symmetric(horizontal=4, vertical=4),
                          text_style=_btn_text(13))


def tool_style() -> ft.ButtonStyle:
    return ft.ButtonStyle(side=ft.BorderSide(1, LINE), shape=ft.RoundedRectangleBorder(radius=R_INNER),
                          bgcolor=SURFACE_2, padding=ft.Padding.all(13))


def field_style() -> dict:
    return dict(filled=True, fill_color=SURFACE_2, border_radius=R_INNER, border_color=LINE,
                focused_border_color=SAFE, text_size=14.5, text_style=style(14.5), color=TEXT,
                label_style=style(13.5, color=MUTED), cursor_color=SAFE)


def dialog(title: str, content: ft.Control, actions: list[ft.Control], icon_name=None,
           icon_color: str = SAFE) -> ft.AlertDialog:
    return ft.AlertDialog(
        bgcolor=SURFACE, shape=ft.RoundedRectangleBorder(radius=R_HERO),
        icon=ft.Row([squircle(icon_name, icon_color, 48, tint(icon_color, 0.12))],
                    alignment=ft.MainAxisAlignment.CENTER) if icon_name else None,
        title=text(title, 18, _W.W_700, text_align=ft.TextAlign.CENTER if icon_name else None),
        content=content, actions=actions, actions_alignment=ft.MainAxisAlignment.END,
    )


def app_theme() -> ft.Theme:
    return ft.Theme(
        color_scheme_seed=SAFE, use_material3=True, font_family="Inter",
        color_scheme=ft.ColorScheme(primary=SAFE, on_primary=ON_ACCENT, surface=SURFACE, on_surface=TEXT,
                                    on_surface_variant=MUTED, outline=LINE, outline_variant=LINE,
                                    surface_tint=ft.Colors.TRANSPARENT),
        divider_theme=ft.DividerTheme(color=LINE),
    )
