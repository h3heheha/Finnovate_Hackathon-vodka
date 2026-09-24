"""The analysis result, built from the /analyze response.

Order follows what a worried person needs first:
  1. verdict            - is it a scam, how sure are we (score), one-line summary
  2. Scam X-Ray         - the message with every trick highlighted
  3. What to do now     - concrete next steps with one-tap actions
  4. Warning signs      - each trick explained (tap to see the evidence)
  5. Threat intelligence- what security databases say about links and numbers
  6. How FraudLens decided - points per verification layer, closest known scams
  7. Reply & report     - safe reply to copy, report scam / genuine
`app` provides the actions (open a link, ask a guardian, copy text...) so this module stays pure UI.
"""
import flet as ft

import theme as T

W5, W6, W7, W8 = ft.FontWeight.W_500, ft.FontWeight.W_600, ft.FontWeight.W_700, ft.FontWeight.W_800

# One muted hue per verification layer (data colours, readable on dark slate).
LAYER_COLORS = {"rules": "#60A5FA", "classifier": "#A78BFA", "memory": "#38BDF8", "url": "#FB923C",
                "community": "#F472B6", "intel": T.FRAUD_TEXT}
LAYER_ICONS = {"rules": ft.Icons.RULE, "classifier": ft.Icons.PSYCHOLOGY, "memory": ft.Icons.MANAGE_SEARCH,
               "url": ft.Icons.LINK, "community": ft.Icons.GROUPS, "intel": ft.Icons.GPP_BAD}
SEVERITY = {
    "danger": (T.RISK["high"]["color"], ft.Icons.GPP_BAD),
    "warning": (T.RISK["medium"]["color"], ft.Icons.GPP_MAYBE),
    "info": (T.MUTED, ft.Icons.INFO_OUTLINE),
}
SOURCE_NAMES = {"URLhaus": "abuse.ch URLhaus", "RDAP": "Domain registry (RDAP)"}


def _tile(title: str, subtitle, leading: ft.Control, trailing: ft.Control | None, controls: list[ft.Control],
          left: int = 54) -> ft.ExpansionTile:
    """Expandable row used for warning signs and closest messages."""
    return ft.ExpansionTile(
        leading=leading, title=T.text(title, 14.5, W7), subtitle=subtitle, trailing=trailing,
        tile_padding=ft.Padding.symmetric(horizontal=0, vertical=4),
        controls_padding=ft.Padding.only(left=left, right=4, bottom=12),
        expanded_cross_axis_alignment=ft.CrossAxisAlignment.START,
        shape=ft.RoundedRectangleBorder(radius=0), collapsed_shape=ft.RoundedRectangleBorder(radius=0),
        controls=controls,
    )


# ---- 1. verdict ------------------------------------------------------------------------------------
def risk_header(a: dict) -> ft.Control:
    """Verdict panel: coloured left rail, mono score in a thin ring, verdict and summary."""
    level = T.RISK[a["risk_level"]]
    score = a["risk_score"]
    size = 86
    gauge = ft.Stack([
        ft.ProgressRing(value=max(score, 2) / 100, width=size, height=size, stroke_width=5,
                        color=level["fill"], bgcolor=T.SURFACE_2, stroke_cap=ft.StrokeCap.ROUND),
        ft.Container(
            ft.Column([T.mono(str(score), 26, level["color"], bold=True, spacing=-0.5),
                       T.mono("/100", 10, T.MUTED)],
                      spacing=0, horizontal_alignment=ft.CrossAxisAlignment.CENTER, tight=True),
            width=size, height=size, alignment=ft.Alignment.CENTER),
    ], width=size, height=size)
    body = ft.Column(
        [
            ft.Row([T.status_chip(level["label"], level["color"]), ft.Container(expand=True),
                    T.mono("FRAUDLENS VERDICT", 10, T.MUTED, spacing=1.2)]),
            ft.Row([
                ft.Column([
                    T.text(a["verdict"], 20, W7, style=ft.TextStyle(letter_spacing=-0.3)),
                    T.pill(a["category_label"].upper(), T.MUTED, T.SURFACE_2, size=10.5),
                ], spacing=10, expand=True),
                gauge,
            ], spacing=14, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            T.divider(),
            T.body(a["summary"], size=14, color=T.TEXT),
        ],
        spacing=14,
    )
    # The rail is positioned inside a Stack so it always matches the panel's height.
    return ft.Container(
        ft.Stack([ft.Container(body, padding=ft.Padding.only(left=22, right=18, top=18, bottom=18)),
                  ft.Container(width=4, bgcolor=level["fill"], left=0, top=0, bottom=0)]),
        border_radius=T.R_CARD, bgcolor=T.SURFACE, border=ft.Border.all(1, T.tint(level["fill"], 0.35)),
        clip_behavior=ft.ClipBehavior.HARD_EDGE,
    )


# ---- 2. Scam X-Ray ---------------------------------------------------------------------------------
def xray(a: dict, tactics_by_id: dict) -> ft.Control:
    spans = []
    for seg in a["segments"]:
        t = tactics_by_id.get(seg["tactic"]) if seg["tactic"] else None
        if t:
            spans.append(ft.TextSpan(seg["text"], style=ft.TextStyle(
                bgcolor=T.tint(t["color"], 0.22), color=T.TEXT, weight=W6, font_family=T.fam(W6),
                decoration=ft.TextDecoration.UNDERLINE, decoration_color=t["color"], decoration_thickness=2,
            )))
        else:
            spans.append(ft.TextSpan(seg["text"], style=ft.TextStyle(color=T.TEXT, font_family=T.fam())))

    legend = ft.Row(
        [
            ft.Container(
                content=ft.Row([ft.Container(width=8, height=8, border_radius=4, bgcolor=t["color"]),
                                T.text(t["short"], 12, W6)],
                               spacing=6, tight=True),
                padding=ft.Padding.symmetric(horizontal=10, vertical=6), border_radius=6,
                bgcolor=T.tint(t["color"], 0.10),
            )
            for t in a["tactics"]
        ],
        wrap=True, spacing=6, run_spacing=6,
    )
    bubble = ft.Container(
        content=ft.Text(spans=spans, size=15, selectable=True, font_family=T.fam()),
        padding=16, bgcolor=T.SUBTLE, border=ft.Border.all(1, T.BORDER),
        border_radius=ft.BorderRadius.only(top_left=2, top_right=12, bottom_left=12, bottom_right=12),
    )
    subtitle = ("Highlighted words are the tricks used in this message." if a["tactics"] else
                "No classic trick words found. See below for what the AI layers detected.")
    parts = [T.section_title("Scam X-Ray", subtitle, icon_name=ft.Icons.DOCUMENT_SCANNER), bubble]
    if a["tactics"]:
        parts.append(legend)
    return T.card(ft.Column(parts, spacing=14))


# ---- 3. What to do now -----------------------------------------------------------------------------
def next_steps(a: dict, app) -> ft.Control:
    items = []
    guardian_shown = False  # one "Ask guardian" button is enough, even if two tips suggest it
    for i, adv in enumerate(a["advice"]):
        action_btn = None
        act = adv.get("action")
        payload = adv.get("payload") or {}
        if act == "call_official":
            action_btn = ft.TextButton("Official contact", icon=ft.Icons.VERIFIED, style=T.link_style(),
                                       on_click=lambda e, p=payload: app.show_official_contact(p))
        elif act == "open_url" and payload.get("url"):
            action_btn = ft.TextButton("Open", icon=ft.Icons.OPEN_IN_NEW, style=T.link_style(),
                                       on_click=lambda e, u=payload["url"]: app.open_url(u))
        elif act in ("verify_contact", "share_guardian") and not guardian_shown:
            guardian_shown = True
            action_btn = ft.TextButton("Ask guardian", icon=ft.Icons.GROUPS, style=T.link_style(),
                                       on_click=lambda e: app.share_with_guardian())
        if i:
            items.append(T.divider())
        items.append(ft.Container(
            content=ft.Row(
                [
                    ft.Stack([
                        T.squircle(T.ADVICE_ICONS.get(adv["id"], ft.Icons.SHIELD), T.TEXT, 40),
                        ft.Container(T.mono(str(i + 1), 9.5, T.ON_ACCENT, bold=True, spacing=0), width=18,
                                     height=18, border_radius=9, bgcolor=T.SAFE, alignment=ft.Alignment.CENTER,
                                     right=-4, top=-4, border=ft.Border.all(2, T.SURFACE)),
                    ], width=44, height=44),
                    ft.Column([T.text(adv["title"], 15, W7),
                               T.caption(adv["detail"], size=13.5),
                               *([action_btn] if action_btn else [])],
                              spacing=3, expand=True),
                ],
                spacing=12, vertical_alignment=ft.CrossAxisAlignment.START,
            ),
            padding=ft.Padding.symmetric(vertical=12),
        ))
    return T.card(ft.Column([T.section_title("What to do now", icon_name=ft.Icons.CHECKLIST,
                                             color=T.SAFE_TEXT),
                             ft.Column(items, spacing=0)], spacing=6))


# ---- 4. Warning signs ------------------------------------------------------------------------------
def warning_signs(a: dict) -> ft.Control:
    if not a["tactics"]:
        if a["risk_level"] != "low":
            return T.card(ft.Row([T.squircle(ft.Icons.PSYCHOLOGY, T.RISK[a["risk_level"]]["color"], 40),
                                  T.body("No classic trick words. This message was flagged by the AI layers, "
                                         "which recognise scams by meaning, not keywords.", size=13.5,
                                         expand=True)], spacing=12))
        return T.card(ft.Row([T.squircle(ft.Icons.CHECK_CIRCLE, T.RISK["low"]["color"], 40),
                              T.text("No warning signs found.", 15, W6, expand=True)], spacing=12))
    rows = []
    for i, t in enumerate(a["tactics"]):
        quotes = ", ".join(f"“{e}”" for e in t["evidence"][:3])
        details = [T.caption(d, size=13) for d in t["details"][:2]]
        if i:
            rows.append(T.divider())
        rows.append(_tile(
            t["label"], T.caption(t["description"], size=12.5),
            T.squircle(T.icon(t["icon"]), T.lighten(t["color"]), 40),
            ft.Row([T.pill(f"+{t['contribution']}", T.lighten(t["color"])),
                    ft.Icon(ft.Icons.EXPAND_MORE, size=18, color=T.FAINT)], spacing=2, tight=True),
            [ft.Column([
                T.text(quotes, 13, W5, T.lighten(t["color"]), italic=True) if quotes else ft.Container(),
                *details,
            ], spacing=4)],
        ))
    combos = a.get("engine", {}).get("combos", [])
    extra = []
    if combos:
        danger = T.RISK["high"]["color"]
        extra.append(T.inner(
            ft.Column([ft.Row([ft.Icon(ft.Icons.BOLT, color=danger, size=18),
                               T.text("Dangerous combinations", 13.5, W7, danger)], spacing=6),
                       *[T.body(f"• {c}", size=13) for c in combos]], spacing=4),
            bgcolor=T.RISK["high"]["bg"]))
    return T.card(ft.Column(
        [T.section_title(f"Warning signs ({len(a['tactics'])})",
                         "Points show how much each sign adds to the score. Tap a sign to see the evidence.",
                         icon_name=ft.Icons.WARNING_AMBER_ROUNDED, color=T.RISK["medium"]["color"]),
         ft.Column(rows, spacing=0), *extra],
        spacing=8,
    ))


# ---- 5. Threat intelligence ------------------------------------------------------------------------
def intel_card(a: dict) -> ft.Control:
    """What global security databases say about the links and numbers in the message."""
    intel = a.get("intel") or {}
    findings = intel.get("findings") or []
    expanded = intel.get("expanded_links") or {}
    if not intel.get("enabled") or (not findings and not expanded):
        return ft.Container()
    controls = [T.section_title(
        "Threat intelligence",
        "Links and numbers checked live against security databases"
        + (f" in {intel['latency_ms']} ms." if intel.get("latency_ms") else "."),
        icon_name=ft.Icons.PUBLIC, color=T.TEXT)]
    if intel.get("blocklisted"):
        controls.append(ft.Container(
            ft.Row([ft.Icon(ft.Icons.GPP_BAD, color=T.FRAUD_TEXT, size=22),
                    T.text("This link is on a security blocklist. Do not open it.", 14, W7, T.FRAUD_TEXT,
                           expand=True)], spacing=10),
            bgcolor=T.tint(T.FRAUD, 0.14), border=ft.Border.all(1, T.tint(T.FRAUD, 0.5)), border_radius=T.R_INNER,
            padding=14))
    for short, full in expanded.items():
        controls.append(T.inner(ft.Row([
            T.squircle(ft.Icons.CALL_SPLIT, LAYER_COLORS["url"], 34, T.SURFACE),
            ft.Column([T.caption(f"Short link {short}", size=12.5, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                       T.text(f"really goes to {full}", 13.5, W6, max_lines=2, overflow=ft.TextOverflow.ELLIPSIS)],
                      spacing=0, expand=True)],
            spacing=10)))
    rows = []
    for f in findings:
        if expanded and f.get("title") == "Short link unmasked":
            continue  # already shown above
        color, icon = SEVERITY.get(f.get("severity"), SEVERITY["info"])
        if rows:
            rows.append(T.divider())
        rows.append(ft.Container(ft.Row([
            T.squircle(icon, color, 36),
            ft.Column([T.text(f["title"], 14.5, W7),
                       T.caption(f.get("detail") or ""),
                       T.text(SOURCE_NAMES.get(f.get("source"), f.get("source", "")), 12, W6, color)],
                      spacing=2, expand=True)],
            spacing=12, vertical_alignment=ft.CrossAxisAlignment.START), padding=ft.Padding.symmetric(vertical=10)))
    if rows:
        controls.append(ft.Column(rows, spacing=0))
    return T.card(ft.Column(controls, spacing=12))


# ---- 6. How FraudLens decided ----------------------------------------------------------------------
def verification_card(a: dict, app) -> ft.Control:
    """Points per verification layer, plus the closest known messages."""
    v = a.get("verification") or {}
    breakdown = a.get("score_breakdown") or []
    if not v.get("enabled") and not breakdown:
        return ft.Container()
    bar = ft.Row(
        [ft.Container(bgcolor=LAYER_COLORS.get(b["source"], T.MUTED), height=12, expand=max(b["points"], 1),
                      tooltip=f"{b['label']}: +{b['points']}") for b in breakdown] or
        [ft.Container(bgcolor=T.BORDER, height=12, expand=1)],
        spacing=3,
    )
    rows = []
    for b in breakdown:
        color = LAYER_COLORS.get(b["source"], T.MUTED)
        rows.append(ft.Row(
            [T.squircle(LAYER_ICONS.get(b["source"], ft.Icons.SHIELD), color, 36),
             ft.Column([T.text(b["label"], 14, W6),
                        T.caption(b.get("detail") or "", size=12.5)], spacing=0, expand=True),
             ft.Container(T.text(f"+{b['points']}", 13.5, W8, color), bgcolor=T.tint(color, 0.10),
                          border_radius=999, padding=ft.Padding.symmetric(horizontal=10, vertical=4))],
            spacing=12,
        ))
    controls = [
        T.section_title("How FraudLens decided",
                        f"Each layer checks something different. Together they make the {a['risk_score']}/100.",
                        icon_name=ft.Icons.INSIGHTS, color=T.TEXT),
        ft.Container(bar, border_radius=6, clip_behavior=ft.ClipBehavior.HARD_EDGE),
        ft.Column(rows, spacing=12),
    ]
    p = v.get("classifier_probability")
    if p is not None:
        c = LAYER_COLORS["classifier"]
        controls.append(T.inner(ft.Column([
            ft.Row([T.caption("AI language model", expand=True),
                    T.text(f"{p:.0%} scam-like wording", 13, W7, c)]),
            ft.ProgressBar(value=p, color=c, bgcolor=T.tint(c, 0.15), bar_height=8, border_radius=4),
        ], spacing=8)))
    for link in v.get("links", []):
        lp = link["phishing_probability"]
        controls.append(ft.Row([ft.Icon(ft.Icons.LINK, size=16, color=LAYER_COLORS["url"]),
                                T.text(link["url"], 13, expand=True, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                                T.pill(f"{lp:.0%} phishing", LAYER_COLORS["url"] if lp >= 0.5 else T.MUTED)],
                               spacing=6))
    similar = v.get("similar") or []
    if similar:
        cards = []
        for m in similar[:3]:
            scam = m["label"] == "scam"
            color = T.RISK["high"]["color"] if scam else T.RISK["low"]["color"]
            who = (f"reported {m['reports']}×" if m["source"] == "report" else
                   "from training data" if m["source"] == "training" else "curated example")
            cards.append(ft.Container(
                content=ft.Column([
                    ft.Row([T.pill("SCAM" if scam else "GENUINE", color),
                            T.caption(m["category_label"], size=12, expand=True),
                            T.text(f"{m['similarity']:.0%} similar", 12.5, W7, color)]),
                    T.text(m["preview"], 13, italic=True, max_lines=2, overflow=ft.TextOverflow.ELLIPSIS),
                    T.text(who, 11.5, color=T.MUTED),
                ], spacing=6),
                padding=14, border_radius=T.R_INNER, bgcolor=T.SUBTLE, border=ft.Border.all(1, T.BORDER),
            ))
        top = similar[0]
        controls.append(_tile(
            "Closest known messages",
            T.caption(f"Best match {top['similarity']:.0%} similar · {top['category_label']}", size=12.5),
            T.squircle(ft.Icons.MANAGE_SEARCH, LAYER_COLORS["memory"], 36), None,
            [ft.Column(cards, spacing=8)], left=0,
        ))
    for note in v.get("notes", []):
        controls.append(ft.Row([ft.Icon(ft.Icons.INFO_OUTLINE, size=16, color=T.MUTED),
                                T.caption(note, size=12.5, expand=True)], spacing=6))
    if v.get("enabled"):
        mode = "learned weights" if v.get("mode") == "learned" else "default weights"
        controls.append(T.text(f"Models: {v.get('embedder')} · {mode}"
                               + (f" · {v['model_version']}" if v.get("model_version") else ""),
                               11.5, color=T.MUTED))
    return T.card(ft.Column(controls, spacing=14))


# ---- 7. Reply & report -----------------------------------------------------------------------------
def respond_card(a: dict, app) -> ft.Control:
    """Safe reply to copy (only for risky messages) and crowd learning: report scam / genuine."""
    parts: list[ft.Control] = []
    if a["risk_level"] != "low":
        parts += [
            T.section_title("Reply safely", "A ready-made answer that puts the burden of proof on the sender.",
                            icon_name=ft.Icons.QUICKREPLY, color=T.TEXT),
            T.inner(T.text(a["verification_reply"], 14.5, italic=True)),
            ft.Row([ft.OutlinedButton("Copy reply", icon=ft.Icons.COPY, style=T.secondary_style(),
                                      on_click=lambda e: app.copy(a["verification_reply"]))]),
            ft.Container(T.divider(), padding=ft.Padding.symmetric(vertical=6)),
        ]
    parts += [
        T.section_title("Help FraudLens learn",
                        "Confirmed reports join the scam memory, so the next person is warned instantly.",
                        icon_name=ft.Icons.GROUPS, color=T.TEXT),
        ft.Row([
            ft.FilledButton("Report scam", icon=ft.Icons.FLAG, expand=True,
                            style=T.primary_style(T.RISK["high"]["color"]),
                            on_click=lambda e: app.report(a, "scam")),
            ft.OutlinedButton("It's genuine", icon=ft.Icons.VERIFIED_USER, expand=True,
                              style=T.secondary_style(T.RISK["low"]["color"]),
                              on_click=lambda e: app.report(a, "legit")),
        ], spacing=10),
    ]
    return T.card(ft.Column(parts, spacing=12))


def transparency_footer(a: dict, app, offline: bool) -> ft.Control:
    p, e = a["privacy"], a["engine"]
    hidden = p["redacted_items"]
    lines = [
        ft.Row([ft.Icon(ft.Icons.LOCK, size=15, color=T.PRIMARY),
                T.caption(f"{hidden} personal detail{'s' if hidden != 1 else ''} hidden before AI analysis"
                          if hidden else "No personal details detected in this message", size=12.5, expand=True)],
               spacing=8),
        ft.Row([ft.Icon(ft.Icons.MEMORY, size=15, color=T.PRIMARY),
                T.caption(f"Engine {e['version']} · {e['rules_fired']} rules fired · "
                          f"AI: {p['ai_provider'] if p['ai_used'] else 'off'} · {e['latency_ms']} ms"
                          + (" · offline demo" if offline else ""), size=12.5, expand=True)], spacing=8),
    ]
    for note in e.get("trust_notes", []):
        lines.append(ft.Row([ft.Icon(ft.Icons.THUMB_UP_ALT_OUTLINED, size=15, color=T.RISK["low"]["color"]),
                             T.caption(note, size=12.5, expand=True)], spacing=8))
    return ft.Container(ft.Column(lines, spacing=8), padding=ft.Padding.symmetric(horizontal=16, vertical=14),
                        border_radius=T.R_CARD, border=ft.Border.all(1, T.BORDER))


def build(a: dict, app, offline: bool = False) -> ft.Column:
    tactics_by_id = {t["tactic"]: t for t in a["tactics"]}
    return ft.Column(
        [
            risk_header(a),
            xray(a, tactics_by_id),
            next_steps(a, app),
            warning_signs(a),
            intel_card(a),
            verification_card(a, app),
            respond_card(a, app),
            transparency_footer(a, app, offline),
        ],
        spacing=T.GAP, horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
    )
