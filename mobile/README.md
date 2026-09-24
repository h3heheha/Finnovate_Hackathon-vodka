# FraudLens mobile app

Flet (Python) client for the FraudLens API. See the main README one folder up.

**On Android you don't build this separately any more.** The backend serves this app at `/app`, and the
FraudLens Android app in `../shield/` shows it in its FraudLens tab, next to the Shield tab. `flet build apk`
below still works for a standalone copy, but it isn't needed.

    pip install "flet[all]==1.0.0" httpx
    flet run src/main.py          # desktop
    flet run --web src/main.py    # browser
    flet build apk                # optional standalone Android package

## Screens

| Screen | File | What it does |
|---|---|---|
| Landing | `views/welcome_view.py` | Shield pulse + live feed show that FraudLens works in the background; content loads behind it. "Get started" stays pinned at the bottom. |
| Home | `views/home_view.py` | A menu of features: each button has a name and a small description, and opens that feature's page (Scan, Paste and scan, Examples, Quiz, Scam tricks, Shield, History, Verified contacts, Ask someone you trust, Server settings). |
| Check | `views/check_view.py` | Paste a message, scan it, see the result (`components/result_panel.py`). |
| Learn | `views/learn_view.py` | Spot-the-scam quiz and 30-second lessons. |
| History | `views/history_view.py` | Stats and past checks (stays on the device). |

## Design system

"Clean Dark Slate". Read **[DESIGN_SPEC.md](DESIGN_SPEC.md)** before you change a screen. Every token lives in `src/theme.py`.
- Background `#121417`, cards `#1C1E23`, text `#F3F4F6` / `#8E95A2`, emerald `#10B981` = safe or active, ruby `#EF4444` = fraud.
- Fonts bundled in `src/assets/fonts` (SIL Open Font License): Inter for the interface, JetBrains Mono for scores, statuses and labels.
- Borders, not shadows. A floating dock for navigation. The only looping animation is the Shield pulse on the landing screen.
