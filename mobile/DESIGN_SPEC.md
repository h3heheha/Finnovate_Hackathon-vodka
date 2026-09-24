# FraudLens design spec: Clean Dark Slate

Read this before you change any screen. Every value lives in `src/theme.py`. Don't hard-code colours or sizes anywhere else.

## Intent
FraudLens should feel like a calm, technical security tool: dark, precise and quiet, with colour used only when it means something. Green means safe or active. Red means fraud. Nothing else is brightly coloured.

## Tokens

| Token | Value | Use |
|---|---|---|
| `BG` | `#121417` | App background (deep slate) |
| `SURFACE` | `#1C1E23` | Cards, dock, dialogs |
| `SURFACE_2` | `#24272D` | Inner blocks, inputs, pressed rows |
| `LINE` | `#2C3037` | 1 px borders and dividers (no drop shadows) |
| `TEXT` | `#F3F4F6` | Main text (15:1 on cards) |
| `MUTED` | `#8E95A2` | Secondary text (5.5:1 on cards) |
| `SAFE` | `#10B981` | Active, safe, primary action. Buttons use dark text on it (7.7:1) |
| `FRAUD` | `#EF4444` | Fraud fills and rings. Red *text* uses `FRAUD_TEXT #F87171` (6:1) |
| `WARN` | `#F59E0B` | Medium risk only |

Tints are the accent at 8–14 % opacity over `SURFACE`, never pastel hex values.

## Type
- **Inter** (bundled) for all UI text. Sizes: 28 display · 22 title · 16 card title · 14.5 body · 13 secondary · 11 label.
- **JetBrains Mono** (bundled) for anything machine-like: scores, counts, status labels, timestamps, overline labels (UPPERCASE, +1 letter spacing).
- Weights: 400 body, 500 labels, 600 titles, 700 display. No 800/900 except the landing headline.

## Shape and spacing
- Radius: 14 for cards, 10 for inner blocks and buttons, 999 only for status dots and the dock.
- Spacing on a 4-pt grid: 16 inside cards, 12 between cards, 20 screen gutter.
- Borders, not shadows. The only glow is the Shield pulse on the landing screen.

## Signature components
1. **Shield pulse** (landing): concentric rings breathing around the shield, plus a live feed of messages being checked. It shows that Shield works in the background.
2. **Feature button** (Home): icon square, name, one-line description in small muted text, chevron. Tapping it opens that feature's page.
3. **Floating dock**: a pill-shaped bottom bar; the active tab shows icon + label on an emerald tint.
4. **Verdict panel**: mono score, thin ring gauge, coloured left rail (green, amber or red).
5. **Status chip**: mono label with a coloured dot (`ONLINE`, `OFFLINE DEMO`).

## Motion
- 200–260 ms ease-out for state changes; tabs cross-fade.
- The only looping animation is the Shield pulse (1.6 s). Nothing else loops.
- Loading shows skeleton blocks in `SURFACE_2`, never spinners alone.

## Anti-patterns (don't)
- No white or light surfaces, no pastel tiles, no blue or indigo or purple gradients.
- No drop shadows on cards, and no emoji in the UI.
- No colour without meaning: green and red are reserved for safe and fraud.
- No centred paragraphs longer than two lines.
- No new features. The Home page only links to screens that already exist.
