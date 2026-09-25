# FraudLens AI: spot the warning signs before you pay

> **Demo on your phone:** follow [`DEMO_PLAN.md`](DEMO_PLAN.md) step by step. **Security review:** [`SECURITY.md`](SECURITY.md).
Finnovate AI Hackathon 2026, Challenge 5.

FraudLens is a mobile app with a FastAPI backend.
- **Scam X-Ray** shows which words in a message are the tricks.
- **Hybrid AI verification** checks every message five different ways and shows how each one contributed to the score.
- **It learns from reports:** a scam reported by users is caught instantly the next time, even reworded.
- **Live threat intelligence:** links and numbers are checked against Google Safe Browsing, abuse.ch URLhaus, domain age (RDAP) and IPQualityScore; short links are unmasked first.
- **One native Android app with Shield built in:** Home, Scan, Learn, History and Shield. Shield warns about scam SMS, WhatsApp and email the moment they arrive, and about scam callers while the phone rings. Share any message from WhatsApp or Messages straight into FraudLens. See [`shield/README.md`](shield/README.md).
- **Pause-Before-Pay** steps in at the moment of payment.

## How a message is verified

```
message ─► rules (EN/FR/Kreol tactics, lookalike links, sender check) ──────────┐
        ─► redact personal data ─► e5 embedding (ONNX) ─┬► AI classifier (ONNX) ─┤
                                                        └► scam memory search ───┼─► combiner ─► score + breakdown
        ─► links ─► pre-trained phishing-URL model (ONNX) ───────────────────────┤      (learned weights)
        ─► accounts / numbers / domains ─► community reputation ────────────────┤
        ─► links + numbers ─► threat intelligence (Safe Browsing, URLhaus, RDAP, IPQS) ┘  (blocklisted ⇒ score ≥ 90)
```

| Layer | What it catches | Model | Learns how |
|---|---|---|---|
| Warning-sign rules | Known tricks, with exact highlights | hand-written, `engine/detectors/` | you add rules |
| AI language model | New wording with the same intent | `multilingual-e5-small` embeddings (ONNX) + logistic regression (ONNX) | retraining (seconds) |
| Scam memory | Reworded or translated variants of reported scams | nearest-neighbour search on e5 embeddings | **instantly**, from confirmed reports |
| Link model | Phishing URLs | `pirocheto/phishing-url-detection` (ONNX, pre-trained) | fixed |
| Community reports | Accounts, numbers or links seen in other scams | hashed identifiers | every high-risk scan and confirmed report |
| Threat intelligence | Known phishing/malware links, days-old domains, risky numbers, hidden short-link targets | Google Safe Browsing, URLhaus, RDAP, IPQS (live APIs, cached) | the databases update themselves |
| Combiner | Weighs all of the above | logistic regression on the layer scores | retraining |

Every layer is optional. If the e5 model isn't downloaded, a built-in hashing embedder takes over. If nothing is trained, a documented default combiner is used. The API never fails because a model is missing.

**Anti-poisoning:**
- A report joins the memory only after `FRAUDLENS_REPORT_CONFIRMATIONS` *different* devices report the same message.
- A "genuine" report can't overwrite a confirmed scam.
- A retrained model is promoted only if its F1 on held-out real messages is not worse than the current one. Rollback is one command.

**Threat intelligence** runs in parallel with a 2.5 s total budget. Results are cached in SQLite (`data/cache/`). A provider that is slow, down or has no key is skipped and listed in `intel.providers`; the rest of the engine still answers. Only URLs, domains and phone numbers are sent to these services, never message text. IPQS is capped at 30 lookups a day (free plan: 35), and only for messages that already look risky. Short links are unmasked by asking the shortener where it redirects; the scam site itself is never contacted.

**Privacy:** only redacted text is embedded, stored in the memory or sent to any AI. Card numbers, accounts, phone numbers, OTPs, NIC numbers and emails are replaced with placeholders. Account numbers are stored only as salted hashes.

## Team


| Member | GitHub | Role | Main contributions |
|---|---|---|---|
|Pushkar Jhaumal| h3heheha | UI/UX design | _…_ |
|Paveesh Rajiah | paveeshrajiah-cmd | _…_ | _…_ |
| Jayesh Dowlol | Gilgamesh1806 | _…_ | _…_ |
| _Name_ | @username | _…_ | _…_ |

## Development history

We built FraudLens offline and saved a copy of the project at each milestone. We had not used Git before, so on **24 Sep 2026** we imported every milestone into this repository **in order, one commit per version**, each tagged. The commit dates are the import date; the order and the contents of each version are the real history. Click a tag (or *Commits*) to see exactly what changed at each step.

| Tag | Milestone | What changed |
|---|---|---|
| `v0.3` | Team's original build (23 Sep) | Backend engine, hybrid AI, threat intelligence, live learning, Flet app, Shield companion |
| `v0.4` | UI/UX redesign, first attempt (24 Sep) | New landing and home; judged too close to the old design, replaced by v0.5 |
| `v0.5` | "Clean Dark Slate" redesign (24 Sep) | Landing shows background protection; home is a feature menu; new design system |
| `v0.6` | App served by the backend + security review (24 Sep) | One server for API and app; attack tests and fixes (`SECURITY.md`); official numbers |
| `v1.0` | One Android app (24 Sep) | FraudLens tab + Shield tab in a single APK |
| `v2.0` | Native Android app (24 Sep) | Every screen rebuilt natively in Kotlin; Shield is one of five tabs; share-to-FraudLens |

**Tools:** Python/FastAPI, ONNX Runtime, Flet, Kotlin/Android. The UI redesign, the web integration, the security review and the single-app merge were done with an AI coding assistant (Claude), directed, reviewed and tested by the team. Later commits are made directly by each member.

## Quick start (demo laptop, CPU only)

Python 3.10–3.12.

```bash
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m scripts.setup_ml     # downloads the ONNX models (~120 MB, once), builds data, trains, refreshes offline cache
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
**Open `http://localhost:8000/`: the backend serves the FraudLens app too** (it redirects to `/app`). It works in any browser, on the laptop or on a phone on the same Wi-Fi at `http://<laptop-LAN-IP>:8000/`. `http://localhost:8000/docs` has the interactive API, and `GET /health` shows which models are loaded.

The app's code lives in `mobile/src` and is mounted by `backend/app/web_ui.py`. Its Python runs inside the API server and calls the same server's `/api/v1`. Everything, including the rendering engine, is served from the laptop, so it works on Wi-Fi with no internet. Set `FRAUDLENS_WEB_UI=false` to serve the API only.

**Threat-intelligence keys** go in `backend/.env` only (it is git-ignored; never put keys in code or in the submission zip). Copy `.env.example` to `.env` if you don't have one, then fill in:
```
FRAUDLENS_SAFE_BROWSING_KEY=...
FRAUDLENS_URLHAUS_KEY=...
FRAUDLENS_IPQS_KEY=...
```
Restart the API, then run `python -m scripts.check_intel` (uses 1 IPQS credit; add `--no-ipqs` to skip). Each provider should print `ok`. Without keys everything still works; RDAP and short-link unmasking need no key.

Standalone mobile app (optional, for the desktop window or an APK), in a second terminal:
```bash
cd mobile
pip install "flet[all]==1.0.0" httpx
flet run src/main.py            # desktop window  (or: flet run --web src/main.py)
```
On a phone, use **the native FraudLens Android app in `shield/`** (Kotlin): the same features and design as this app, with Shield built in (see `shield/README.md`). The web version here stays as the laptop demo and backup.

## The 24-hour data plan

1. **Collect real messages (the whole team, about 1 hour).** Copy `backend/data/seed/team_messages_TEMPLATE.csv` to `backend/data/raw/team_messages.csv`. Add real scams and, just as important, **real genuine texts**: bank OTPs, delivery notices, family chats. The test set is drawn from these real messages, so this is what makes your accuracy numbers credible.
2. **Public data.**
   - The UCI SMS Spam Collection downloads automatically. If the download is blocked, put the `SMSSpamCollection` file in `data/raw/`.
   - Optionally add the Mishra & Soni SMS phishing CSV in `data/raw/mishra_soni/`. Download it manually from Mendeley; the licence says to contact the authors.
3. **Synthetic French/Kreol variants on the 4070 desktop:**
   ```bash
   ollama pull gemma3:12b
   python -m scripts.generate_synthetic --per-seed 4      # writes data/raw/synthetic_gemma3_12b.csv
   ```
   Copy the CSV to the laptop's `backend/data/raw/` and **skim it by hand**. LLM Kreol can be odd.
4. **Train and evaluate:**
   ```bash
   python -m scripts.build_dataset
   python -m scripts.train          # prints rules-only vs classifier vs hybrid on held-out REAL messages
   python -m scripts.evaluate       # same comparison through the live engine, for the slide
   python -m scripts.export_demo_cache
   ```

## The live-learning demo

Start the API with `FRAUDLENS_REPORT_CONFIRMATIONS=1`, so one report is enough on stage.
1. Scan a scam type that isn't in the data. Example: *"Good evening, I'm Karen from the members desk. Our group made 12,000 last month from home with a simple app. Shall I add you so you can start tonight?"* It scores low or medium.
2. Tap **Report scam**. The toast reads "Confirmed. This scam is now in FraudLens memory".
3. Scan a reworded version, or a French translation (translations need the e5 model). It now scores at least 85: *"It matches a scam reported by a FraudLens user (89% similar)"*, and the matching message appears under "Closest messages in the FraudLens memory".

Reports are saved in `data/runtime/`. They join the training data at the next `scripts.train` or `POST /api/v1/admin/retrain`.

## API (v1)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/analyze` | Score, level, tactics, X-Ray segments, `score_breakdown` per layer, `verification` (classifier %, similar messages, link scores), `intel` (findings, unmasked links), advice. `use_intel: false` skips the live checks |
| POST | `/api/v1/report` | Report a message as `scam` / `legit` → `pending`, `confirmed`, `reinforced` or `rejected` |
| GET | `/api/v1/models` | Loaded models, memory stats, version history, training status |
| POST | `/api/v1/admin/retrain` | Retrain on dataset + confirmed reports in the background (header `X-Admin-Token`) |
| POST | `/api/v1/admin/rollback` | Switch back to the previous model version |
| GET | `/api/v1/intel/status` | Which threat-intel providers are configured, IPQS credits used today |
| GET | `/api/v1/intel/url?url=` | Threat-intel verdict for one link (short links unmasked) |
| GET | `/api/v1/intel/phone?number=` | Caller check: IPQS + FraudLens community reports → `risk_level`, `headline`, `reasons` (used by Shield while the phone rings) |
| POST | `/api/v1/payments/check` | Pause-Before-Pay: `allow` / `warn` / `pause` |
| GET | `/api/v1/samples`, `/learn/tactics`, `/learn/quiz`, `/directory`, `/radar` | Content and trend stats |

## Project layout

```
backend/app/
  engine/        rules: detectors (phrases, entities, sender), redaction, scoring, explain, pipeline
  ml/            embedders.py (e5 ONNX + hashing fallback) · classifier.py (ONNX) · url_model.py
                 memory.py (scam memory + reports) · combiner.py · registry.py (versions, promotion)
                 service.py (loads everything) · training.py (train, evaluate, champion/challenger)
  intel/         providers.py (Safe Browsing, URLhaus, RDAP, IPQS, short links) · service.py (parallel, budget) · cache.py
  api/routes/    analyze · learning (report, models, retrain) · intel (url, phone) · payments · content
backend/scripts/ setup_ml · download_models · build_dataset · generate_synthetic · train · evaluate · check_intel
backend/models/  downloaded ONNX models + artifacts/<embedder>/<version>/ (classifier.onnx, combiner.json …)
backend/data/    seed/ (curated EN/FR/Kreol examples) · raw/ (your data) · runtime/ (reports)
mobile/src/      Flet app, served by the backend at /app (backend/app/web_ui.py) or run on its own:
                 landing + Home, Check, Learn, History (views/); theme.py + mobile/DESIGN_SPEC.md = design system;
                 components/result_panel.py shows the verification + threat-intelligence cards
shield/          The native FraudLens Android app (Kotlin): Home, Scan, Learn, History, Shield (notification
                 listener, call screening, overlay banner), share-in. Guide in shield/README.md
```

## Tests

```bash
cd backend && pytest -q     # 61 passed, 1 skipped
```
The threat-intel tests simulate every provider (hits, timeouts, outages, quota) with a fake network, so they run offline. The tests build tiny **stand-in ONNX models** with the same inputs and outputs as the real downloads, so the ONNX code paths are tested without internet access. After `setup_ml`, check `GET /health`. It should list `"embedder": "e5-small-onnx"` and `"url_model": "pirocheto-phishing-url"`.

**Linux note:** the URL model needs the `en_US.UTF-8` locale (`sudo locale-gen en_US.UTF-8`). The Dockerfile installs it. Windows and macOS need nothing.

## Before the final: checklist

- [ ] Run `python -m scripts.setup_ml` on the demo laptop and check `/health`. Keep a copy of `backend/models/` on a USB stick.
- [ ] Add real team messages and synthetic variants, retrain, and put the `scripts.evaluate` table on a slide.
- [ ] Verify the domains in `app/knowledge/directory.json` and add the official phone numbers.
- [ ] Have a native speaker review the Kreol phrases in `engine/detectors/phrases.py` and the synthetic Kreol data.
- [ ] Keys in `backend/.env`, `python -m scripts.check_intel` all `ok`. Restrict the Google key to the Safe Browsing API; create new keys after the hackathon.
- [ ] Shield: rehearse the SMS demo on the emulator (see `shield/README.md`). Have the "Send a test scam alert" button as a fallback.
- [ ] Rehearse the live-learning demo with `FRAUDLENS_REPORT_CONFIRMATIONS=1`. Run `export_demo_cache` so the offline fallback matches.
