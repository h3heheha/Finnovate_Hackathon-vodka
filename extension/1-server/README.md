# FraudLens server

**FraudLens: spot the warning signs before you pay.** This is the server behind the FraudLens Chrome extension:
the scam engine, the AI models and the security-database checks. The extension itself stores no API keys.

It runs free on Render (Docker, 512 MB). Follow **START HERE** in the EXTENSION V2 folder.

## What it does for each message

| Layer | What it is | Needs a key? |
|---|---|---|
| Warning-sign rules | English, French and Kreol Morisien scam tactics (urgency, OTP requests, fake fees…) | no |
| AI language model | multilingual-e5-small (ONNX) + our classifier trained on local scam data | no |
| Scam memory | nearest-neighbour search: reworded scams are caught right away after a report | no |
| Link model | phishing-URL classifier (numpy version of pirocheto/phishing-url-detection) | no |
| OpenPhish | live list of phishing links, refreshed every 6 hours | no |
| Google Safe Browsing | Google's list of dangerous sites | free key |
| URLhaus (abuse.ch) | malware links | free key |
| VirusTotal | 70+ security vendors' verdict on a link | free key |
| Domain age (RDAP) | brand-new websites are a red flag | no |
| Phone check | real number? mobile / VoIP / premium, which Mauritian network | no |
| AI explanations | Groq (free) or Gemini (free tier) writes the summary. It only ever sees **redacted** text and can't overrule the rules | free key |

Check which services work: extension → Settings → **Check services** (or `GET /api/v1/status/providers`).

## Files

- `render.yaml`, `Dockerfile`: the Render setup (the AI model is downloaded while Render builds)
- `app/`: the server (FastAPI). `app/static/demo/`: the practice pages at `/demo/`
- `models/`: our trained artifacts + small tokenizer and link-model files
- `tests/`: 89 automatic tests (`python -m pytest -q`)
- `SECURITY.md`: how it resists abuse

Never put keys in these files: on Render they go in **Environment**. On your own computer they go in `MY_KEYS.txt`, which sits outside this folder.
