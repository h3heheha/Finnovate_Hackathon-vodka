"""Generate extra training messages (EN / FR / Kreol Morisien) with a LOCAL LLM via Ollama.

Run this on the desktop with the RTX 4070:
    ollama pull gemma3:12b                  # once (≈8 GB of VRAM at Q4)
    python -m scripts.generate_synthetic --per-seed 4
    python -m scripts.generate_synthetic --host http://192.168.1.20:11434   # Ollama on another machine

It rewrites every seed message (curated + your team's real messages) into new
variants that keep the same label and scam tactic but change wording, names,
amounts and language. Output: data/raw/synthetic_<model>.csv, then run
`python -m scripts.build_dataset` and `python -m scripts.train`.

Synthetic rows are marked is_real=0 and share a `group` with their seed, so a
seed and its variants never end up split across train and test.
Review a sample by hand before training: models sometimes produce odd Kreol.
"""
import argparse
import csv
import hashlib
import json
import re
import time
import urllib.request

from app.core.config import get_settings
from scripts.build_dataset import csv_rows

PROMPT = """You help build a dataset to train a fraud-DETECTION model for bank customers in Mauritius.
Rewrite the example below into {n} NEW, realistic SMS/WhatsApp messages that a person in Mauritius might receive.
Keep the same intent and label ({label}). {tactic_hint}
Vary wording, names, amounts (in Rs), brands and length. Write them in: {langs}.
Kreol Morisien must use common SMS spelling (e.g. "ou", "mo", "pou", "zordi", "avoy").
Do not include real phone numbers or real links; use made-up ones like 5XXX XXXX or example-pay.site.

Example ({label}): {text}

Return ONLY a JSON list of objects: [{{"text": "...", "lang": "en|fr|mfe"}}]"""


def ollama(host: str, model: str, prompt: str, timeout: int = 180) -> str:
    body = json.dumps({"model": model, "prompt": prompt, "stream": False,
                       "options": {"temperature": 0.9}}).encode()
    req = urllib.request.Request(f"{host}/api/generate", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())["response"]


def parse(text: str) -> list[dict]:
    m = re.search(r"\[.*\]", text, re.S)
    if not m:
        return []
    try:
        items = json.loads(m.group(0))
    except json.JSONDecodeError:
        return []
    return [i for i in items if isinstance(i, dict) and len(str(i.get("text", ""))) > 15]


def main(host: str, model: str, per_seed: int, langs: str, limit: int | None) -> None:
    s = get_settings()
    seeds = csv_rows(str(s.data_dir / "seed" / "curated_messages.csv"), "curated", 0)
    seeds += csv_rows(str(s.data_dir / "raw" / "team_messages.csv"), "team", 1)
    if limit:
        seeds = seeds[:limit]
    out_path = s.data_dir / "raw" / f"synthetic_{re.sub(r'[^a-z0-9]+', '_', model.lower())}.csv"
    written = 0
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["text", "label", "lang", "category", "source", "group"])
        w.writeheader()
        for i, seed in enumerate(seeds, 1):
            group = seed.get("group") or hashlib.md5(seed["text"].lower().encode()).hexdigest()[:12]
            hint = ("Keep the same scam tricks (urgency, fake authority, requests for money or codes)."
                    if seed["label"] == "scam" else
                    "It must stay a normal, harmless message (it may mention banks, OTPs or payments).")
            prompt = PROMPT.format(n=per_seed, label=seed["label"], text=seed["text"], langs=langs, tactic_hint=hint)
            t0 = time.time()
            try:
                items = parse(ollama(host, model, prompt))
            except Exception as exc:
                print(f"[{i}/{len(seeds)}] failed: {exc}")
                continue
            for it in items[:per_seed]:
                w.writerow({"text": it["text"].strip(), "label": seed["label"], "lang": it.get("lang", ""),
                            "category": seed.get("category", ""), "source": "synthetic", "group": group})
                written += 1
            fh.flush()
            print(f"[{i}/{len(seeds)}] +{len(items[:per_seed])} ({time.time() - t0:.1f}s)")
    print(f"Wrote {written} synthetic messages to {out_path}. Review a sample, then run scripts.build_dataset.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--model", default="gemma3:12b")
    ap.add_argument("--per-seed", type=int, default=4)
    ap.add_argument("--langs", default="English, French and Kreol Morisien (mix them)")
    ap.add_argument("--limit", type=int, default=None, help="only the first N seeds (quick test)")
    a = ap.parse_args()
    main(a.host, a.model, a.per_seed, a.langs, a.limit)
