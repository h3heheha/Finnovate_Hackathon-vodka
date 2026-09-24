"""Merge every data source into data/processed/dataset.csv.

Columns: text, label (scam|legit), lang, category, source, is_real (1 = a real message), group

Sources (all optional except the curated seed):
  data/seed/curated_messages.csv        hand-written local examples (EN/FR/Kreol)       is_real=0
  data/raw/SMSSpamCollection            UCI SMS Spam Collection (auto-downloaded)        is_real=1
  data/raw/mishra_soni/*.csv            SMS Phishing Dataset, Mishra & Soni (Mendeley,   is_real=1
                                        download manually: licence is "contact authors")
  data/raw/team_messages.csv            REAL messages your team received (text,label,…)  is_real=1
  data/raw/extra/*.csv                  any other labelled CSV with text,label columns   is_real=1
  data/raw/synthetic*.csv               output of scripts.generate_synthetic             is_real=0

Usage:
    python -m scripts.build_dataset                  # UCI spam counted as scam, Mishra-Soni spam dropped
    python -m scripts.build_dataset --no-download    # don't try to fetch UCI
"""
import argparse
import csv
import glob
import io
import urllib.request
import zipfile
from pathlib import Path

from app.core.config import get_settings

UCI_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
FIELDS = ["text", "label", "lang", "category", "source", "is_real", "group"]


def uci(raw: Path, download: bool) -> list[dict]:
    path = raw / "SMSSpamCollection"
    if not path.exists() and download:
        try:
            print("  ↓ UCI SMS Spam Collection")
            data = urllib.request.urlopen(UCI_URL, timeout=30).read()
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                path.write_bytes(z.read("SMSSpamCollection"))
        except Exception as exc:
            print(f"  ! could not download UCI ({exc}). Download it manually from\n    {UCI_URL}\n"
                  f"    and put the 'SMSSpamCollection' file in {raw}")
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "\t" not in line:
            continue
        lab, text = line.split("\t", 1)
        # UCI "spam" is mostly premium-rate prize scams ("You have WON… call 09…"), so we count it as scam.
        rows.append({"text": text, "label": "scam" if lab == "spam" else "legit", "lang": "en",
                     "category": "prize" if lab == "spam" else "none", "source": "uci", "is_real": 1})
    return rows


def mishra_soni(raw: Path, spam_as: str) -> list[dict]:
    rows = []
    for f in glob.glob(str(raw / "mishra_soni" / "*.csv")):
        with open(f, encoding="utf-8", errors="ignore") as fh:
            for r in csv.DictReader(fh):
                r = {k.strip().lower(): v for k, v in r.items() if k}
                lab, text = (r.get("label") or "").strip().lower(), r.get("text") or ""
                if lab == "smishing":
                    label = "scam"
                elif lab == "ham":
                    label = "legit"
                elif lab == "spam" and spam_as != "drop":
                    label = spam_as
                else:
                    continue
                rows.append({"text": text, "label": label, "lang": "en", "category": "generic" if label == "scam"
                             else "none", "source": "mishra_soni", "is_real": 1})
    return rows


def csv_rows(pattern: str, source: str, is_real: int) -> list[dict]:
    rows = []
    for f in glob.glob(pattern):
        with open(f, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("text") and r.get("label") in ("scam", "legit"):
                    rows.append({"text": r["text"], "label": r["label"], "lang": r.get("lang", ""),
                                 "category": r.get("category") or ("none" if r["label"] == "legit" else "generic"),
                                 "source": r.get("source") or source, "is_real": is_real,
                                 "group": r.get("group", "")})
    return rows


def main(download: bool, spam_as: str) -> None:
    s = get_settings()
    raw = s.data_dir / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    rows = []
    rows += csv_rows(str(s.data_dir / "seed" / "curated_messages.csv"), "curated", 0)
    rows += uci(raw, download)
    rows += mishra_soni(raw, spam_as)
    rows += csv_rows(str(raw / "team_messages.csv"), "team", 1)
    rows += csv_rows(str(raw / "extra" / "*.csv"), "extra", 1)
    rows += csv_rows(str(raw / "synthetic*.csv"), "synthetic", 0)

    out = s.data_dir / "processed" / "dataset.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    by_src: dict[str, list[int]] = {}
    for r in rows:
        by_src.setdefault(r["source"], [0, 0])[r["label"] == "scam"] += 1
    print(f"Wrote {len(rows)} messages to {out}")
    for src, (legit, scam) in sorted(by_src.items()):
        print(f"  {src:12} {scam:6} scam  {legit:6} genuine")
    if not any(r["is_real"] for r in rows):
        print("  ! No real messages yet: add data/raw/team_messages.csv so the test set is realistic.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-download", action="store_true")
    ap.add_argument("--spam-as", choices=["scam", "legit", "drop"], default="drop",
                    help="how to label Mishra-Soni 'spam' (promotions) rows")
    a = ap.parse_args()
    main(not a.no_download, a.spam_as)
