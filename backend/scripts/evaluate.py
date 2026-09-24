"""Compare rules-only vs the full hybrid engine -> numbers for the pitch slide.

    python -m scripts.evaluate                    # demo samples + last training's held-out test split
    python -m scripts.evaluate data/my_set.csv    # any CSV with text,label (scam|legit)

"Flagged" means score >= the medium-risk threshold (default 30).
"""
import asyncio
import csv
import sys

from app.api.deps import get_analyzer
from app.core.config import get_settings
from app.knowledge import loader
from app.ml.training import TEST_SPLIT, metrics

import numpy as np


def load(path: str | None) -> list[tuple[str, str]]:
    if path:
        with open(path, encoding="utf-8") as fh:
            return [(r["text"], r["label"].strip().lower()) for r in csv.DictReader(fh)]
    return []


async def run(name: str, rows: list[tuple[str, str]]) -> None:
    if not rows:
        return
    analyzer = get_analyzer()
    thr = get_settings().medium_risk_threshold
    y, rules, hybrid, misses = [], [], [], []
    for text, label in rows:
        r = await analyzer.analyze(text, use_ai=False, use_intel=False)  # no API calls / budget
        y.append(1 if label == "scam" else 0)
        rules.append(int(r["engine"]["rules_score"] >= thr))
        hybrid.append(int(r["risk_score"] >= thr))
        if hybrid[-1] != y[-1]:
            misses.append(f"  MISS [{label}] {r['risk_score']:3}: {text[:90]}")
    y = np.array(y)
    print(f"\n== {name}: {len(rows)} messages ==")
    for k, pred in (("rules only", rules), ("hybrid", hybrid)):
        m = metrics(y, np.array(pred))
        print(f"  {k:11} precision {m['precision']:.1%}  recall {m['recall']:.1%}  F1 {m['f1']:.3f}  "
              f"false positives {m['false_positive_rate']:.1%}")
    print("\n".join(misses[:15]))


async def main(path: str | None) -> None:
    await run("demo samples", [(s["text"], s["expected"]) for s in loader.samples()])
    split = get_settings().data_dir / TEST_SPLIT
    await run("held-out test split", load(str(split)) if split.exists() else [])
    await run(path or "", load(path))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else None))
