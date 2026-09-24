"""Pre-compute results for the demo samples and bundle them into the mobile app.

The app falls back to this cache when the backend is unreachable, so the live
demo still works if the Wi-Fi fails. Re-run after changing rules or samples:

    python -m scripts.export_demo_cache
"""
import asyncio
import json
from pathlib import Path

from app.api.deps import get_analyzer
from app.knowledge import loader
from app.knowledge.tactics import TACTICS
from dataclasses import asdict

OUT = Path(__file__).resolve().parents[2] / "mobile" / "src" / "assets" / "demo_cache.json"


async def main() -> None:
    analyzer = get_analyzer()  # full hybrid engine (rules + ML layers)
    results = {}
    for s in loader.samples():
        r = await analyzer.analyze(s["text"], sender=s.get("sender"), use_ai=False, use_intel=False)
        r.pop("identifiers", None)
        r.pop("redacted_text", None)
        r["created_at"] = r["created_at"].isoformat()
        r["analysis_id"] = f"offline-{s['id']}"
        results[s["text"]] = r
    payload = {
        "samples": loader.samples(),
        "analyses": results,
        "tactics": [asdict(t) for t in TACTICS.values()],
        "quiz": loader.quiz(),
        "directory": loader.directory(),
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Wrote {len(results)} cached analyses to {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
