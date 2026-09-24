"""Train the classifier + learned combiner, evaluate, and promote if not worse than the champion.

    python -m scripts.train             # champion/challenger promotion
    python -m scripts.train --force     # always promote the new model
    python -m scripts.train --rollback  # switch back to the previous version
"""
import argparse
import logging

from app.core.config import get_settings
from app.ml.embedders import load_embedder
from app.ml.registry import Registry
from app.ml.training import train

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--rollback", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    s = get_settings()
    if a.rollback:
        emb = load_embedder(s.embedder, s.models_dir, s.onnx_threads)
        print("Rolled back to", Registry(s.models_dir, emb.id).rollback() or "nothing (no older version)")
    else:
        train(s, force_promote=a.force)
        print("Restart the API (or call POST /api/v1/admin/retrain next time) to use the new model.")
