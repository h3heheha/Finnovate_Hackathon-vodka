"""Training + evaluation + champion/challenger promotion.

    dataset.csv (+ confirmed user reports)
        │  redact personal data
        ├─ embed (cached)                  ─► scam classifier (logistic regression → ONNX)
        ├─ rule engine                     ─┐
        ├─ URL model                       ─┼► learned combiner (logistic regression)
        └─ leave-one-out memory similarity ─┘
    evaluate on a held-out test set of REAL messages (rules only vs. classifier vs. full hybrid)
    promote the new model only if it is at least as good as the current champion.

CLI: python -m scripts.train
API: POST /api/v1/admin/retrain
"""
from __future__ import annotations

import asyncio
import csv
import hashlib
import json
import logging
import random
import time
from dataclasses import asdict
from pathlib import Path

import numpy as np

from ..core.config import Settings
from ..engine.pipeline import Analyzer
from ..engine.redaction import redact
from ..knowledge import loader
from . import combiner as combiner_mod
from .classifier import OnnxClassifier, export_onnx, train_classifier
from .combiner import Combiner
from .embedders import BaseEmbedder, load_embedder
from .memory import DEFAULT_CALIBRATION, Calibration, MemoryItem
from .registry import Registry
from .service import read_seed_csv, signals_from
from .url_model import load_url_model

log = logging.getLogger("fraudlens.train")
DATASET = "processed/dataset.csv"
TEST_SPLIT = "processed/test_split.csv"
MAX_LEGIT_IN_MEMORY = 4000
PRIOR_COEFS = {"community": 1.2, "url": 0.8}  # used when a feature never varies in the training data


# ---- data -----------------------------------------------------------------------------
def load_rows(settings: Settings, include_reports: bool = True) -> list[dict]:
    path = settings.data_dir / DATASET
    rows: list[dict] = []
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            rows = [r for r in csv.DictReader(fh) if r.get("text") and r.get("label") in ("scam", "legit")]
    else:
        log.warning("%s not found; training on the curated seed set only. Run scripts.build_dataset first.", path)
        for r in read_seed_csv(settings.data_dir / "seed/curated_messages.csv"):
            rows.append({**r, "is_real": "0", "group": ""})
    if include_reports:
        rows += report_rows(settings)
    for r in rows:
        r["is_real"] = str(r.get("is_real", "0"))
        r["group"] = r.get("group") or hashlib.md5(r["text"].lower().encode()).hexdigest()[:12]
        r.setdefault("category", "generic")
        r["category"] = r.get("category") or ("none" if r["label"] == "legit" else "generic")
    # exact duplicates leak between train and test
    seen, unique = set(), []
    for r in rows:
        key = " ".join(r["text"].lower().split())
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def report_rows(settings: Settings) -> list[dict]:
    """Confirmed user reports (already redacted) become training data at the next retrain."""
    out = []
    for runtime in (settings.data_dir / "runtime").glob("*/memory_runtime.json"):
        data = json.loads(runtime.read_text(encoding="utf-8"))
        for item in data.get("confirmed", []):
            out.append({"text": item["text"], "label": item["label"], "lang": "", "category": item["category"],
                        "source": "report", "is_real": "1", "group": item["id"]})
    return out


def split(rows: list[dict], test_fraction: float = 0.2, seed: int = 13) -> tuple[list[dict], list[dict], str]:
    """Group-aware stratified split. The test set uses REAL messages whenever enough exist."""
    rng = random.Random(seed)
    real = [r for r in rows if r["is_real"] == "1"]
    pool = real if sum(r["label"] == "scam" for r in real) >= 15 and sum(r["label"] == "legit" for r in real) >= 15 \
        else rows
    note = "test set = real messages only" if pool is real else \
        "WARNING: not enough real messages; test set includes curated/synthetic ones, so metrics are optimistic"
    test_groups = set()
    for label in ("scam", "legit"):
        groups = sorted({r["group"] for r in pool if r["label"] == label})
        rng.shuffle(groups)
        test_groups.update(groups[:max(1, int(len(groups) * test_fraction))])
    test = [r for r in pool if r["group"] in test_groups]
    train = [r for r in rows if r["group"] not in test_groups]
    return train, test, note


# ---- embeddings cache ------------------------------------------------------------------
class EmbeddingCache:
    def __init__(self, settings: Settings, embedder: BaseEmbedder):
        self.embedder = embedder
        self.path = settings.data_dir / "cache" / f"embeddings_{embedder.id}.npz"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.store: dict[str, np.ndarray] = {}
        if self.path.exists():
            d = np.load(self.path, allow_pickle=False)
            if d["vectors"].shape[1:] == (embedder.dim,):
                self.store = dict(zip(d["keys"].tolist(), d["vectors"]))

    def embed(self, texts: list[str]) -> np.ndarray:
        keys = [hashlib.sha1(t.encode()).hexdigest() for t in texts]
        missing = [(k, t) for k, t in dict(zip(keys, texts)).items() if k not in self.store]
        if missing:
            log.info("Embedding %d new messages with %s…", len(missing), self.embedder.id)
            vecs = self.embedder.embed([t for _, t in missing])
            self.store.update({k: v for (k, _), v in zip(missing, vecs)})
            np.savez(self.path, keys=np.array(list(self.store)), vectors=np.stack(list(self.store.values())))
        return np.stack([self.store[k] for k in keys]).astype(np.float32)


# ---- features ----------------------------------------------------------------------------
def rule_features(settings: Settings, texts: list[str]) -> list[dict]:
    rules = Analyzer(settings)  # rules only

    async def run():
        out = []
        for t in texts:
            a = await rules.analyze(t, use_ai=False)
            out.append({"score": a["risk_score"], "tactics": {x["tactic"] for x in a["tactics"]},
                        "urls": a["entities"]["urls"]})
        return out
    return asyncio.run(run())


def nearest_sims(queries: np.ndarray, bank: np.ndarray, bank_labels: np.ndarray, exclude_self: bool,
                 chunk: int = 1024) -> tuple[np.ndarray, np.ndarray]:
    """Highest similarity to a scam and to a genuine message in `bank`, for every query row."""
    n = len(queries)
    best_scam = np.full(n, np.nan, dtype=np.float32)
    best_legit = np.full(n, np.nan, dtype=np.float32)
    scam_mask = bank_labels == 1
    for i in range(0, n, chunk):
        s = queries[i:i + chunk] @ bank.T
        if exclude_self:
            idx = np.arange(i, min(i + chunk, n))
            s[np.arange(len(idx)), idx] = -1
        if scam_mask.any():
            best_scam[i:i + chunk] = s[:, scam_mask].max(axis=1)
        if (~scam_mask).any():
            best_legit[i:i + chunk] = s[:, ~scam_mask].max(axis=1)
    return best_scam, best_legit


def calibrate(sim_scam: np.ndarray, y: np.ndarray, embedder_id: str) -> Calibration:
    """Pick the similarity above which a message can safely be called 'the same scam'."""
    default = DEFAULT_CALIBRATION.get(embedder_id, Calibration(0.9, 0.8, 0.95))
    ok = ~np.isnan(sim_scam)
    s, lab = sim_scam[ok], y[ok]
    if len(s) < 40 or lab.sum() < 10 or (lab == 0).sum() < 10:
        return default
    match = default.match
    for t in np.linspace(float(np.percentile(s, 50)), 0.995, 200):
        hit = s >= t
        if hit.sum() >= 5 and lab[hit].mean() >= 0.97:
            match = float(t)
            break
    match = float(np.clip(match, default.low + 0.02, 0.99))
    low = float(np.clip(np.percentile(s[lab == 0], 50), default.low - 0.2, match - 0.02))
    return Calibration(match=round(match, 4), low=round(low, 4), duplicate=round(max(default.duplicate, match), 4))


def build_feature_matrix(rules, clf_p, sim_scam, sim_legit, url_probs, cal) -> np.ndarray:
    class _Cal:  # tiny adapter so signals_from can use the calibration
        def __init__(self, c):
            self.calibration = c

        def strength(self, sim):
            if sim is None or np.isnan(sim):
                return 0.0
            c = self.calibration
            return float(np.clip((sim - c.low) / max(c.match - c.low, 1e-6), 0, 1))

    mem = _Cal(cal)
    X = []
    for i, r in enumerate(rules):
        sg = signals_from(rules_score=r["score"], tactics=r["tactics"],
                          classifier_p=None if clf_p is None else float(clf_p[i]),
                          sim_scam=None if np.isnan(sim_scam[i]) else float(sim_scam[i]),
                          sim_legit=None if np.isnan(sim_legit[i]) else float(sim_legit[i]),
                          memory=mem, url_probs=url_probs[i], community=0)
        X.append(sg.vector({"classifier": 0.5}))
    return np.asarray(X, dtype=float)


# ---- metrics ----------------------------------------------------------------------------
def metrics(y_true: np.ndarray, flagged: np.ndarray) -> dict:
    tp = int(((flagged == 1) & (y_true == 1)).sum())
    fp = int(((flagged == 1) & (y_true == 0)).sum())
    tn = int(((flagged == 0) & (y_true == 0)).sum())
    fn = int(((flagged == 0) & (y_true == 1)).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"n": len(y_true), "tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": round(p, 4),
            "recall": round(r, 4), "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
            "accuracy": round((tp + tn) / len(y_true), 4) if len(y_true) else 0.0}


def hybrid_scores(X: np.ndarray, comb: Combiner) -> np.ndarray:
    out = []
    for row in X:
        sig = combiner_mod.Signals(**dict(zip(combiner_mod.FEATURES, row)))
        out.append(comb.combine(sig).probability * 100)
    return np.asarray(out)


# ---- main entry point ---------------------------------------------------------------------
def train(settings: Settings, *, force_promote: bool = False, embedder: BaseEmbedder | None = None,
          progress=print) -> dict:
    t0 = time.time()
    embedder = embedder or load_embedder(settings.embedder, settings.models_dir, settings.onnx_threads)
    registry = Registry(settings.models_dir, embedder.id)
    url_model = load_url_model(settings.models_dir)
    thr = settings.medium_risk_threshold

    rows = load_rows(settings)
    train_rows, test_rows, split_note = split(rows)
    progress(f"Data: {len(rows)} messages ({sum(r['label'] == 'scam' for r in rows)} scam) → "
             f"train {len(train_rows)}, test {len(test_rows)}. {split_note}")

    cache = EmbeddingCache(settings, embedder)

    def prepare(rs):
        red = [redact(r["text"]).text for r in rs]
        vecs = cache.embed(red)
        rules = rule_features(settings, [r["text"] for r in rs])
        urls = [url_model.predict(r["urls"]) if (url_model and r["urls"]) else [] for r in rules]
        y = np.array([1 if r["label"] == "scam" else 0 for r in rs])
        return red, vecs, rules, urls, y

    progress("Embedding + rule features (cached after the first run)…")
    tr_red, Xtr, tr_rules, tr_urls, ytr = prepare(train_rows)
    te_red, Xte, te_rules, te_urls, yte = prepare(test_rows)

    # 1) classifier -------------------------------------------------------------------------
    from sklearn.model_selection import cross_val_predict

    progress("Training the scam classifier…")
    clf = train_classifier(Xtr, ytr)
    folds = min(5, int(min(ytr.sum(), (ytr == 0).sum())))
    clf_tr = cross_val_predict(train_classifier(Xtr, ytr), Xtr, ytr, cv=folds, method="predict_proba")[:, 1] \
        if folds >= 2 else clf.predict_proba(Xtr)[:, 1]
    out_dir = registry.new_version_dir()
    export_onnx(clf, embedder.dim, out_dir / "classifier.onnx")
    onnx_clf = OnnxClassifier(out_dir / "classifier.onnx")
    clf_te = onnx_clf.predict_proba(Xte)                # evaluate the exported ONNX, not sklearn

    # 2) memory similarity (leave-one-out on train) + calibration ----------------------------------
    sim_s_tr, sim_l_tr = nearest_sims(Xtr, Xtr, ytr, exclude_self=True)
    cal = calibrate(sim_s_tr, ytr, embedder.id)
    sim_s_te, sim_l_te = nearest_sims(Xte, Xtr, ytr, exclude_self=False)
    progress(f"Memory calibration: match ≥ {cal.match}, ignore < {cal.low}")

    # 3) learned combiner ----------------------------------------------------------------------
    Ftr = build_feature_matrix(tr_rules, clf_tr, sim_s_tr, sim_l_tr, tr_urls, cal)
    Fte = build_feature_matrix(te_rules, clf_te, sim_s_te, sim_l_te, te_urls, cal)
    params = combiner_mod.fit(Ftr, ytr)
    for f, prior in PRIOR_COEFS.items():
        i = combiner_mod.FEATURES.index(f)
        if Ftr[:, i].std() == 0:
            params["coefs"][i] = prior
    comb = Combiner(params)

    # 4) evaluation ----------------------------------------------------------------------------
    rules_te = np.array([r["score"] for r in te_rules])
    hyb_te = hybrid_scores(Fte, comb)
    results = {
        "rules_only": metrics(yte, (rules_te >= thr).astype(int)),
        "classifier_only": metrics(yte, (clf_te >= 0.5).astype(int)),
        "hybrid": metrics(yte, (hyb_te >= thr).astype(int)),
    }
    demo = [(s["text"], s["expected"]) for s in loader.samples()]
    progress("Test results (flagged = score ≥ medium threshold):")
    for k, m in results.items():
        progress(f"  {k:16} precision {m['precision']:.1%}  recall {m['recall']:.1%}  "
                 f"F1 {m['f1']:.3f}  false positives {m['false_positive_rate']:.1%}")

    # 5) write artifacts ---------------------------------------------------------------------------
    (out_dir / "combiner.json").write_text(json.dumps(params, indent=1), encoding="utf-8")
    (out_dir / "calibration.json").write_text(json.dumps(asdict(cal)), encoding="utf-8")
    keep = [i for i, y in enumerate(ytr) if y == 1]
    legit_idx = [i for i, y in enumerate(ytr) if y == 0]
    random.Random(7).shuffle(legit_idx)
    keep += legit_idx[:MAX_LEGIT_IN_MEMORY]
    items = [MemoryItem(id=f"train-{i}", label=train_rows[i]["label"], text=tr_red[i],
                        category=train_rows[i]["category"], source="training", reports=1) for i in keep]
    np.savez_compressed(out_dir / "memory_seed.npz", vectors=Xtr[keep])
    (out_dir / "memory_seed.json").write_text(json.dumps([asdict(i) for i in items], ensure_ascii=False), encoding="utf-8")
    report = {
        "version": out_dir.name, "embedder": embedder.id, "trained_at": time.time(),
        "seconds": round(time.time() - t0, 1), "split_note": split_note,
        "data": {"total": len(rows), "train": len(train_rows), "test": len(test_rows),
                 "sources": _count(rows, "source"), "languages": _count(rows, "lang")},
        "test": results, "calibration": asdict(cal), "url_model": bool(url_model),
        "demo_samples": len(demo),
    }

    # 6) champion / challenger ----------------------------------------------------------------------
    champion_dir = registry.current_dir()
    champion_f1 = None
    if champion_dir and champion_dir != out_dir:
        try:
            champion_f1 = _evaluate_champion(champion_dir, Xte, te_rules, te_urls, yte, thr, embedder.id)
        except Exception as exc:
            progress(f"Could not evaluate the current champion ({exc}); promoting the new model.")
    promoted = force_promote or champion_f1 is None or results["hybrid"]["f1"] >= champion_f1 - 0.005
    report["champion_f1"] = champion_f1
    report["promoted"] = promoted
    (out_dir / "metrics.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    (settings.data_dir / TEST_SPLIT).parent.mkdir(parents=True, exist_ok=True)
    with open(settings.data_dir / TEST_SPLIT, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["text", "label", "lang", "category", "source"], extrasaction="ignore")
        w.writeheader()
        w.writerows(test_rows)
    if promoted:
        registry.promote(out_dir)
        progress(f"Promoted {out_dir.name} (hybrid F1 {results['hybrid']['f1']:.3f}"
                 + (f" vs champion {champion_f1:.3f})" if champion_f1 is not None else ")"))
    else:
        progress(f"Kept champion (F1 {champion_f1:.3f}); new model {out_dir.name} scored "
                 f"{results['hybrid']['f1']:.3f} and was not promoted.")
    return report


def _evaluate_champion(d: Path, Xte, te_rules, te_urls, yte, thr, embedder_id) -> float:
    clf = OnnxClassifier(d / "classifier.onnx")
    cal = Calibration(**json.loads((d / "calibration.json").read_text(encoding="utf-8")))
    meta = json.loads((d / "memory_seed.json").read_text(encoding="utf-8"))
    bank = np.load(d / "memory_seed.npz")["vectors"]
    labels = np.array([1 if m["label"] == "scam" else 0 for m in meta])
    ss, sl = nearest_sims(Xte, bank, labels, exclude_self=False)
    F = build_feature_matrix(te_rules, clf.predict_proba(Xte), ss, sl, te_urls, cal)
    comb = Combiner.load(d / "combiner.json")
    return metrics(yte, (hybrid_scores(F, comb) >= thr).astype(int))["f1"]


def _count(rows: list[dict], key: str) -> dict:
    out: dict[str, int] = {}
    for r in rows:
        out[r.get(key) or "?"] = out.get(r.get(key) or "?", 0) + 1
    return out
