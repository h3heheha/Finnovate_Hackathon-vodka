"""ML verification layer: memory learning, ONNX classifier, combiner, training, ONNX plumbing."""
import asyncio
import json
import sys
from pathlib import Path

import numpy as np
import pytest

from app.core.config import Settings, get_settings
from app.engine.pipeline import Analyzer
from app.knowledge import loader
from app.ml.classifier import OnnxClassifier, export_onnx, train_classifier
from app.ml.combiner import Combiner, Signals
from app.ml.embedders import E5OnnxEmbedder, HashingEmbedder, load_embedder
from app.ml.memory import ScamMemory
from app.ml.service import MLService
from app.services.store import Store

sys.path.insert(0, str(Path(__file__).parent))
import standin_models  # noqa: E402

NOVEL = ("Good evening, I'm Karen from the members desk. Our group made 12,000 last month from home "
         "with a simple app. Shall I add you so you can start tonight?")
VARIANT = ("Good evening, this is Karen from the members desk! Our group made 15,000 last month from home "
           "using a simple app. Shall I add you so you can start tonight?")


def settings(tmp_path: Path, **kw) -> Settings:
    base = get_settings()
    data = tmp_path / "data"
    (data / "seed").mkdir(parents=True)
    (data / "seed" / "curated_messages.csv").write_bytes((base.data_dir / "seed" / "curated_messages.csv").read_bytes())
    return Settings(data_dir=data, models_dir=tmp_path / "models", embedder="hashing", **kw)


def analyze(a: Analyzer, text: str, **kw) -> dict:
    return asyncio.run(a.analyze(text, **kw))


def test_breakdown_adds_up_and_samples_still_correct(tmp_path):
    s = settings(tmp_path)
    ml = MLService(s)
    a = Analyzer(s, ml=ml, reputation=Store().reputation)
    for smp in loader.samples():
        r = analyze(a, smp["text"], sender=smp.get("sender"))
        assert sum(b["points"] for b in r["score_breakdown"]) == r["risk_score"]
        rule_pts = next((b["points"] for b in r["score_breakdown"] if b["source"] == "rules"), 0)
        assert sum(t["contribution"] for t in r["tactics"]) == rule_pts
        expected = "high" if smp["expected"] == "scam" else "low"
        assert r["risk_level"] == expected, (smp["id"], r["risk_score"])
        assert r["verification"]["enabled"]


def test_live_learning_needs_independent_reports(tmp_path):
    s = settings(tmp_path, report_confirmations=2)
    ml = MLService(s)
    a = Analyzer(s, ml=ml)
    before = analyze(a, VARIANT)
    assert before["verification"]["memory_match"] is None

    assert ml.report(NOVEL, "scam", "device-A", "investment")["status"] == "pending"
    assert ml.report(NOVEL, "scam", "device-A", "investment")["status"] == "pending"   # same person twice
    assert ml.report(NOVEL, "scam", "device-B", "investment")["status"] == "confirmed"

    after = analyze(a, VARIANT)
    assert after["verification"]["memory_match"] is not None
    assert after["risk_score"] >= 85 > before["risk_score"]
    assert after["category"] == "investment"
    assert after["advice"][0]["id"] == "known_scam"

    # poisoning attempt: a scammer marks the confirmed scam as genuine
    assert ml.report(NOVEL, "legit", "scammer", "none")["status"] == "rejected"
    # reports survive a restart
    assert MLService(s).memory.stats()["confirmed_reports"] == 1


def test_onnx_classifier_matches_sklearn(tmp_path):
    rng = np.random.default_rng(0)
    X = rng.normal(size=(200, 16)).astype(np.float32)
    y = (X[:, 0] + 0.3 * X[:, 1] > 0).astype(int)
    clf = train_classifier(X, y)
    export_onnx(clf, 16, tmp_path / "c.onnx")
    onnx_p = OnnxClassifier(tmp_path / "c.onnx").predict_proba(X)
    assert np.allclose(onnx_p, clf.predict_proba(X)[:, 1], atol=1e-4)


def test_combiner_modes():
    d = Combiner().combine(Signals(rules=0.2, classifier=0.95, url=0.9))
    assert d.probability > 0.6 and d.mode == "default"
    Combiner.finalize(d, round(d.probability * 100))
    assert sum(b["points"] for b in d.breakdown) == round(d.probability * 100)
    known = Combiner().combine(Signals(rules=0.0, memory=1.0))
    assert known.probability >= 0.85
    # learned weights that would ignore the memory are still floored for a confirmed-scam match
    params = {"coefs": [0.0] * 7, "intercept": -3.0,
              "means": dict.fromkeys(["rules", "classifier", "memory", "genuine", "url", "community", "hard_flag"], 0.0),
              "scales": dict.fromkeys(["rules", "classifier", "memory", "genuine", "url", "community", "hard_flag"], 1.0)}
    floored = Combiner(params).combine(Signals(rules=0.0, memory=1.0))
    assert floored.probability == 0.85 and floored.notes


def test_training_end_to_end_and_promotion(tmp_path):
    from app.ml.training import train

    s = settings(tmp_path)
    first = train(s, progress=lambda m: None)
    assert first["promoted"] and (s.models_dir / "artifacts" / "hashing-v1" / "current.json").exists()
    ml = MLService(s)
    assert ml.classifier is not None and ml.combiner.mode == "learned"
    second = train(s, progress=lambda m: None)
    assert second["champion_f1"] is not None
    a = Analyzer(s, ml=ml)
    r = analyze(a, loader.samples()[0]["text"])
    assert r["verification"]["classifier_probability"] is not None


def test_onnx_embedder_and_url_model_plumbing(tmp_path):
    """Uses stand-ins with the same interface as the real downloads (random weights)."""
    models = tmp_path / "models"
    standin_models.build(models, get_settings().data_dir / "seed" / "curated_messages.csv")
    emb = load_embedder("e5", models)
    assert isinstance(emb, E5OnnxEmbedder) and emb.dim == 384
    v = emb.embed(["hello", "MCB: votre compte sera bloqué", "x" * 5000])
    assert v.shape == (3, 384) and np.allclose(np.linalg.norm(v, axis=1), 1, atol=1e-4)

    s = Settings(data_dir=settings(tmp_path / "x").data_dir, models_dir=models, embedder="auto")
    ml = MLService(s)
    assert ml.embedder.id == "e5-small-onnx"
    try:
        probs = ml.url_scores(["http://mcb-secure-verify.com/login", "https://www.mcb.mu"])
    except Exception:
        probs = []
    if ml.url_model is None:
        pytest.skip("URL stand-in needs the en_US.UTF-8 locale on Linux")
    assert len(probs) == 2 and all(0 <= p <= 1 for p in probs)


def test_hashing_fallback_when_models_missing(tmp_path):
    emb = load_embedder("auto", tmp_path / "nothing-here")
    assert isinstance(emb, HashingEmbedder)


def test_two_trainings_in_the_same_second_get_different_versions(tmp_path):
    from app.ml.registry import Registry
    reg = Registry(tmp_path, "hashing-v1")
    a, b, c = reg.new_version_dir(), reg.new_version_dir(), reg.new_version_dir()
    assert len({a, b, c}) == 3
    assert all(p.exists() for p in (a, b, c))
