"""Turn the pre-trained phishing-URL model (ONNX, 23 MB) into small numpy tables.

    python -m scripts.make_url_model            # writes models/phishing-url-detection/url_model.npz
    python -m scripts.make_url_model --verify   # also compares with onnxruntime on test URLs

Why: onnxruntime needs ~225 MB of memory for this model's 1.4 million n-gram strings. The same maths
in numpy (sorted string tables + searchsorted) needs ~25 MB, which keeps the server inside a free
512 MB host. The graph is: lower-case -> word unigrams + character 1-5-grams (term counts) -> L2
normalise each -> 5 linear SVMs -> sigmoid calibration -> average. See app/ml/url_model.py.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

from app.core.config import get_settings
from app.ml.url_model import NPZ_NAME, URL_DIR_NAME


def _attrs(node) -> dict:
    from onnx import helper
    return {a.name: helper.get_attribute_value(a) for a in node.attribute}


def _vocab(node) -> tuple[list[str], np.ndarray]:
    """n-grams (tokens joined) and their output column, from a TfIdfVectorizer node."""
    a = _attrs(node)
    pool = [s.decode("utf-8") for s in a["pool_strings"]]
    counts = list(a["ngram_counts"]) + [len(pool)]
    grams: list[str] = []
    for n in range(a["min_gram_length"], a["max_gram_length"] + 1):
        start, end = counts[n - 1], counts[n]
        grams += ["".join(pool[i:i + n]) if n > 1 else pool[i] for i in range(start, end, n)]
    idx = np.asarray(a["ngram_indexes"], dtype=np.int64)
    assert len(grams) == len(idx), (len(grams), len(idx))
    return grams, idx


def convert(onnx_path: Path, out: Path) -> None:
    import onnx
    from onnx import numpy_helper

    g = onnx.load(str(onnx_path)).graph
    nodes = {n.output[0]: n for n in g.node}
    init = {i.name: numpy_helper.to_array(i) for i in g.initializer}
    # expected wiring (checked, so a different model is refused rather than mis-read)
    tok_w, tok_c = _attrs(nodes["tokenized"]), _attrs(nodes["tokenized1"])
    assert tok_w["tokenexp"] == b"[a-zA-Z0-9_]+" and tok_c["tokenexp"] == b"."
    assert _attrs(nodes["normalized"])["case_change_action"] == b"LOWER"
    assert list(nodes["union"].input) == ["tfidftr_norm", "tfidftr_norm1"]
    for name in ("output", "output1"):
        assert _attrs(nodes[name])["mode"] == b"TF" and _attrs(nodes[name])["max_skip_count"] == 0
    words, widx = _vocab(nodes["output"])
    chars, cidx = _vocab(nodes["output1"])
    n_word, n_char = int(widx.max()) + 1, int(cidx.max()) + 1
    coef, icpt, cal_a, cal_b = [], [], [], []
    for i, label in enumerate(["label1", "label2", "label3", "label4", "label5"]):
        a = _attrs(nodes[label])
        assert a["post_transform"] == b"NONE" and list(a["classlabels_ints"]) == [0, 1]
        c = np.asarray(a["coefficients"], dtype=np.float32).reshape(2, n_word + n_char)
        coef.append(c[1]); icpt.append(np.float32(a["intercepts"][1]))
        sfx = "" if i == 0 else str(i)
        cal_a.append(float(init[f"a{sfx}"])); cal_b.append(float(init[f"b{sfx}"]))
    assert int(init["k"]) == 1 and float(init["clf_length"]) == 5.0
    wo, co = np.argsort(np.array(words)), np.argsort(np.array(chars))
    out.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(out, words=np.array(words)[wo], word_col=widx[wo].astype(np.int32),
                        chars=np.array(chars)[co], char_col=cidx[co].astype(np.int32),
                        n_word=n_word, n_char=n_char, coef=np.stack(coef), intercept=np.array(icpt, dtype=np.float32),
                        cal_a=np.array(cal_a, dtype=np.float32), cal_b=np.array(cal_b, dtype=np.float32))
    print(f"Wrote {out} ({out.stat().st_size // 1024} KB): {n_word} words, {n_char} character n-grams")


def verify(onnx_path: Path, npz: Path, urls: list[str]) -> float:
    import onnxruntime as ort

    from app.ml.url_model import NumpyUrlModel
    sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    ref = sess.run(None, {"inputs": np.array(urls, dtype="str")})[1]
    ref = np.array([p[1] if not isinstance(p, dict) else p.get(1) for p in ref], dtype=np.float64)
    mine = np.array(NumpyUrlModel(npz).predict_raw(urls))
    worst = float(np.max(np.abs(ref - mine)))
    print(f"{len(urls)} URLs: largest difference from onnxruntime = {worst:.2e}")
    return worst


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", nargs="*", help="text files with one URL per line")
    a = ap.parse_args()
    d = get_settings().models_dir / URL_DIR_NAME
    convert(d / "model.onnx", d / NPZ_NAME)
    if a.verify is not None:
        urls = ["http://mcb-secure-verify.com/login", "https://www.mcb.mu/", "HTTPS://WWW.GOOGLE.COM/Search?q=A",
                "http://192.168.1.20/bank/login", "http://xn--mcb-lpa.mu/", "http://ex.com/ümlaut/ÇA", "a"]
        for f in a.verify:
            urls += [u.strip() for u in open(f, encoding="utf-8") if u.strip()]
        sys.exit(0 if verify(d / "model.onnx", d / NPZ_NAME, urls) < 1e-4 else 1)
