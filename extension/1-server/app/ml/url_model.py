"""Pre-trained phishing-URL model (pirocheto/phishing-url-detection, MIT licence).

Word unigrams + character 1-5-grams of the lower-cased URL (term counts, L2-normalised), five
calibrated linear SVMs, averaged. Output: the probability that the URL is phishing.

Two ways to run it (same numbers, checked by scripts/make_url_model.py --verify):
  * NumpyUrlModel  - url_model.npz: sorted n-gram tables + weights, ~25 MB of memory (used on servers)
  * OnnxUrlModel   - the original model.onnx with onnxruntime, ~225 MB of memory
Downloaded by `python -m scripts.download_models`.
"""
from __future__ import annotations

import logging
import math
import re
from collections import Counter
from pathlib import Path

import numpy as np

log = logging.getLogger("fraudlens.ml")
URL_DIR_NAME = "phishing-url-detection"
NPZ_NAME = "url_model.npz"
_WORD = re.compile(r"[a-zA-Z0-9_]+")


def _full(urls: list[str]) -> list[str]:
    return [u if u.lower().startswith(("http://", "https://")) else f"http://{u}" for u in urls]


class NumpyUrlModel:
    id = "pirocheto-phishing-url"

    def __init__(self, path: Path):
        z = np.load(path)
        self.words, self.word_col = z["words"], z["word_col"]
        self.chars, self.char_col = z["chars"], z["char_col"]
        self.n_word = int(z["n_word"])
        self.coef = z["coef"]                   # (5, n_word + n_char) weights for "phishing"
        self.intercept = z["intercept"].astype(np.float64)
        self.cal_a, self.cal_b = z["cal_a"].astype(np.float64), z["cal_b"].astype(np.float64)

    @staticmethod
    def _lookup(table: np.ndarray, cols: np.ndarray, counts: Counter) -> tuple[np.ndarray, np.ndarray]:
        if not counts:
            return np.zeros(0, dtype=np.int64), np.zeros(0, dtype=np.float64)
        keys = list(counts)
        pos = np.searchsorted(table, np.array(keys))
        pos_ok = np.minimum(pos, len(table) - 1)
        hit = table[pos_ok] == np.array(keys)
        values = np.array([counts[k] for k in keys], dtype=np.float64)[hit]
        return cols[pos_ok[hit]].astype(np.int64), values

    def _features(self, url: str) -> tuple[np.ndarray, np.ndarray]:
        low = url.lower()
        words = Counter(_WORD.findall(low))
        text = low.replace("\n", "")            # the model's "." tokenizer skips line breaks
        grams = Counter(text[i:i + n] for n in range(1, 6) for i in range(len(text) - n + 1))
        wcol, wval = self._lookup(self.words, self.word_col, words)
        ccol, cval = self._lookup(self.chars, self.char_col, grams)
        for vals in (wval, cval):
            norm = math.sqrt(float((vals * vals).sum()))
            if norm > 0:
                vals /= norm
        return np.concatenate([wcol, ccol + self.n_word]), np.concatenate([wval, cval])

    def predict_raw(self, urls: list[str]) -> list[float]:
        out = []
        for u in urls:
            cols, vals = self._features(u)
            scores = self.coef[:, cols].astype(np.float64) @ vals + self.intercept
            out.append(float(np.mean(1.0 / (1.0 + np.exp(self.cal_a * scores + self.cal_b)))))
        return out

    def predict(self, urls: list[str]) -> list[float]:
        return self.predict_raw(_full(urls)) if urls else []


class OnnxUrlModel:
    id = "pirocheto-phishing-url"

    def __init__(self, path: Path):
        import onnxruntime as ort

        self.session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
        self.input_name = self.session.get_inputs()[0].name

    def predict(self, urls: list[str]) -> list[float]:
        if not urls:
            return []
        probs = self.session.run(None, {self.input_name: np.array(_full(urls), dtype="str")})[1]
        if isinstance(probs, list):
            return [float(p.get(1, p.get("1", 0.0))) for p in probs]
        return [float(p[1]) for p in np.asarray(probs)]


UrlModel = OnnxUrlModel  # backwards-compatible name


def load_url_model(models_dir: Path):
    d = models_dir / URL_DIR_NAME
    for path, cls in ((d / NPZ_NAME, NumpyUrlModel), (d / "model.onnx", OnnxUrlModel)):
        if path.exists():
            try:
                return cls(path)
            except Exception as exc:
                log.warning("Could not load URL model %s: %s", path.name, exc)
    log.info("URL model not downloaded (%s); link checks use rules only.", d)
    return None
