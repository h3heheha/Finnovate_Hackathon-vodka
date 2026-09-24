"""Pre-trained phishing-URL model (pirocheto/phishing-url-detection, MIT licence).

A linear SVM over URL text features, published directly as ONNX. Input is a
1-D string array named "inputs"; output[1] holds [p_legit, p_phishing].
Downloaded by `python -m scripts.download_models`.
"""
from __future__ import annotations

import logging
from pathlib import Path

import numpy as np

log = logging.getLogger("fraudlens.ml")
URL_DIR_NAME = "phishing-url-detection"


class UrlModel:
    id = "pirocheto-phishing-url"

    def __init__(self, path: Path):
        import onnxruntime as ort

        self.session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
        self.input_name = self.session.get_inputs()[0].name

    def predict(self, urls: list[str]) -> list[float]:
        if not urls:
            return []
        full = [u if u.lower().startswith(("http://", "https://")) else f"http://{u}" for u in urls]
        probs = self.session.run(None, {self.input_name: np.array(full, dtype="str")})[1]
        if isinstance(probs, list):
            return [float(p.get(1, p.get("1", 0.0))) for p in probs]
        return [float(p[1]) for p in np.asarray(probs)]


def load_url_model(models_dir: Path) -> UrlModel | None:
    path = models_dir / URL_DIR_NAME / "model.onnx"
    if not path.exists():
        log.info("URL model not downloaded (%s); link checks use rules only.", path)
        return None
    try:
        return UrlModel(path)
    except Exception as exc:
        log.warning("Could not load URL model: %s", exc)
        return None
