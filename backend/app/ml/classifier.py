"""Scam classifier: logistic regression on message embeddings, served as ONNX.

Training uses scikit-learn (seconds, even on a laptop). The trained model is
exported to ONNX with skl2onnx and served with onnxruntime, so the API never
depends on the training library's pickles.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np

INPUT_NAME = "embedding"


class OnnxClassifier:
    def __init__(self, path: Path, threads: int = 1):
        import onnxruntime as ort

        opts = ort.SessionOptions()
        opts.intra_op_num_threads = threads
        self.session = ort.InferenceSession(str(path), opts, providers=["CPUExecutionProvider"])
        self.input_name = self.session.get_inputs()[0].name
        self.dim = self.session.get_inputs()[0].shape[1]

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Probability that each row is a scam."""
        out = self.session.run(None, {self.input_name: X.astype(np.float32)})
        return _scam_column(out[1])


def _scam_column(probs) -> np.ndarray:
    # skl2onnx returns either an array (zipmap disabled) or a list of {label: p} dicts.
    if isinstance(probs, list):
        return np.array([p.get(1, p.get("1", 0.0)) for p in probs], dtype=np.float32)
    return np.asarray(probs)[:, 1].astype(np.float32)


def train_classifier(X: np.ndarray, y: np.ndarray, sample_weight: np.ndarray | None = None, C: float = 4.0):
    from sklearn.linear_model import LogisticRegression

    clf = LogisticRegression(C=C, max_iter=2000, class_weight="balanced")
    clf.fit(X, y, sample_weight=sample_weight)
    return clf


def export_onnx(clf, dim: int, path: Path) -> None:
    from skl2onnx import to_onnx
    from skl2onnx.common.data_types import FloatTensorType

    onx = to_onnx(clf, initial_types=[(INPUT_NAME, FloatTensorType([None, dim]))],
                  options={id(clf): {"zipmap": False}}, target_opset=17)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(onx.SerializeToString())
