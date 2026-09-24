"""Text embedders: turn a message into a vector that captures its meaning.

* E5OnnxEmbedder: multilingual-e5-small exported to ONNX (English, French and
  90+ other languages). Runs on CPU with onnxruntime, no PyTorch needed.
  Files are downloaded by `python -m scripts.download_models`.
* HashingEmbedder: character n-gram hashing. No model file, works anywhere.
  It is the fallback so the app never breaks, and it's robust to spelling variants.

Both return L2-normalised float32 vectors, so cosine similarity = dot product.
"""
from __future__ import annotations

import logging
from pathlib import Path

import numpy as np

log = logging.getLogger("fraudlens.ml")

E5_DIR_NAME = "multilingual-e5-small"
E5_MODEL_CANDIDATES = ("onnx/model_quantized.onnx", "onnx/model_int8.onnx", "onnx/model.onnx", "model.onnx")


class BaseEmbedder:
    id: str = "base"
    dim: int = 0

    def embed(self, texts: list[str], batch_size: int = 32) -> np.ndarray:
        raise NotImplementedError

    def embed_one(self, text: str) -> np.ndarray:
        return self.embed([text])[0]


def _l2(x: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(x, axis=1, keepdims=True)
    return (x / np.clip(norms, 1e-9, None)).astype(np.float32)


class HashingEmbedder(BaseEmbedder):
    """Character 2-4-gram hashing vectoriser. Fast, tiny, no downloads."""

    id = "hashing-v1"

    def __init__(self, n_features: int = 2 ** 14):
        from sklearn.feature_extraction.text import HashingVectorizer

        self.dim = n_features
        self._vec = HashingVectorizer(analyzer="char_wb", ngram_range=(2, 4), n_features=n_features,
                                      alternate_sign=False, norm=None, lowercase=True)

    def embed(self, texts: list[str], batch_size: int = 256) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        m = self._vec.transform(texts)
        m.data = np.log1p(m.data)  # dampen very frequent n-grams
        return _l2(m.toarray().astype(np.float32))


class E5OnnxEmbedder(BaseEmbedder):
    """multilingual-e5-small in ONNX with mean pooling (as recommended by the model authors)."""

    id = "e5-small-onnx"

    def __init__(self, model_dir: Path, threads: int = 2, providers: list[str] | None = None):
        import onnxruntime as ort
        from tokenizers import Tokenizer

        model_path = next((model_dir / c for c in E5_MODEL_CANDIDATES if (model_dir / c).exists()), None)
        if model_path is None:
            raise FileNotFoundError(f"No ONNX model found in {model_dir}")
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = threads
        self.session = ort.InferenceSession(str(model_path), opts,
                                            providers=providers or ["CPUExecutionProvider"])
        self.tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        self.tokenizer.enable_truncation(max_length=256)
        pad_id = self.tokenizer.token_to_id("<pad>")
        self.tokenizer.enable_padding(pad_id=pad_id if pad_id is not None else 0,
                                      pad_token="<pad>" if pad_id is not None else "[PAD]")
        self.input_names = {i.name for i in self.session.get_inputs()}
        self.output_name = self.session.get_outputs()[0].name
        self.model_file = model_path.name
        self.dim = int(self.embed(["dimension probe"]).shape[1])

    def embed(self, texts: list[str], batch_size: int = 32) -> np.ndarray:
        out = []
        for i in range(0, len(texts), batch_size):
            # e5 expects a "query: " prefix for symmetric tasks such as similarity/classification.
            batch = [f"query: {t}" for t in texts[i:i + batch_size]]
            enc = self.tokenizer.encode_batch(batch)
            ids = np.array([e.ids for e in enc], dtype=np.int64)
            mask = np.array([e.attention_mask for e in enc], dtype=np.int64)
            feed = {"input_ids": ids, "attention_mask": mask}
            if "token_type_ids" in self.input_names:
                feed["token_type_ids"] = np.zeros_like(ids)
            feed = {k: v for k, v in feed.items() if k in self.input_names}
            hidden = self.session.run([self.output_name], feed)[0]          # (batch, seq, dim)
            m = mask[..., None].astype(np.float32)
            pooled = (hidden * m).sum(axis=1) / np.clip(m.sum(axis=1), 1e-9, None)
            out.append(pooled)
        if not out:
            return np.zeros((0, self.dim), dtype=np.float32)
        return _l2(np.concatenate(out).astype(np.float32))


def load_embedder(choice: str, models_dir: Path, threads: int = 2) -> BaseEmbedder:
    """'auto' → e5 if its files exist, else hashing. Never raises for 'auto'."""
    e5_dir = models_dir / E5_DIR_NAME
    if choice in ("auto", "e5"):
        try:
            emb = E5OnnxEmbedder(e5_dir, threads=threads)
            log.info("Embedder: %s (%s, dim=%d)", emb.id, emb.model_file, emb.dim)
            return emb
        except Exception as exc:  # missing files or runtime problem
            if choice == "e5":
                raise
            log.warning("e5 ONNX model not available (%s); using hashing embedder. "
                        "Run `python -m scripts.setup_ml` to download it.", exc)
    return HashingEmbedder()
