"""Text embedders: turn a message into a vector that captures its meaning.

* E5OnnxEmbedder: multilingual-e5-small exported to ONNX (English, French and
  90+ other languages). Runs on CPU with onnxruntime, no PyTorch needed.
  Files are downloaded by `python -m scripts.download_models`.
  Words are split with SentencePiece (e5-tokenizer.model + e5-normalizer.model, ~60 MB in memory)
  when those files exist, otherwise with the Hugging Face tokenizer.json (~280 MB in memory).
  Both give the same token ids (checked on 13,709 messages by scripts/make_tokenizer.py), so the
  server fits a free 512 MB host.
* HashingEmbedder: character n-gram hashing. No model file, works anywhere.
  It is the fallback so the app never breaks, and it's robust to spelling variants.

Both return L2-normalised float32 vectors, so cosine similarity = dot product.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

import numpy as np

log = logging.getLogger("fraudlens.ml")

E5_DIR_NAME = "multilingual-e5-small"
E5_MODEL_CANDIDATES = ("onnx/model_quantized.onnx", "onnx/model_int8.onnx", "onnx/model.onnx", "model.onnx")
SPM_MODEL = "e5-tokenizer.model"       # SentencePiece pieces (identity normalisation)
SPM_NORMALIZER = "e5-normalizer.model"  # the model's own character map (NFKC, whitespace, control chars)
MAX_TOKENS = 256                        # including <s> and </s>
BOS, PAD, EOS, UNK = 0, 1, 2, 3         # XLM-R ids


class SpmTokenizer:
    """Same ids as the Hugging Face tokenizer.json of multilingual-e5, at a fraction of the memory.

    HF pipeline: precompiled char map -> collapse runs of spaces -> Metaspace -> Unigram -> <s> ... </s>.
    Here: SentencePieceNormalizer (same char map) -> collapse spaces -> SentencePiece Unigram with
    identity normalisation. SentencePiece ids are shifted by one (fairseq offset): spm 0 (<unk>) -> 3.
    """

    def __init__(self, model_dir: Path):
        import sentencepiece as spm

        self._norm = spm.SentencePieceNormalizer(model_file=str(model_dir / SPM_NORMALIZER))
        self._sp = spm.SentencePieceProcessor(model_file=str(model_dir / SPM_MODEL))

    def encode(self, text: str) -> list[int]:
        s = re.sub(" {2,}", " ", self._norm.normalize(text))
        ids = [UNK if i == 0 else i + 1 for i in self._sp.encode(s)]
        return [BOS] + ids[: MAX_TOKENS - 2] + [EOS]


class HfTokenizer:
    def __init__(self, model_dir: Path):
        from tokenizers import Tokenizer

        self._tok = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        self._tok.enable_truncation(max_length=MAX_TOKENS)
        pad = self._tok.token_to_id("<pad>")
        self.pad_id = pad if pad is not None else 0

    def encode(self, text: str) -> list[int]:
        return self._tok.encode(text).ids


def load_tokenizer(model_dir: Path):
    if (model_dir / SPM_MODEL).exists() and (model_dir / SPM_NORMALIZER).exists():
        try:
            return SpmTokenizer(model_dir)
        except ImportError:
            log.warning("sentencepiece is not installed; using tokenizer.json (uses more memory)")
    return HfTokenizer(model_dir)


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

        model_path = next((model_dir / c for c in E5_MODEL_CANDIDATES if (model_dir / c).exists()), None)
        if model_path is None:
            raise FileNotFoundError(f"No ONNX model found in {model_dir}")
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = threads
        opts.inter_op_num_threads = 1
        opts.enable_cpu_mem_arena = False   # small hosts: give memory back after each request
        self.session = ort.InferenceSession(str(model_path), opts,
                                            providers=providers or ["CPUExecutionProvider"])
        self.tokenizer = load_tokenizer(model_dir)
        self.pad_id = getattr(self.tokenizer, "pad_id", PAD)
        self.input_names = {i.name for i in self.session.get_inputs()}
        self.output_name = self.session.get_outputs()[0].name
        self.model_file = model_path.name
        self.tokenizer_kind = type(self.tokenizer).__name__
        self.dim = int(self.embed(["dimension probe"]).shape[1])

    def embed(self, texts: list[str], batch_size: int = 32) -> np.ndarray:
        out = []
        for i in range(0, len(texts), batch_size):
            # e5 expects a "query: " prefix for symmetric tasks such as similarity/classification.
            batch = [f"query: {t}" for t in texts[i:i + batch_size]]
            enc = [self.tokenizer.encode(t) for t in batch]
            width = max(len(e) for e in enc)
            ids = np.full((len(enc), width), self.pad_id, dtype=np.int64)
            mask = np.zeros((len(enc), width), dtype=np.int64)
            for r, e in enumerate(enc):
                ids[r, :len(e)] = e
                mask[r, :len(e)] = 1
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
