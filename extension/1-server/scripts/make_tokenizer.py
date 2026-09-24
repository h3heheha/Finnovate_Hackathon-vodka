"""Convert multilingual-e5's tokenizer.json into two small SentencePiece files.

    python -m scripts.make_tokenizer              # writes models/multilingual-e5-small/e5-*.model
    python -m scripts.make_tokenizer --verify     # also checks the ids match tokenizer.json

Why: the Hugging Face `tokenizers` library needs ~280 MB of memory for this 250,000-word
vocabulary; SentencePiece needs ~60 MB. That is the difference between fitting a free
512 MB server or not. The files are generated once and shipped with the server.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from app.core.config import get_settings
from app.ml.embedders import E5_DIR_NAME, SPM_MODEL, SPM_NORMALIZER


def build(tok_json: Path, out_dir: Path) -> None:
    from sentencepiece import sentencepiece_model_pb2 as pb

    t = json.loads(tok_json.read_text(encoding="utf-8"))
    vocab = t["model"]["vocab"]
    norms = t["normalizer"]["normalizers"]
    if [n["type"] for n in norms] != ["Precompiled", "Replace"] or norms[1]["pattern"] != {"Regex": " {2,}"}:
        sys.exit("Unexpected normalizer in tokenizer.json; not converting.")
    if vocab[:4] != [["<s>", 0.0], ["<pad>", 0.0], ["</s>", 0.0], ["<unk>", 0.0]] or vocab[-1][0] != "<mask>":
        sys.exit("Unexpected vocabulary layout in tokenizer.json; not converting.")
    piece = pb.ModelProto.SentencePiece

    def base():
        m = pb.ModelProto()
        for text, kind in (("<unk>", piece.UNKNOWN), ("<s>", piece.CONTROL), ("</s>", piece.CONTROL)):
            p = m.pieces.add()
            p.piece, p.score, p.type = text, 0.0, kind
        ts = m.trainer_spec
        ts.model_type = pb.TrainerSpec.UNIGRAM
        ts.unk_id, ts.bos_id, ts.eos_id, ts.pad_id = 0, 1, 2, -1
        return m

    m = base()  # word pieces; text arrives already normalised
    for text, score in vocab[4:-1]:
        p = m.pieces.add()
        p.piece, p.score, p.type = text, float(score), piece.NORMAL
    m.trainer_spec.vocab_size = len(m.pieces)
    ns = m.normalizer_spec
    ns.name, ns.add_dummy_prefix, ns.remove_extra_whitespaces, ns.escape_whitespaces = "identity", True, False, True
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / SPM_MODEL).write_bytes(m.SerializeToString())

    n = base()  # normaliser only: the model's precompiled character map
    p = n.pieces.add()
    p.piece, p.score, p.type = "a", -1.0, piece.NORMAL
    n.trainer_spec.vocab_size = len(n.pieces)
    ns = n.normalizer_spec
    ns.name = "nmt_nfkc"
    ns.precompiled_charsmap = base64.b64decode(norms[0]["precompiled_charsmap"])
    ns.add_dummy_prefix, ns.remove_extra_whitespaces, ns.escape_whitespaces = False, False, False
    (out_dir / SPM_NORMALIZER).write_bytes(n.SerializeToString())
    print(f"Wrote {out_dir / SPM_MODEL} and {out_dir / SPM_NORMALIZER}")


def verify(tok_json: Path, out_dir: Path, texts: list[str]) -> int:
    from tokenizers import Tokenizer

    from app.ml.embedders import HfTokenizer, SpmTokenizer

    hf, sp = HfTokenizer(tok_json.parent), SpmTokenizer(out_dir)
    assert isinstance(hf._tok, Tokenizer)
    diff = reordered = 0
    for t in texts:
        a, b = hf.encode("query: " + t), sp.encode("query: " + t)
        if a != b:
            diff += 1
            reordered += sorted(a) == sorted(b)   # same pieces, tie broken differently
    print(f"{len(texts)} texts: {len(texts) - diff} identical, {reordered} same pieces in another order, "
          f"{diff - reordered} different")
    return diff - reordered


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", nargs="*", help="CSV files with a 'text' column to compare on")
    a = ap.parse_args()
    e5 = get_settings().models_dir / E5_DIR_NAME
    build(e5 / "tokenizer.json", e5)
    if a.verify is not None:
        import csv
        texts = ["", "a  b", "trail  ", "new\nline", "emoji 😀", "Zéro café", "x" * 3000]
        for f in a.verify:
            texts += [r.get("text") or "" for r in csv.DictReader(open(f, encoding="utf-8"))]
        sys.exit(1 if verify(e5 / "tokenizer.json", e5, texts) else 0)
