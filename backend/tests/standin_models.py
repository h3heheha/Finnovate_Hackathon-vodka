"""Build tiny stand-in ONNX models with the SAME interfaces as the real downloads.

They let the tests exercise the real ONNX code paths (tokenizer.json + e5-shaped
transformer, string-input URL model) without downloading anything. They are NOT
useful models: the embedding is random, so similarity between different wordings
means nothing. Usage: python tests/standin_models.py <models_dir> <seed_csv>
"""
import csv, sys, numpy as np, onnx
from onnx import helper, TensorProto, numpy_helper
from pathlib import Path
from tokenizers import Tokenizer, models, trainers, pre_tokenizers, processors

def build(out: Path, seed_csv: Path) -> None:
    texts = [r["text"] for r in csv.DictReader(open(seed_csv, encoding="utf-8"))]
    _build(out, texts)


def _build(out, texts):
    e5 = out / "multilingual-e5-small"; (e5 / "onnx").mkdir(parents=True, exist_ok=True)

    # Tokenizer shaped like XLM-R (<s>=0, <pad>=1, </s>=2, <unk>=3)
    tok = Tokenizer(models.BPE(unk_token="<unk>"))
    tok.pre_tokenizer = pre_tokenizers.Metaspace()
    tr = trainers.BpeTrainer(vocab_size=2000, special_tokens=["<s>", "<pad>", "</s>", "<unk>"])
    tok.train_from_iterator(texts * 3, tr)
    tok.post_processor = processors.TemplateProcessing(single="<s> $A </s>", special_tokens=[("<s>", 0), ("</s>", 2)])
    tok.save(str(e5 / "tokenizer.json"))
    V, D = tok.get_vocab_size(), 384

    # Transformer stand-in: embedding lookup + small mixing, output 'last_hidden_state' [B, S, 384]
    rng = np.random.default_rng(0)
    emb = numpy_helper.from_array(rng.normal(size=(V, D)).astype(np.float32), "emb")
    w = numpy_helper.from_array((np.eye(D) + 0.1 * rng.normal(size=(D, D))).astype(np.float32), "w")
    nodes = [
        helper.make_node("Gather", ["emb", "input_ids"], ["h0"], axis=0),
        helper.make_node("MatMul", ["h0", "w"], ["h1"]),
        helper.make_node("Tanh", ["h1"], ["last_hidden_state"]),
        # consume attention_mask + token_type_ids so they are real graph inputs like in BERT exports
        helper.make_node("Cast", ["attention_mask"], ["m"], to=TensorProto.FLOAT),
        helper.make_node("Cast", ["token_type_ids"], ["t"], to=TensorProto.FLOAT),
        helper.make_node("Add", ["m", "t"], ["unused"]),
    ]
    g = helper.make_graph(nodes, "e5_standin",
        [helper.make_tensor_value_info(n, TensorProto.INT64, ["batch", "seq"]) for n in ("input_ids", "attention_mask", "token_type_ids")],
        [helper.make_tensor_value_info("last_hidden_state", TensorProto.FLOAT, ["batch", "seq", D]),
         helper.make_tensor_value_info("unused", TensorProto.FLOAT, ["batch", "seq"])],
        [emb, w])
    m = helper.make_model(g, opset_imports=[helper.make_opsetid("", 17)]); m.ir_version = 8
    onnx.checker.check_model(m); onnx.save(m, str(e5 / "onnx" / "model_quantized.onnx"))

    # URL model stand-in: string input 'inputs', output[1] probabilities (zipmap like skl2onnx default)
    from sklearn.pipeline import Pipeline
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from skl2onnx import to_onnx
    from skl2onnx.common.data_types import StringTensorType
    urls = ["https://www.mcb.mu/personal", "https://www.google.com", "https://www.bbc.co.uk/news", "https://www.dhl.com/track",
            "https://en.wikipedia.org/wiki/Mauritius", "https://www.gov.mu", "https://github.com/login",
            "http://mcb-secure-verify.com/login", "http://sbm-mu.info/confirm", "https://bit.ly/mupost-fee",
            "http://paypal-account-verify.xyz/signin", "http://192.168.1.20/bank/login", "http://secure-update-login.top/verify",
            "http://mra-refund.info/claim"]
    y = [0] * 7 + [1] * 7
    pipe = Pipeline([("tfidf", TfidfVectorizer(token_pattern=r"[A-Za-z0-9]+")), ("lr", LogisticRegression())]).fit(urls, y)
    onx = to_onnx(pipe, initial_types=[("inputs", StringTensorType([None]))], target_opset=17)
    (out / "phishing-url-detection").mkdir(parents=True, exist_ok=True)
    (out / "phishing-url-detection" / "model.onnx").write_bytes(onx.SerializeToString())
    print("stand-ins written to", out, "vocab", V)


if __name__ == "__main__":
    build(Path(sys.argv[1]), Path(sys.argv[2]))
