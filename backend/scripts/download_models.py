"""Download the free pre-trained models (needs internet once; afterwards everything runs offline).

    python -m scripts.download_models            # laptop: int8-quantised e5 (118 MB) + URL model
    python -m scripts.download_models --full     # also the fp32 e5 model (470 MB)

Models:
  * Xenova/multilingual-e5-small   ONNX export of intfloat/multilingual-e5-small (MIT)
  * pirocheto/phishing-url-detection  ONNX phishing-URL classifier (MIT)
"""
import argparse
import shutil
from pathlib import Path

from app.core.config import get_settings
from app.ml.embedders import E5_DIR_NAME
from app.ml.url_model import URL_DIR_NAME

E5_REPO = "Xenova/multilingual-e5-small"
URL_REPO = "pirocheto/phishing-url-detection"


def fetch(repo: str, filename: str, dest: Path) -> None:
    from huggingface_hub import hf_hub_download

    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        print(f"  ✓ {dest.relative_to(dest.parents[2])} (already there)")
        return
    print(f"  ↓ {repo}/{filename}")
    path = hf_hub_download(repo_id=repo, filename=filename)
    shutil.copy(path, dest)


def main(full: bool = False) -> bool:
    """Returns True when every model is in place. Each file is tried independently."""
    models = get_settings().models_dir
    print(f"Downloading models into {models}")
    e5 = models / E5_DIR_NAME
    wanted = [(E5_REPO, "tokenizer.json", e5 / "tokenizer.json"),
              (E5_REPO, "onnx/model_quantized.onnx", e5 / "onnx/model_quantized.onnx"),
              (URL_REPO, "model.onnx", models / URL_DIR_NAME / "model.onnx")]
    if full:
        wanted.append((E5_REPO, "onnx/model.onnx", e5 / "onnx/model.onnx"))
    ok = True
    for repo, name, dest in wanted:
        try:
            fetch(repo, name, dest)
        except Exception as exc:
            ok = False
            print(f"  ! {repo}/{name} failed: {exc}")
    print("Done." if ok else "Some downloads failed: missing layers fall back automatically "
          "(hashing embedder / rule-based link checks). Re-run when you have internet.")
    return ok


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="also download the full-precision e5 model")
    main(ap.parse_args().full)
