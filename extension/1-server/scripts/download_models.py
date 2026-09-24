"""Download the free pre-trained models (needs internet once; afterwards everything runs offline).

    python -m scripts.download_models            # e5 model (118 MB) + anything else that is missing
    python -m scripts.download_models --server   # cloud build: fail loudly if the e5 model can't be fetched

Models:
  * Xenova/multilingual-e5-small      ONNX export of intfloat/multilingual-e5-small (MIT)
  * pirocheto/phishing-url-detection  phishing-URL classifier (MIT); shipped as url_model.npz,
                                      the ONNX original is only needed to rebuild that file

The e5 word-splitter files (e5-tokenizer.model / e5-normalizer.model) and url_model.npz are
shipped with the server, so a normal install only downloads the 118 MB e5 model.
"""
import argparse
import shutil
import sys
import time
from pathlib import Path

from app.core.config import get_settings
from app.ml.embedders import E5_DIR_NAME, SPM_MODEL, SPM_NORMALIZER
from app.ml.url_model import NPZ_NAME, URL_DIR_NAME

E5_REPO = "Xenova/multilingual-e5-small"
URL_REPO = "pirocheto/phishing-url-detection"


def fetch(repo: str, filename: str, dest: Path, tries: int = 3) -> None:
    from huggingface_hub import hf_hub_download

    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        print(f"  ✓ {dest.name} (already there)")
        return
    for attempt in range(1, tries + 1):
        try:
            print(f"  ↓ {repo}/{filename}", flush=True)
            path = hf_hub_download(repo_id=repo, filename=filename)
            shutil.copy(path, dest)
            return
        except Exception as exc:
            if attempt == tries:
                raise
            print(f"    retrying after error: {exc}", flush=True)
            time.sleep(5 * attempt)


def main(server: bool = False) -> bool:
    models = get_settings().models_dir
    print(f"Downloading models into {models}")
    e5 = models / E5_DIR_NAME
    wanted = [(E5_REPO, "onnx/model_quantized.onnx", e5 / "onnx/model_quantized.onnx")]
    if not ((e5 / SPM_MODEL).exists() and (e5 / SPM_NORMALIZER).exists()):
        wanted.append((E5_REPO, "tokenizer.json", e5 / "tokenizer.json"))
    if not (models / URL_DIR_NAME / NPZ_NAME).exists():
        wanted.append((URL_REPO, "model.onnx", models / URL_DIR_NAME / "model.onnx"))
    ok = True
    for repo, name, dest in wanted:
        try:
            fetch(repo, name, dest)
        except Exception as exc:
            ok = False
            print(f"  ! {repo}/{name} failed: {exc}")
    if server and not ok:
        print("Model download failed. On Render: open the service and click Manual Deploy -> Deploy latest commit.")
        sys.exit(1)
    print("Done." if ok else "Some downloads failed: missing layers fall back automatically "
          "(hashing embedder / rule-based link checks). Re-run when you have internet.")
    return ok


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", action="store_true", help="exit with an error if a download fails")
    ap.add_argument("--full", action="store_true", help="(ignored, kept for old instructions)")
    main(ap.parse_args().server)
