"""Test isolation: every test run uses a temporary data/models folder.

No downloaded models are needed: the ML layer falls back to the hashing embedder,
and test_ml.py builds tiny stand-in ONNX models to exercise the ONNX code paths.
"""
import os
import shutil
import tempfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
_TMP = Path(tempfile.mkdtemp(prefix="fraudlens-tests-"))
shutil.copytree(BACKEND / "data" / "seed", _TMP / "data" / "seed")
(_TMP / "models").mkdir()

os.environ.setdefault("FRAUDLENS_DATA_DIR", str(_TMP / "data"))
os.environ.setdefault("FRAUDLENS_MODELS_DIR", str(_TMP / "models"))
os.environ.setdefault("FRAUDLENS_EMBEDDER", "hashing")
os.environ.setdefault("FRAUDLENS_REPORT_CONFIRMATIONS", "2")
os.environ.setdefault("FRAUDLENS_INTEL_ENABLED", "false")
os.environ.setdefault("FRAUDLENS_RATE_LIMIT_PER_MINUTE", "0")        # test_security.py checks the limiter itself
os.environ.setdefault("FRAUDLENS_ADMIN_TOKEN", "")   # test_intel.py simulates the providers itself
