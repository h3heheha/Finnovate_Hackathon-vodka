# FraudLens server for a free cloud host (Render). Fits in 512 MB of memory.
FROM python:3.11-slim

# The phishing-URL maths is in numpy now, but keep a UTF-8 locale for any text tools.
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MALLOC_ARENA_MAX=2 \
    HF_HUB_DISABLE_TELEMETRY=1

# Run as an ordinary user, never as root.
RUN useradd --create-home --uid 1000 fraudlens
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=fraudlens:fraudlens . .
USER fraudlens

# Download the 118 MB multilingual AI model at build time (fails the build loudly if it can't).
RUN python -m scripts.download_models --server && rm -rf /home/fraudlens/.cache/huggingface

# Cloud defaults (Render's dashboard can override any of them):
#  - every API call needs the signed install token that the Chrome extension gets automatically
#  - one ONNX thread: the free instance has a small slice of one CPU
ENV FRAUDLENS_REQUIRE_INSTALL_TOKEN=true \
    FRAUDLENS_ONNX_THREADS=1 \
    PORT=10000
EXPOSE 10000

# X-Forwarded-For is NOT trusted (visitors can fake it). On Render the visitor's address comes from
# Cloudflare's True-Client-IP header instead (see app/core/security.py: client_ip).
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --timeout-keep-alive 30"]
