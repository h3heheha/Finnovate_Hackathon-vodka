FROM python:3.11-slim
# The pre-trained URL model lower-cases text with an ONNX op that needs the en_US.UTF-8 locale.
RUN apt-get update && apt-get install -y --no-install-recommends locales \
    && sed -i 's/# en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen && locale-gen && rm -rf /var/lib/apt/lists/*
ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY scripts ./scripts
COPY data/seed ./data/seed
# Bring your trained models with you (run scripts.setup_ml locally first), or download at build time:
COPY models ./models
ENV PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
