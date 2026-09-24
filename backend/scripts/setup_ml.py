"""One command to get the ML layer ready on a new machine:

    python -m scripts.setup_ml

1. downloads the pre-trained ONNX models (needs internet once)
2. builds the dataset (curated seed + UCI + any files you added to data/raw)
3. trains, evaluates and promotes the first model version
4. refreshes the mobile app's offline demo cache
"""
import logging

from scripts import build_dataset, download_models, export_demo_cache

if __name__ == "__main__":
    import asyncio

    from app.core.config import get_settings
    from app.ml.training import train

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    print("\n[1/4] Pre-trained models")
    download_models.main()
    print("\n[2/4] Dataset")
    build_dataset.main(download=True, spam_as="drop")
    print("\n[3/4] Training")
    train(get_settings(), force_promote=True)
    print("\n[4/4] Offline demo cache")
    asyncio.run(export_demo_cache.main())
    print("\nAll set. Start the API with: uvicorn app.main:app --host 0.0.0.0 --port 8000")
