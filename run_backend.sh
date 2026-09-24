#!/bin/bash
# Start FraudLens (API + app) on port 8000, reachable from phones on the same Wi-Fi.
cd "$(dirname "$0")/backend"
pip install -q -r requirements.txt
echo "FraudLens: open http://localhost:8000/ (app) or http://localhost:8000/docs (API)"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
