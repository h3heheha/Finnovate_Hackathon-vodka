@echo off
cd /d "%~dp0backend"
pip install -q -r requirements.txt
echo FraudLens: open http://localhost:8000/ (app) or http://localhost:8000/docs (API)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
