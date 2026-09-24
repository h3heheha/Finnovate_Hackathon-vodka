"""App configuration.

API_URL can be set with the FRAUDLENS_API_URL environment variable, or changed
inside the app (tap the settings icon). Typical values:
  - Laptop demo / desktop:          http://127.0.0.1:8000
  - Android emulator -> your laptop: http://10.0.2.2:8000
  - Real phone on the same Wi-Fi:    http://<your-laptop-LAN-IP>:8000
  - Deployed backend:                https://fraudlens-api.onrender.com  (example)
"""
import os

DEFAULT_API_URL = os.getenv("FRAUDLENS_API_URL", "http://127.0.0.1:8000")
API_PREFIX = "/api/v1"
REQUEST_TIMEOUT = 8.0
APP_NAME = "FraudLens"
TAGLINE = "Spot the warning signs before you pay"

GUARDIAN = {"name": "Ravi (son)", "phone": "+230 5XXX XXXX"}
