#!/bin/bash
# Start the FraudLens mobile app. Pass --web to open it in a browser.
cd "$(dirname "$0")/mobile"
pip install -q "flet[all]==1.0.0" httpx
flet run "$@" src/main.py
