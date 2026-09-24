@echo off
cd /d "%~dp0mobile"
pip install -q "flet[all]==1.0.0" httpx
flet run %* src/main.py
