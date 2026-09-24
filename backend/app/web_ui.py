"""Serve the FraudLens app (mobile/src, a Flet app) from this backend.

One server, one port: the API stays at /api/v1, /health and /docs, and the app is at /app
(the root URL / redirects there). Open http://localhost:8000/ in any browser, on the laptop or on a
phone on the same Wi-Fi.

The app's Python code runs inside this server process, and the browser only draws the interface.
The app calls this server's own API over HTTP, so it works exactly like the standalone mobile app,
including the offline demo fallback.

Turn it off with FRAUDLENS_WEB_UI=false (API only). If Flet isn't installed, the API still starts
and a log line explains how to add the app.
"""
from __future__ import annotations

import importlib.util
import logging
import os
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

log = logging.getLogger("fraudlens.web_ui")

MOUNT_PATH = "/app"
# backend/app/web_ui.py -> repo root -> mobile/src
MOBILE_SRC = Path(__file__).resolve().parents[2] / "mobile" / "src"


def _enabled() -> bool:
    return os.getenv("FRAUDLENS_WEB_UI", "true").strip().lower() not in ("0", "false", "no", "off")


def _load_mobile_main():
    """Import mobile/src/main.py under a private name, so it can't clash with backend modules."""
    src = str(MOBILE_SRC)
    if src not in sys.path:
        sys.path.append(src)  # the app imports its own modules: theme, views, services, ...
    spec = importlib.util.spec_from_file_location("fraudlens_mobile_main", MOBILE_SRC / "main.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.main


def mount_web_ui(app: FastAPI) -> bool:
    """Mount the app at /app and redirect / to it. Returns True when the app is being served."""
    if not _enabled():
        log.info("Web app disabled (FRAUDLENS_WEB_UI=false); serving the API only.")
        return False
    if not (MOBILE_SRC / "main.py").exists():
        log.warning("Web app not found at %s; serving the API only.", MOBILE_SRC)
        return False
    try:
        import flet_web.fastapi as flet_fastapi
    except ImportError:
        log.warning("Web app needs Flet: pip install flet==1.0.0 flet-web==1.0.0. Serving the API only for now.")
        return False

    # The app talks to this same server unless FRAUDLENS_API_URL says otherwise.
    port = os.getenv("PORT", "8000")
    os.environ.setdefault("FRAUDLENS_API_URL", f"http://127.0.0.1:{port}")

    try:
        main = _load_mobile_main()
    except Exception:  # never let the UI stop the API from starting
        log.exception("Couldn't load the web app; serving the API only.")
        return False

    app.mount(MOUNT_PATH, flet_fastapi.app(
        main,
        assets_dir=str(MOBILE_SRC / "assets"),
        app_name="FraudLens",
        app_short_name="FraudLens",
        app_description="Spot the warning signs before you pay",
        no_cdn=True,  # everything served from this laptop: works on hackathon Wi-Fi with no internet
    ))

    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        return RedirectResponse(url=MOUNT_PATH + "/")

    @app.on_event("startup")
    async def _start_flet() -> None:
        # Mounted sub-apps don't get their own start-up event, so start Flet's session manager here.
        await flet_fastapi.app_manager.start()

    @app.on_event("shutdown")
    async def _stop_flet() -> None:
        await flet_fastapi.app_manager.shutdown()

    log.info("FraudLens app served at %s (API at /api/v1, docs at /docs).", MOUNT_PATH)
    return True
