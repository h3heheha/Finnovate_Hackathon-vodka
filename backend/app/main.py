"""FraudLens AI backend.

Run locally:
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
The app (mobile/src, served by this backend): http://localhost:8000/   (redirects to /app)
Interactive docs: http://localhost:8000/docs
"""
import asyncio

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import logging

from .api.deps import get_analyzer, get_intel, get_ml
from .api.security import RateLimitMiddleware, SecurityHeadersMiddleware
from .api.routes import analyze, content, intel, learning, payments
from .core.config import get_settings
from .web_ui import mount_web_ui


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description="Spot the warning signs before you pay. Hybrid rules + AI scam analysis, "
                    "explanations, and Pause-Before-Pay payment checks.",
    )
    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["GET", "POST"],
                           allow_headers=["Content-Type", "X-Admin-Token"])
    app.add_middleware(RateLimitMiddleware, api_prefix=settings.api_prefix,
                       per_minute=settings.rate_limit_per_minute)
    app.add_middleware(SecurityHeadersMiddleware)
    from .services.store import store
    store.strict_sources = settings.report_confirmations >= 2

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    @app.on_event("startup")
    async def warm_up() -> None:
        get_analyzer()  # load models once at start-up, not on the first request
        intel_svc = get_intel()
        if intel_svc is not None:
            asyncio.create_task(intel_svc.warm_up())  # RDAP directory, in the background

    @app.get("/health", tags=["System"])
    async def health() -> dict:
        analyzer = get_analyzer()
        ml, intel_svc = get_ml(), get_intel()
        return {"status": "ok", "version": settings.version, "ai_provider": analyzer.ai.name,
                "ml": ml.status() if ml else None, "intel": intel_svc.status() if intel_svc else None}

    for router in (analyze.router, payments.router, content.router, learning.router, intel.router):
        app.include_router(router, prefix=settings.api_prefix)
    mount_web_ui(app)  # last, so the API routes always win
    return app


app = create_app()
