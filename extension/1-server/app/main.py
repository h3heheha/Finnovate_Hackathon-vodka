"""FraudLens AI backend.

Free cloud server (Render): see render.yaml and START HERE.md.
On this computer:  uvicorn app.main:app --host 127.0.0.1 --port 8000
Interactive docs: /docs · practice pages for the Chrome extension: /demo/
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api.deps import get_analyzer, get_intel, get_ml
from .api.routes import analyze, content, extension, intel, learning, payments, status
from .core.config import LOCAL_ORIGIN_REGEX, get_settings
from .core.security import TOKEN_HEADER, SecurityMiddleware

STATIC = Path(__file__).resolve().parent / "static"


def _quiet_http_logs() -> None:
    """httpx logs every request URL at INFO, and some providers put the API key in the URL
    (Safe Browsing ?key=, IPQS /phone/<key>/). Keep those lines off the console."""
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    _quiet_http_logs()
    log = logging.getLogger("fraudlens")
    if not settings.admin_enabled:
        log.warning("Admin endpoints are LOCKED (FRAUDLENS_ADMIN_TOKEN is empty or weak).")

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        analyzer = get_analyzer()  # load the models once at start-up, not on the first request
        log.info("AI provider: %s", analyzer.ai.name)
        tasks = []
        intel_svc = get_intel()
        if intel_svc is not None:
            tasks.append(asyncio.create_task(intel_svc.warm_up()))        # RDAP directory
            tasks.append(asyncio.create_task(intel_svc.openphish_loop()))  # live phishing list
        yield
        for t in tasks:
            t.cancel()

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description="Spot the warning signs before you pay. Hybrid rules + AI scam analysis, "
                    "explanations, and Pause-Before-Pay payment checks.",
        lifespan=lifespan,
    )
    # Order matters: the last middleware added runs first. CORS answers preflights,
    # then the security layer checks origin, identity and rate limits.
    app.add_middleware(SecurityMiddleware)
    app.add_middleware(
        CORSMiddleware, allow_origins=settings.allowed_origins, allow_origin_regex=LOCAL_ORIGIN_REGEX,
        allow_methods=["GET", "POST"], allow_headers=["Content-Type", TOKEN_HEADER, "X-Admin-Token"],
    )

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if not request.url.path.startswith("/docs"):
            response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    @app.get("/health", tags=["System"])
    async def health() -> dict:
        analyzer = get_analyzer()
        ml, intel_svc = get_ml(), get_intel()
        return {"status": "ok", "version": settings.version, "ai_provider": analyzer.ai.name,
                "ml": ml.status() if ml else None, "intel": intel_svc.status() if intel_svc else None,
                "pause_cooldown_seconds": settings.pause_cooldown_seconds,
                "demo_pages": settings.demo_pages, "install_token_required": settings.require_install_token}

    @app.get("/", include_in_schema=False)
    async def home():
        return FileResponse(STATIC / "index.html")

    if settings.demo_pages:
        app.mount("/demo", StaticFiles(directory=STATIC / "demo", html=True), name="demo")

    for router in (analyze.router, payments.router, content.router, learning.router, intel.router,
                   extension.router, status.router):
        app.include_router(router, prefix=settings.api_prefix)
    return app


app = create_app()
