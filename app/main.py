import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from prometheus_fastapi_instrumentator import Instrumentator

from app import __version__
from app.config import Settings, get_settings
from app.logging_config import request_id_var, setup_logging
from app.routers import enrich, health
from app.services.cache import build_backend
from app.services.enricher import Enricher
from app.services.sources import SourceContext

STATIC_DIR = Path(__file__).resolve().parent / "static"
# Strict CSP for the demo UI; Swagger UI (/docs) loads its assets from a CDN.
UI_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)

DESCRIPTION = """
Enrich Indicators of Compromise (IP, domain, URL, file hash) from several
threat-intel feeds in parallel and get **one explainable verdict**.

Sources: local feed/allowlist, AbuseIPDB, VirusTotal, AlienVault OTX, URLhaus, ThreatFox.
Providers without an API key configured are skipped.
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    setup_logging(settings.log_level)
    cache = build_backend(settings.redis_url)
    async with httpx.AsyncClient(
        timeout=settings.timeout,
        headers={"User-Agent": f"ioc-enricher/{__version__}"},
        follow_redirects=False,
    ) as http:
        app.state.cache = cache
        app.state.enricher = Enricher(settings, SourceContext(settings, http), cache)
        try:
            yield
        finally:
            await cache.close()


def create_app(settings: Settings | None = None) -> FastAPI:
    application = FastAPI(
        title="ioc-enricher", version=__version__, description=DESCRIPTION, lifespan=lifespan
    )
    application.state.settings = settings or get_settings()
    if settings is not None:  # explicit settings (tests, embedding) win over env
        application.dependency_overrides[get_settings] = lambda: settings

    @application.middleware("http")
    async def request_context(request: Request, call_next):
        rid = request.headers.get("X-Request-ID", "")
        if not rid or len(rid) > 64 or not rid.replace("-", "").isalnum():
            rid = uuid.uuid4().hex
        token = request_id_var.set(rid)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        if not request.url.path.startswith(("/docs", "/redoc")):
            response.headers["Content-Security-Policy"] = UI_CSP
            response.headers["X-Frame-Options"] = "DENY"
        return response

    @application.get("/", include_in_schema=False)
    async def ui() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    application.include_router(health.router)
    application.include_router(enrich.router)
    Instrumentator(excluded_handlers=["/metrics", "/health", "/ready"]).instrument(
        application
    ).expose(application, include_in_schema=False)
    return application


app = create_app()
