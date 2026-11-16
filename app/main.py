from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator

from app.routers import enrich, health


def create_app() -> FastAPI:
    application = FastAPI(title="ioc-enricher", version="0.1.0")
    application.include_router(health.router)
    application.include_router(enrich.router)
    Instrumentator(excluded_handlers=["/metrics", "/health"]).instrument(application).expose(
        application, include_in_schema=False
    )
    return application


app = create_app()
