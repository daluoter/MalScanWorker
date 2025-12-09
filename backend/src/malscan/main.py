"""FastAPI application entry point."""

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from malscan.api.routes import router
from malscan.config import get_settings

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)

settings = get_settings()
log = structlog.get_logger()

app = FastAPI(
    title="MalScan API",
    description="惡意檔案分析 Pipeline API",
    version="0.1.0",
)

# CORS
cors_origins = [origin.strip() for origin in settings.cors_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Prometheus metrics
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# Routes
app.include_router(router, prefix="/api/v1")


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/ready")
async def readiness_check() -> dict[str, str]:
    """Readiness check endpoint."""
    # TODO: 檢查資料庫連線、MinIO、RabbitMQ
    return {"status": "ready"}


@app.on_event("startup")
async def startup_event() -> None:
    """Application startup."""
    log.info("application_startup", cors_origins=cors_origins)


@app.on_event("shutdown")
async def shutdown_event() -> None:
    """Application shutdown."""
    log.info("application_shutdown")
