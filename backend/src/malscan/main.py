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

# Increase max request body size for file uploads (50MB)
MAX_REQUEST_BODY_SIZE = 50 * 1024 * 1024  # 50MB

app = FastAPI(
    title="MalScan API",
    description="惡意檔案分析 Pipeline API",
    version="0.1.0",
)

# CORS
if settings.cors_origins == "*":
    cors_origins = ["*"]
else:
    cors_origins = [origin.strip() for origin in settings.cors_origins.split(",")]

# Prometheus metrics (add BEFORE CORS so CORS middleware runs first)
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# CORS middleware (added last = runs first in middleware chain)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,  # Must be False when allow_origins is ["*"]
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,  # Cache preflight for 10 minutes
)

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

    # Auto-create database tables if they don't exist
    from malscan.db.engine import get_engine
    from malscan.models import Base

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    log.info("database_tables_ready")


@app.on_event("shutdown")
async def shutdown_event() -> None:
    """Application shutdown."""
    log.info("application_shutdown")
