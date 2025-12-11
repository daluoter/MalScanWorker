"""Prometheus metrics server for worker."""

from aiohttp import web
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# Metrics definitions
job_total = Counter(
    "malscan_job_total",
    "Total jobs by status",
    ["status"],  # queued, scanning, done, failed
)

stage_latency = Histogram(
    "malscan_stage_latency_seconds",
    "Stage execution latency",
    ["stage", "status"],
    buckets=[0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300],
)

queue_depth = Gauge(
    "malscan_queue_depth",
    "Number of pending jobs in queue",
)

worker_active_jobs = Gauge(
    "malscan_worker_active_jobs",
    "Currently processing jobs",
)


async def metrics_handler(request: web.Request) -> web.Response:
    """Prometheus metrics endpoint."""
    return web.Response(
        body=generate_latest(),
        content_type=CONTENT_TYPE_LATEST,
    )


async def health_handler(request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.Response(text="ok")


async def ready_handler(request: web.Request) -> web.Response:
    """Readiness check endpoint."""
    return web.Response(text="ready")


async def start_metrics_server(port: int = 9090) -> web.AppRunner:
    """Start aiohttp server for metrics and health endpoints."""
    app = web.Application()
    app.router.add_get("/metrics", metrics_handler)
    app.router.add_get("/health", health_handler)
    app.router.add_get("/ready", ready_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    return runner
