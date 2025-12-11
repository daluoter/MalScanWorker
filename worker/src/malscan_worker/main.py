"""Worker main entry point."""

import asyncio
import signal
import sys

import structlog

from malscan_worker.config import get_settings
from malscan_worker.consumer import start_consumer
from malscan_worker.metrics import start_metrics_server

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)

log = structlog.get_logger()
settings = get_settings()

# Shutdown flag
shutdown_event = asyncio.Event()


def handle_shutdown(signum: int, frame: object) -> None:
    """Handle shutdown signals."""
    log.info("shutdown_signal_received", signal=signum)
    shutdown_event.set()


async def main() -> None:
    """Main entry point."""
    log.info(
        "worker_starting",
        rabbitmq_queue=settings.rabbitmq_queue,
        metrics_port=settings.metrics_port,
    )

    # Start metrics server
    metrics_runner = await start_metrics_server(port=settings.metrics_port)
    log.info("metrics_server_started", port=settings.metrics_port)

    try:
        # Start RabbitMQ consumer
        await start_consumer(shutdown_event)
    except Exception as e:
        log.error("worker_error", error=str(e))
        raise
    finally:
        # Cleanup
        await metrics_runner.cleanup()
        log.info("worker_shutdown_complete")


if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("worker_interrupted")
        sys.exit(0)
