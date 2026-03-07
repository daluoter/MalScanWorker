"""RabbitMQ publisher for job queue operations."""

import json
import logging
from typing import Any

import aio_pika
import structlog
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from malscan.config import get_settings

log = structlog.get_logger()
settings = get_settings()

# Get standard logging logger for tenacity before_sleep_log
_logger = logging.getLogger(__name__)

# RabbitMQ singleton connection and channel
_connection: aio_pika.abc.AbstractRobustConnection | None = None
_channel: aio_pika.abc.AbstractChannel | None = None


async def init_rabbitmq() -> None:
    """Initialize persistent RabbitMQ connection and channel."""
    global _connection, _channel

    if _connection is not None and not _connection.is_closed:
        log.info("rabbitmq_already_initialized")
        return

    try:
        _connection = await aio_pika.connect_robust(settings.rabbitmq_url)
        _channel = await _connection.channel()

        # Declare queue (idempotent) - must match worker's configuration
        await _channel.declare_queue(
            settings.rabbitmq_queue,
            durable=True,
            arguments={
                "x-dead-letter-exchange": "",
                "x-dead-letter-routing-key": "malscan-dlq",
            },
        )

        log.info("rabbitmq_initialized")
    except Exception as e:
        log.error("rabbitmq_initialization_failed", error=str(e))
        raise


async def close_rabbitmq() -> None:
    """Close RabbitMQ connection and channel."""
    global _connection, _channel

    try:
        if _channel is not None and not _channel.is_closed:
            await _channel.close()
            _channel = None

        if _connection is not None and not _connection.is_closed:
            await _connection.close()
            _connection = None

        log.info("rabbitmq_closed")
    except Exception as e:
        log.error("rabbitmq_close_failed", error=str(e))


def is_rabbitmq_initialized() -> bool:
    """Check if RabbitMQ connection is initialized."""
    return _connection is not None and not _connection.is_closed


def _log_retry_failure(retry_state: Any) -> None:
    """Log final failure after all retries exhausted."""
    log.error(
        "rabbitmq_publish_failed",
        attempts=retry_state.attempt_number,
        error=str(retry_state.outcome.exception()),
    )


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=16),
    before_sleep=before_sleep_log(_logger, logging.WARNING),
    retry=retry_if_exception_type(Exception),
    retry_error_callback=_log_retry_failure,
    reraise=True,
)
async def publish_job(job_data: dict[str, Any]) -> None:
    """Publish a job message to RabbitMQ.

    Uses exponential backoff retry strategy:
    - Maximum 5 attempts
    - Wait times: 1s -> 2s -> 4s -> 8s -> 16s
    - Total maximum wait: ~31 seconds

    Uses persistent singleton connection/channel initialized at startup.

    Args:
        job_data: Job data containing job_id, file_id, storage_key, sha256, original_filename.

    Raises:
        Exception: If publishing fails after all retries.
        RuntimeError: If RabbitMQ is not initialized.
    """
    if not is_rabbitmq_initialized():
        raise RuntimeError("RabbitMQ is not initialized. Call init_rabbitmq() first.")

    # Prepare message
    message_body = json.dumps(job_data).encode()
    message = aio_pika.Message(
        body=message_body,
        delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        content_type="application/json",
    )

    # Publish to default exchange with queue name as routing key
    await _channel.default_exchange.publish(
        message,
        routing_key=settings.rabbitmq_queue,
    )

    log.info(
        "job_published",
        job_id=job_data.get("job_id"),
        file_id=job_data.get("file_id"),
        queue=settings.rabbitmq_queue,
    )
