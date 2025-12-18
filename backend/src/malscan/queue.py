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

    Args:
        job_data: Job data containing job_id, file_id, storage_key, sha256, original_filename.

    Raises:
        Exception: If publishing fails after all retries.
    """
    connection = await aio_pika.connect_robust(settings.rabbitmq_url)

    async with connection:
        channel = await connection.channel()

        # Declare queue (idempotent)
        await channel.declare_queue(
            settings.rabbitmq_queue,
            durable=True,
        )

        # Prepare message
        message_body = json.dumps(job_data).encode()
        message = aio_pika.Message(
            body=message_body,
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            content_type="application/json",
        )

        # Publish to default exchange with queue name as routing key
        await channel.default_exchange.publish(
            message,
            routing_key=settings.rabbitmq_queue,
        )

        log.info(
            "job_published",
            job_id=job_data.get("job_id"),
            file_id=job_data.get("file_id"),
            queue=settings.rabbitmq_queue,
        )
