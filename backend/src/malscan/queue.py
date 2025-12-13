"""RabbitMQ publisher for job queue operations."""

import json
from typing import Any

import aio_pika
import structlog

from malscan.config import get_settings

log = structlog.get_logger()
settings = get_settings()

# Connection retry settings
MAX_RETRIES = 3
RETRY_DELAY = 1  # seconds


async def publish_job(job_data: dict[str, Any]) -> None:
    """Publish a job message to RabbitMQ.

    Args:
        job_data: Job data containing job_id, file_id, storage_key, sha256, original_filename.

    Raises:
        Exception: If publishing fails after retries.
    """
    connection = None
    last_error = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
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
                return

        except Exception as e:
            last_error = e
            log.warning(
                "rabbitmq_publish_retry",
                attempt=attempt,
                max_retries=MAX_RETRIES,
                error=str(e),
            )
            if attempt < MAX_RETRIES:
                import asyncio
                await asyncio.sleep(RETRY_DELAY)

    log.error(
        "rabbitmq_publish_failed",
        job_id=job_data.get("job_id"),
        error=str(last_error),
    )
    raise last_error  # type: ignore
