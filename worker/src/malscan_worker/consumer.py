"""RabbitMQ consumer for processing jobs with retry and DLQ support."""

import asyncio
import json
import logging

import aio_pika
import structlog
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_fixed,
)

from malscan_worker.config import get_settings
from malscan_worker.db import update_job_status
from malscan_worker.metrics import job_total, worker_active_jobs
from malscan_worker.pipeline import run_pipeline

log = structlog.get_logger()
settings = get_settings()

# Get standard logging logger for tenacity before_sleep_log
_logger = logging.getLogger(__name__)

# Connection retry settings - allow 15 minutes for RabbitMQ to be ready
MAX_CONNECTION_RETRIES = 90
RETRY_DELAY = 10  # seconds

# Message processing settings
DLQ_QUEUE = "malscan-dlq"
MAX_MESSAGE_RETRIES = 3


def _get_retry_count(message: aio_pika.abc.AbstractIncomingMessage) -> int:
    """Extract retry count from message x-death header.

    RabbitMQ adds x-death header when a message is dead-lettered.
    Each entry in the array represents a dead-letter event with a count.

    Args:
        message: The incoming RabbitMQ message.

    Returns:
        Total number of times this message has been retried.
    """
    headers = message.headers or {}
    x_death = headers.get("x-death")

    if not x_death or not isinstance(x_death, list):
        return 0

    # x-death is a list of dicts, each with a 'count' field
    total_count = 0
    for entry in x_death:
        if isinstance(entry, dict):
            count = entry.get("count", 0)
            if isinstance(count, int):
                total_count += count

    return total_count


async def process_message(message: aio_pika.abc.AbstractIncomingMessage) -> None:
    """Process a single job message with retry tracking.

    If processing fails and retry count < MAX_MESSAGE_RETRIES, the message
    is rejected with requeue=True for another attempt.
    If retry count >= MAX_MESSAGE_RETRIES, the message is rejected with
    requeue=False, causing it to be routed to the DLQ.
    """
    job_id = None
    file_id = None
    retry_count = _get_retry_count(message)

    try:
        # Parse message
        body = json.loads(message.body.decode())
        job_id = body.get("job_id")
        file_id = body.get("file_id")

        log.info(
            "job_received",
            job_id=job_id,
            file_id=file_id,
            retry_count=retry_count,
        )

        worker_active_jobs.inc()
        job_total.labels(status="scanning").inc()

        # Update job status to scanning
        if job_id:
            await update_job_status(job_id, "scanning")

        try:
            # Run the analysis pipeline
            await run_pipeline(body)
            job_total.labels(status="done").inc()

            # Acknowledge successful processing
            await message.ack()

        except Exception as e:
            log.error(
                "job_failed",
                job_id=job_id,
                file_id=file_id,
                error=str(e),
                retry_count=retry_count,
            )
            job_total.labels(status="failed").inc()

            # Check if we should retry or send to DLQ
            if retry_count < MAX_MESSAGE_RETRIES:
                log.warning(
                    "job_retry_scheduled",
                    job_id=job_id,
                    retry_count=retry_count,
                    max_retries=MAX_MESSAGE_RETRIES,
                )
                # Reject with requeue to try again
                await message.reject(requeue=True)
            else:
                log.warning(
                    "job_sent_to_dlq",
                    job_id=job_id,
                    retry_count=retry_count,
                    reason="max_retries_exceeded",
                )
                # Update job status to failed before sending to DLQ
                if job_id:
                    await update_job_status(
                        job_id, "failed", error_message=f"Max retries exceeded: {e}"
                    )
                # Reject without requeue - message goes to DLQ
                await message.reject(requeue=False)

        finally:
            worker_active_jobs.dec()

    except json.JSONDecodeError as e:
        log.error("invalid_message_format", error=str(e))
        # Don't requeue invalid messages - send to DLQ
        await message.reject(requeue=False)


@retry(
    stop=stop_after_attempt(MAX_CONNECTION_RETRIES),
    wait=wait_fixed(RETRY_DELAY),
    before_sleep=before_sleep_log(_logger, logging.WARNING),
    retry=retry_if_exception_type(Exception),
    reraise=True,
)
async def connect_with_retry() -> aio_pika.abc.AbstractRobustConnection:
    """Connect to RabbitMQ with retry logic.

    Uses fixed 10-second intervals for RabbitMQ startup scenarios.
    Maximum 90 retries = 15 minutes total wait time.
    """
    connection = await aio_pika.connect_robust(settings.rabbitmq_url)
    log.info("rabbitmq_connected")
    return connection


async def start_consumer(shutdown_event: asyncio.Event) -> None:
    """Start consuming messages from RabbitMQ with DLQ support."""
    connection = await connect_with_retry()

    async with connection:
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=1)

        # Declare DLQ first (result unused but ensures queue exists)
        _ = await channel.declare_queue(
            DLQ_QUEUE,
            durable=True,
        )
        log.info("dlq_declared", queue=DLQ_QUEUE)

        # Declare main queue with DLQ configuration
        # Note: If the queue already exists with different arguments,
        # this will silently use the existing queue configuration.
        try:
            queue = await channel.declare_queue(
                settings.rabbitmq_queue,
                durable=True,
                arguments={
                    "x-dead-letter-exchange": "",
                    "x-dead-letter-routing-key": DLQ_QUEUE,
                },
            )
        except aio_pika.exceptions.ChannelPreconditionFailed:
            # Queue exists with different arguments - use it as-is
            log.warning(
                "queue_dlq_config_skipped",
                queue=settings.rabbitmq_queue,
                reason="queue_already_exists_with_different_arguments",
            )
            queue = await channel.declare_queue(
                settings.rabbitmq_queue,
                durable=True,
                passive=True,  # Just get the existing queue
            )

        log.info("consumer_started", queue=settings.rabbitmq_queue, dlq=DLQ_QUEUE)

        async with queue.iterator() as queue_iter:
            async for message in queue_iter:
                if shutdown_event.is_set():
                    break
                await process_message(message)

    log.info("consumer_stopped")
