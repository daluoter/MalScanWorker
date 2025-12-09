"""RabbitMQ consumer for processing jobs."""

import asyncio
import json
from typing import Any

import aio_pika
import structlog

from malscan_worker.config import get_settings
from malscan_worker.pipeline import run_pipeline
from malscan_worker.metrics import job_total, worker_active_jobs

log = structlog.get_logger()
settings = get_settings()


async def process_message(message: aio_pika.IncomingMessage) -> None:
    """Process a single job message."""
    async with message.process():
        try:
            # Parse message
            body = json.loads(message.body.decode())
            job_id = body.get("job_id")
            file_id = body.get("file_id")

            log.info(
                "job_received",
                job_id=job_id,
                file_id=file_id,
            )

            worker_active_jobs.inc()
            job_total.labels(status="scanning").inc()

            try:
                # Run the analysis pipeline
                await run_pipeline(body)
                job_total.labels(status="done").inc()
            except Exception as e:
                log.error(
                    "job_failed",
                    job_id=job_id,
                    file_id=file_id,
                    error=str(e),
                )
                job_total.labels(status="failed").inc()
                raise
            finally:
                worker_active_jobs.dec()

        except json.JSONDecodeError as e:
            log.error("invalid_message_format", error=str(e))
            # Don't requeue invalid messages


async def start_consumer(shutdown_event: asyncio.Event) -> None:
    """Start consuming messages from RabbitMQ."""
    connection = await aio_pika.connect_robust(settings.rabbitmq_url)
    log.info("rabbitmq_connected")

    async with connection:
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=1)

        queue = await channel.declare_queue(
            settings.rabbitmq_queue,
            durable=True,
        )

        log.info("consumer_started", queue=settings.rabbitmq_queue)

        async with queue.iterator() as queue_iter:
            async for message in queue_iter:
                if shutdown_event.is_set():
                    break
                await process_message(message)

    log.info("consumer_stopped")
