"""Internal job submission utility for recursive analysis."""

import json
from typing import Optional

import aio_pika
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from malscan.config import get_settings
from malscan.models.file import File
from malscan.models.job import Job, JobStatus
from malscan.storage import upload_file_path as upload_to_minio

log = structlog.get_logger()
settings = get_settings()


class InternalJobSubmitter:
    """Singleton class to manage MQ connections and submit sub-jobs safely."""

    _instance: Optional["InternalJobSubmitter"] = None
    _connection: Optional[aio_pika.abc.AbstractRobustConnection] = None
    _channel: Optional[aio_pika.abc.AbstractChannel] = None
    _exchange: Optional[aio_pika.abc.AbstractExchange] = None

    def __new__(cls) -> "InternalJobSubmitter":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    async def get_instance(cls) -> "InternalJobSubmitter":
        """Get the singleton instance and ensure connection is established."""
        instance = cls()
        await instance._ensure_connection()
        return instance

    async def _ensure_connection(self) -> None:
        """Ensure RabbitMQ connection is active. Reconnect if necessary.
        Uses connect_robust to handle connection drops automatically.
        """
        if self._connection is None or self._connection.is_closed:
            log.info("initializing_internal_job_submitter_mq_connection")
            # Connect_robust handles automatic reconnects and heartbeats
            self._connection = await aio_pika.connect_robust(
                settings.rabbitmq_url,
                client_properties={"connection_name": "malscan_worker_submitter"},
            )
            self._channel = await self._connection.channel()
            # Default exchange for direct queue routing
            self._exchange = self._channel.default_exchange
            log.info("internal_job_submitter_mq_connected")

    async def close(self) -> None:
        """Close RabbitMQ connection."""
        if self._connection and not self._connection.is_closed:
            await self._connection.close()
            self._connection = None
            self._channel = None
            self._exchange = None
            log.info("internal_job_submitter_mq_closed")

    async def submit_subjob(
        self,
        db: AsyncSession,
        file_path: str,
        filename: str,
        content_type: str,
        sha256_hash: str,
        file_size: int,
        parent_job: Job,
    ) -> Job | None:
        """Submit a new sub-job for analysis.
        Follows strictly: 1. Hash/De-dupe -> 2. MinIO -> 3. DB (QUEUED) -> 4. MQ Publish.
        If step 4 fails, revert DB status to FAILED.
        """
        # Ensure parent constraints
        if parent_job.depth >= getattr(settings, "max_job_depth", 3):
            log.warning(
                "max_recursion_depth_reached",
                parent_job_id=str(parent_job.id),
                depth=parent_job.depth,
                filename=filename,
            )
            return None

        # 1. Deduplication using DB Query
        stmt = select(File).where(File.sha256 == sha256_hash)
        result = await db.execute(stmt)
        existing_file = result.scalar_one_or_none()

        if existing_file:
            file_record = existing_file
            log.info(
                "sub_file_exists_de_duped",
                file_id=str(file_record.id),
                sha256=sha256_hash,
            )
        else:
            # 2. Upload to MinIO (only if it's a new unique file)
            try:
                await upload_to_minio(file_path, sha256_hash, content_type)
            except Exception as e:
                log.error(
                    "minio_sub_upload_failed",
                    sha256=sha256_hash,
                    error=str(e),
                )
                raise

            # Insert new file into DB
            file_record = File(
                sha256=sha256_hash,
                size=file_size,
                filename=filename,
                content_type=content_type,
            )
            db.add(file_record)
            await db.flush()
            log.info(
                "sub_file_created",
                file_id=str(file_record.id),
                sha256=sha256_hash,
            )

        # 3. Create Job record in DB (State: QUEUED)
        new_depth = parent_job.depth + 1
        sub_job = Job(
            file_id=file_record.id,
            status=JobStatus.QUEUED.value,
            stages_total=settings.stages_total,
            parent_job_id=parent_job.id,
            depth=new_depth,
        )
        db.add(sub_job)
        await db.commit()
        await db.refresh(sub_job)

        log.info(
            "sub_job_created",
            job_id=str(sub_job.id),
            parent_id=str(parent_job.id),
            filename=filename,
        )

        # 4. Publish to MQ
        await self._ensure_connection()
        message_body = {
            "job_id": str(sub_job.id),
            "file_id": str(file_record.id),
            "storage_key": sha256_hash,
            "sha256": sha256_hash,
            "original_filename": filename,
        }

        try:
            message = aio_pika.Message(
                body=json.dumps(message_body).encode(),
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            )
            if self._exchange:
                await self._exchange.publish(
                    message,
                    routing_key=settings.rabbitmq_queue,
                )
            log.info("sub_job_published_to_mq", job_id=str(sub_job.id))
        except Exception as e:
            # MQ failed, revert job status to failed
            log.error(
                "rabbitmq_sub_publish_failed",
                job_id=str(sub_job.id),
                error=str(e),
            )
            sub_job.status = JobStatus.FAILED.value
            sub_job.error_message = f"Failed to publish to MQ: {e!s}"
            await db.commit()
            return sub_job

        return sub_job
