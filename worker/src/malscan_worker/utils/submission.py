"""Internal job submission utility for recursive analysis."""

import asyncio
import json
from typing import Optional
from uuid import UUID

import aio_pika
import structlog
from malscan.config import get_settings
from malscan.models.file import File
from malscan.models.job import Job, JobStatus
from malscan.storage import get_minio_client
from malscan.storage import upload_file_path as upload_to_minio
from malscan_worker.db import _engine
from minio.error import S3Error
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

log = structlog.get_logger()
settings = get_settings()


class InternalJobSubmitter:
    """Singleton class to manage MQ connections and submit sub-jobs safely."""

    _instance: Optional["InternalJobSubmitter"] = None
    _connection: aio_pika.abc.AbstractRobustConnection | None = None
    _channel: aio_pika.abc.AbstractChannel | None = None
    _exchange: aio_pika.abc.AbstractExchange | None = None

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

    async def _storage_object_exists(self, key: str) -> bool:
        """Check whether an object key exists in MinIO uploads bucket."""

        def _check_exists() -> bool:
            client = get_minio_client()
            try:
                client.stat_object(settings.minio_bucket_uploads, key)
                return True
            except S3Error as e:
                if e.code == "NoSuchKey":
                    return False
                raise

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _check_exists)

    async def submit_subjob(
        self,
        *,
        file_path: str,
        filename: str,
        content_type: str,
        sha256_hash: str,
        file_size: int,
        parent_job_id: str,
        parent_job_depth: int,
        artifact_id: str | None = None,
        root_artifact_id: str | None = None,
        root_job_id: str | None = None,
        ancestor_hashes: set[str] | None = None,
    ) -> str | None:
        """Submit a new sub-job for analysis.

        Uses its own independent DB session to avoid polluting the caller's
        session (which would expire all ORM objects on commit and cause
        "greenlet_spawn has not been called" errors in SQLAlchemy async).

        Args:
            file_path: Path to the extracted file on disk.
            filename: Original filename of the extracted file.
            content_type: MIME content type.
            sha256_hash: SHA256 hash of the extracted file.
            file_size: Size in bytes.
            parent_job_id: Parent job UUID as string.
            parent_job_depth: Recursion depth of the parent job.

        Returns:
            The sub-job UUID as string, or None if skipped/failed.
        """
        # Ensure parent constraints
        max_depth = getattr(settings, "max_job_depth", 3)
        if parent_job_depth >= max_depth:
            log.warning(
                "max_recursion_depth_reached",
                parent_job_id=parent_job_id,
                depth=parent_job_depth,
                filename=filename,
            )
            return None

        # Use an independent DB session so we never expire the pipeline's
        # shared session objects.
        async with AsyncSession(_engine) as db:
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

                # Dedup rows may outlive MinIO lifecycle; ensure blob still exists.
                if not await self._storage_object_exists(sha256_hash):
                    log.warning(
                        "dedup_file_missing_in_storage_reupload",
                        file_id=str(file_record.id),
                        sha256=sha256_hash,
                    )
                    await upload_to_minio(file_path, sha256_hash, content_type)
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
            new_depth = parent_job_depth + 1
            sub_job = Job(
                file_id=file_record.id,
                status=JobStatus.QUEUED.value,
                stages_total=settings.stages_total,
                parent_job_id=UUID(parent_job_id),
                depth=new_depth,
            )
            db.add(sub_job)

            # Flush to get the ID, then capture before commit expires objects
            await db.flush()
            sub_job_id = str(sub_job.id)
            file_id_str = str(file_record.id)

            await db.commit()

            if artifact_id is not None:
                try:
                    await db.execute(
                        text("UPDATE artifacts SET job_id = :job_id WHERE id = :artifact_id"),
                        {
                            "job_id": UUID(sub_job_id),
                            "artifact_id": UUID(artifact_id),
                        },
                        execution_options={"artifact_job_link": True},
                    )
                    await db.commit()
                except Exception as e:
                    log.warning(
                        "artifact_job_link_update_failed",
                        artifact_id=artifact_id,
                        job_id=sub_job_id,
                        error=str(e),
                    )

        log.info(
            "sub_job_created",
            job_id=sub_job_id,
            parent_id=parent_job_id,
            filename=filename,
        )

        # 4. Publish to MQ (outside of DB session)
        await self._ensure_connection()
        message_body = {
            "job_id": sub_job_id,
            "file_id": file_id_str,
            "storage_key": sha256_hash,
            "sha256": sha256_hash,
            "original_filename": filename,
            "artifact_id": artifact_id,
            "root_artifact_id": root_artifact_id,
            "root_job_id": root_job_id,
            "ancestor_hashes": list(ancestor_hashes or set()),
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
            log.info("sub_job_published_to_mq", job_id=sub_job_id)
        except Exception as e:
            # MQ failed — update job status via explicit UPDATE
            log.error(
                "rabbitmq_sub_publish_failed",
                job_id=sub_job_id,
                error=str(e),
            )
            async with AsyncSession(_engine) as db:
                await db.execute(
                    update(Job)
                    .where(Job.id == UUID(sub_job_id))
                    .values(
                        status=JobStatus.FAILED.value,
                        error_message=f"Failed to publish to MQ: {e!s}",
                    )
                )
                await db.commit()
            return None

        return sub_job_id
