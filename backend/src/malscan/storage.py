"""MinIO storage client for file upload operations."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from io import BytesIO

import structlog
from minio import Minio
from minio.commonconfig import Filter
from minio.error import S3Error
from minio.lifecycleconfig import Expiration, LifecycleConfig, Rule

from malscan.config import get_settings

log = structlog.get_logger()
settings = get_settings()

# Thread pool for running sync MinIO operations
_executor = ThreadPoolExecutor(max_workers=4)

# Singleton MinIO client
_minio_client: Minio | None = None


def get_minio_client() -> Minio:
    """Get or create the MinIO client instance (Singleton)."""
    global _minio_client
    if _minio_client is None:
        _minio_client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
        )
    return _minio_client


def init_buckets() -> None:
    """Ensure required buckets exist and have lifecycle rules.

    This runs synchronously and should be called once during app startup.
    """
    client = get_minio_client()
    bucket = settings.minio_bucket_uploads

    try:
        # Create bucket if not exists
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
            log.info("bucket_created", bucket=bucket)

        # Set lifecycle rule (1 days expiry)
        lifecycle_config = LifecycleConfig(
            [
                Rule(
                    status="Enabled",
                    rule_id="1-day-expiry",
                    expiration=Expiration(days=1),
                    rule_filter=Filter(prefix=""),
                )
            ]
        )
        client.set_bucket_lifecycle(bucket, lifecycle_config)
        log.info("bucket_lifecycle_configured", bucket=bucket, days=1)

    except S3Error as e:
        log.error("bucket_init_failed", bucket=bucket, error=str(e))
        raise


def _upload_file_sync(content: bytes, key: str, content_type: str) -> str:
    """Synchronous file upload to MinIO.

    Args:
        content: File content as bytes.
        key: Storage key (SHA256 hash).
        content_type: MIME type of the file.

    Returns:
        The storage key.

    Raises:
        S3Error: If upload fails.
    """
    client = get_minio_client()
    bucket = settings.minio_bucket_uploads

    # Upload file
    data = BytesIO(content)
    client.put_object(
        bucket_name=bucket,
        object_name=key,
        data=data,
        length=len(content),
        content_type=content_type,
    )

    log.info(
        "file_uploaded_to_minio",
        bucket=bucket,
        key=key,
        size=len(content),
        content_type=content_type,
    )

    return key


def _upload_file_path_sync(file_path: str, key: str, content_type: str) -> str:
    """Synchronous file upload to MinIO from a file path.

    Args:
        file_path: Local path to the file.
        key: Storage key (SHA256 hash).
        content_type: MIME type of the file.

    Returns:
        The storage key.

    Raises:
        S3Error: If upload fails.
    """
    client = get_minio_client()
    bucket = settings.minio_bucket_uploads

    # Upload file directly from filesystem
    client.fput_object(
        bucket_name=bucket,
        object_name=key,
        file_path=file_path,
        content_type=content_type,
    )

    log.info(
        "file_path_uploaded_to_minio",
        bucket=bucket,
        key=key,
        file_path=file_path,
        content_type=content_type,
    )

    return key


async def upload_file(
    content: bytes, key: str, content_type: str = "application/octet-stream"
) -> str:
    """Upload file to MinIO asynchronously from memory.

    Args:
        content: File content as bytes.
        key: Storage key (typically SHA256 hash).
        content_type: MIME type of the file.

    Returns:
        The storage key.

    Raises:
        S3Error: If upload fails.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        _executor,
        partial(_upload_file_sync, content, key, content_type),
    )


async def upload_file_path(
    file_path: str, key: str, content_type: str = "application/octet-stream"
) -> str:
    """Upload file to MinIO asynchronously from a file path.

    Args:
        file_path: Local path to the file.
        key: Storage key (typically SHA256 hash).
        content_type: MIME type of the file.

    Returns:
        The storage key.

    Raises:
        S3Error: If upload fails.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        _executor,
        partial(_upload_file_path_sync, file_path, key, content_type),
    )
