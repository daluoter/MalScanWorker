"""MinIO storage client for file upload operations."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from io import BytesIO
from typing import Any

import structlog
from minio import Minio
from minio.error import S3Error

from malscan.config import get_settings

log = structlog.get_logger()
settings = get_settings()

# Thread pool for running sync MinIO operations
_executor = ThreadPoolExecutor(max_workers=4)


def _get_minio_client() -> Minio:
    """Create MinIO client instance."""
    return Minio(
        settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_secure,
    )


def _ensure_bucket_exists(client: Minio, bucket: str) -> None:
    """Ensure the bucket exists, create if not."""
    try:
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
            log.info("bucket_created", bucket=bucket)
    except S3Error as e:
        log.error("bucket_check_failed", bucket=bucket, error=str(e))
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
    client = _get_minio_client()
    bucket = settings.minio_bucket_uploads

    # Ensure bucket exists
    _ensure_bucket_exists(client, bucket)

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


async def upload_file(content: bytes, key: str, content_type: str = "application/octet-stream") -> str:
    """Upload file to MinIO asynchronously.

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
