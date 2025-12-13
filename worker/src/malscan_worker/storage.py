"""MinIO storage client for file download operations."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path

import structlog
from minio import Minio
from minio.error import S3Error

from malscan_worker.config import get_settings

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


def _download_file_sync(key: str, dest_dir: Path) -> Path:
    """Synchronous file download from MinIO.

    Args:
        key: Storage key (SHA256 hash).
        dest_dir: Destination directory.

    Returns:
        Path to the downloaded file.

    Raises:
        S3Error: If download fails.
    """
    client = _get_minio_client()
    bucket = settings.minio_bucket_uploads

    # Create destination directory if needed
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Download file
    dest_path = dest_dir / f"{key}.bin"
    client.fget_object(
        bucket_name=bucket,
        object_name=key,
        file_path=str(dest_path),
    )

    log.info(
        "file_downloaded_from_minio",
        bucket=bucket,
        key=key,
        dest_path=str(dest_path),
    )

    return dest_path


async def download_file(key: str, dest_dir: Path) -> Path:
    """Download file from MinIO asynchronously.

    Args:
        key: Storage key (typically SHA256 hash).
        dest_dir: Destination directory.

    Returns:
        Path to the downloaded file.

    Raises:
        S3Error: If download fails.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        _executor,
        partial(_download_file_sync, key, dest_dir),
    )
