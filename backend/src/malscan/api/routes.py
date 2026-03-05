"""API routes for file upload, job status, and reports."""

import asyncio
import hashlib
import os
import tempfile
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from malscan.config import get_settings
from malscan.db import get_db, get_session_factory
from malscan.models import File, Job, JobStatus
from malscan.queue import publish_job
from malscan.schemas.requests import JobStatusResponse, ReportResponse, UploadResponse
from malscan.storage import upload_file_path as upload_to_minio

router = APIRouter()
settings = get_settings()
log = structlog.get_logger()

CHUNK_SIZE = 1024 * 1024  # 1MB chunks


def _sanitize_filename(filename: str) -> str:
    """Sanitize uploaded filename to prevent path traversal and other attacks.

    - Strips path components (../../etc/passwd -> passwd)
    - Handles Windows path separators
    - Removes null bytes
    - Truncates to 255 characters
    - Falls back to 'unnamed' if result is empty
    """
    # Replace Windows path separators with Unix ones, then get basename
    filename = filename.replace(chr(92), "/")
    filename = os.path.basename(filename)

    # Remove null bytes
    filename = filename.replace("\x00", "")

    # Truncate to 255 characters (common filesystem limit)
    if len(filename) > 255:
        filename = filename[:255]

    # Fallback for empty/whitespace-only names
    if not filename.strip():
        filename = "unnamed"

    return filename


@router.post(
    "/files",
    response_model=UploadResponse,
    status_code=201,
    openapi_extra={
        "requestBody": {
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "file": {
                                "type": "string",
                                "format": "binary",
                                "description": "File to upload for malware analysis",
                            }
                        },
                        "required": ["file"],
                    }
                }
            }
        }
    },
)
async def upload_file(request: Request, db: AsyncSession = Depends(get_db)) -> UploadResponse:
    """
    Upload a file for malware analysis.

    - Uses streaming to handle large files efficiently
    - Calculates SHA256 hash incrementally
    - Stores file in MinIO
    - Creates file and job records in database
    - Publishes job to RabbitMQ
    - Returns job_id immediately (async processing)
    """
    try:
        # Parse multipart form
        form = await request.form()
        file = form.get("file")

        if file is None:
            raise HTTPException(
                status_code=422,
                detail="No file field in form data",
            )

        filename = getattr(file, "filename", "unknown")
        filename = _sanitize_filename(filename)
        content_type = getattr(file, "content_type", "application/octet-stream")

        log.info(
            "file_upload_started",
            filename=filename,
            content_type=content_type,
        )

        # Process file using streaming
        hasher = hashlib.sha256()
        file_size = 0

        # Create a temporary file to hold the upload
        fd, temp_path = tempfile.mkstemp()

        try:
            with os.fdopen(fd, "wb") as temp_file:
                while True:
                    chunk = await file.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    file_size += len(chunk)

                    # Check size limit dynamically to avoid writing huge files
                    if file_size > settings.max_file_size:
                        raise HTTPException(
                            status_code=400,
                            detail={
                                "error": {
                                    "code": "FILE_TOO_LARGE",
                                    "message": "File size exceeds limit",
                                    "details": {
                                        "max_size_bytes": settings.max_file_size,
                                        "actual_size_bytes": file_size,
                                    },
                                }
                            },
                        )

                    hasher.update(chunk)
                    temp_file.write(chunk)

            sha256_hash = hasher.hexdigest()

            # Store file in MinIO (use SHA256 as storage key)
            try:
                await upload_to_minio(temp_path, sha256_hash, content_type)
            except Exception as e:
                log.error("minio_upload_failed", sha256=sha256_hash, error=str(e))
                raise HTTPException(
                    status_code=500,
                    detail={
                        "error": {
                            "code": "STORAGE_ERROR",
                            "message": f"Failed to store file: {e}",
                        }
                    },
                ) from e

        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)

        # Check for existing file by SHA256 (deduplication)
        stmt = select(File).where(File.sha256 == sha256_hash)
        result = await db.execute(stmt)
        existing_file = result.scalar_one_or_none()

        if existing_file:
            file_record = existing_file
            log.info("file_exists", file_id=str(file_record.id), sha256=sha256_hash)
        else:
            # Create new file record
            file_record = File(
                sha256=sha256_hash,
                size=file_size,
                filename=filename,
                content_type=content_type,
            )
            db.add(file_record)
            await db.flush()  # Get the file ID
            log.info("file_created", file_id=str(file_record.id), sha256=sha256_hash)

        # Create job record
        job_record = Job(
            file_id=file_record.id,
            status=JobStatus.QUEUED.value,
            stages_total=settings.stages_total,
        )
        db.add(job_record)
        await db.commit()

        log.info(
            "job_created",
            job_id=str(job_record.id),
            file_id=str(file_record.id),
            sha256=sha256_hash,
            size=file_size,
            filename=filename,
        )

        # Publish job to RabbitMQ
        job_message = {
            "job_id": str(job_record.id),
            "file_id": str(file_record.id),
            "storage_key": sha256_hash,
            "sha256": sha256_hash,
            "original_filename": filename,
        }
        try:
            await publish_job(job_message)
        except Exception as e:
            log.error("rabbitmq_publish_failed", job_id=str(job_record.id), error=str(e))
            # Note: Job is already in DB, so we don't rollback. Worker can be triggered manually.
            # In production, consider a retry mechanism or dead-letter queue.

        return UploadResponse(
            job_id=str(job_record.id),
            file_id=str(file_record.id),
            sha256=sha256_hash,
            status=job_record.status,
            created_at=job_record.created_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        log.error("file_upload_error", error=str(e))
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": str(e),
                }
            },
        ) from e


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str, db: AsyncSession = Depends(get_db)) -> JobStatusResponse:
    """
    Get the status of a job.

    Returns current stage, progress, and any error message.
    """
    log.info("job_status_requested", job_id=job_id)

    # Parse job_id to UUID
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job_id format") from None

    # Query job from database
    stmt = select(Job).where(Job.id == job_uuid)
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()

    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    # Calculate progress percent
    percent = int((job.stages_done / job.stages_total) * 100) if job.stages_total > 0 else 0

    return JobStatusResponse(
        job_id=str(job.id),
        status=job.status,
        progress={
            "current_stage": job.current_stage,
            "stages_done": job.stages_done,
            "stages_total": job.stages_total,
            "percent": percent,
        },
        updated_at=job.updated_at,
        error_message=job.error_message,
    )


@router.get("/jobs/{job_id}/stream")
async def stream_job_status(job_id: str, request: Request):
    """
    Stream the status of a job using Server-Sent Events (SSE).
    """
    log.info("job_status_stream_requested", job_id=job_id)

    # Parse job_id to UUID
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job_id format") from None

    # Check if job exists first
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(Job).where(Job.id == job_uuid)
        result = await session.execute(stmt)
        if result.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Job not found")

    async def event_generator():
        last_updated_at = None
        last_status = None
        session_factory = get_session_factory()

        try:
            while True:
                # If client disconnected, stop
                if await request.is_disconnected():
                    log.info("client_disconnected", job_id=job_id)
                    break

                # Create a new session per iteration
                async with session_factory() as session:
                    stmt = select(Job).where(Job.id == job_uuid)
                    result = await session.execute(stmt)
                    job = result.scalar_one_or_none()

                    if not job:
                        break

                    # Only yield if something changed
                    if job.updated_at != last_updated_at or job.status != last_status:
                        last_updated_at = job.updated_at
                        last_status = job.status

                        percent = (
                            int((job.stages_done / job.stages_total) * 100)
                            if job.stages_total > 0
                            else 0
                        )

                        data = JobStatusResponse(
                            job_id=str(job.id),
                            status=job.status,
                            progress={
                                "current_stage": job.current_stage,
                                "stages_done": job.stages_done,
                                "stages_total": job.stages_total,
                                "percent": percent,
                            },
                            updated_at=job.updated_at,
                            error_message=job.error_message,
                        )

                        yield {"event": "message", "data": data.model_dump_json()}

                        # Stop if job is done or failed
                        if job.status in (JobStatus.DONE.value, JobStatus.FAILED.value):
                            break

                # Sleep a bit before checking again to avoid hammering the DB
                await asyncio.sleep(1.0)

        except asyncio.CancelledError:
            log.info("client_disconnected_via_cancel", job_id=job_id)

    return EventSourceResponse(event_generator())


@router.get("/reports/{job_id}", response_model=ReportResponse)
async def get_report(job_id: str, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """
    Get the analysis report for a completed job.

    Returns full report including AV results, YARA hits, IOCs, and timings.
    """
    log.info("report_requested", job_id=job_id)

    # Parse job_id to UUID
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job_id format") from None

    # Query job from database
    stmt = select(Job).where(Job.id == job_uuid)
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()

    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    # Check if job is completed
    if job.status != JobStatus.DONE.value:
        raise HTTPException(
            status_code=400,
            detail=f"Job not completed. Current status: {job.status}",
        )

    # Check if result exists
    if job.result is None:
        raise HTTPException(status_code=404, detail="Report not available yet")

    # Return stored result with created_at
    report = dict(job.result)
    report["created_at"] = job.created_at.isoformat()
    return report
