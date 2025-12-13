"""API routes for file upload, job status, and reports."""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from malscan.config import get_settings
from malscan.db import get_db
from malscan.models import File, Job, JobStatus
from malscan.schemas.requests import JobStatusResponse, ReportResponse, UploadResponse

router = APIRouter()
settings = get_settings()
log = structlog.get_logger()


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
async def upload_file(
    request: Request, db: AsyncSession = Depends(get_db)
) -> UploadResponse:
    """
    Upload a file for malware analysis.

    - Calculates SHA256 hash
    - Stores file in MinIO
    - Creates file and job records in database
    - Publishes job to RabbitMQ
    - Returns job_id immediately (async processing)
    """
    try:
        # Parse multipart form manually to handle large files
        form = await request.form()
        file = form.get("file")

        if file is None:
            raise HTTPException(
                status_code=422,
                detail="No file field in form data",
            )

        # Read file content
        content = await file.read()
        file_size = len(content)
        filename = getattr(file, "filename", "unknown")
        content_type = getattr(file, "content_type", "application/octet-stream")

        log.info(
            "file_upload_started",
            filename=filename,
            content_type=content_type,
            size=file_size,
        )

        # Check size limit
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

        # Calculate hash
        sha256_hash = hashlib.sha256(content).hexdigest()

        # TODO: Store file in MinIO

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

        # TODO: Publish job to RabbitMQ

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
async def get_job_status(
    job_id: str, db: AsyncSession = Depends(get_db)
) -> JobStatusResponse:
    """
    Get the status of a job.

    Returns current stage, progress, and any error message.
    """
    log.info("job_status_requested", job_id=job_id)

    # Parse job_id to UUID
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job_id format")

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


@router.get("/reports/{job_id}", response_model=ReportResponse)
async def get_report(job_id: str) -> dict[str, Any]:
    """
    Get the analysis report for a completed job.

    Returns full report including AV results, YARA hits, IOCs, and timings.
    """
    # TODO: Query report from database
    log.info("report_requested", job_id=job_id)

    # Mock response for skeleton
    return {
        "job_id": job_id,
        "file": {
            "file_id": "mock-file-id",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991",
            "mime": "application/octet-stream",
            "size": 1024,
            "original_filename": "test.bin",
        },
        "verdict": "clean",
        "score": 0,
        "results": {
            "av_result": {
                "engine": "ClamAV",
                "infected": False,
                "threat_name": None,
            },
            "yara_hits": [],
            "iocs": {
                "urls": [],
                "domains": [],
                "ips": [],
                "hashes": {
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb924",
                },
            },
            "sandbox": {
                "executed": True,
                "behaviors": [],
                "network_connections": [],
                "is_mock": True,
            },
        },
        "timings": {
            "total_ms": 5000,
            "stages": [
                {"name": "file-type", "status": "ok", "duration_ms": 50},
                {"name": "clamav", "status": "ok", "duration_ms": 2000},
                {"name": "yara", "status": "ok", "duration_ms": 1000},
                {"name": "ioc-extract", "status": "ok", "duration_ms": 450},
                {"name": "sandbox", "status": "ok", "duration_ms": 1500},
            ],
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

