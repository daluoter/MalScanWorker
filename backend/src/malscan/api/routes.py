"""API routes for file upload, job status, and reports."""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, File, HTTPException, UploadFile

from malscan.config import get_settings
from malscan.schemas.requests import JobStatusResponse, ReportResponse, UploadResponse

router = APIRouter()
settings = get_settings()
log = structlog.get_logger()


@router.post("/files", response_model=UploadResponse, status_code=201)
async def upload_file(
    file: Annotated[UploadFile, File(description="File to upload for malware analysis")]
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
        # Read file content
        content = await file.read()
        file_size = len(content)

        log.info(
            "file_upload_started",
            filename=file.filename,
            content_type=file.content_type,
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

        # Generate IDs
        file_id = str(uuid.uuid4())
        job_id = str(uuid.uuid4())

        log.info(
            "file_uploaded",
            job_id=job_id,
            file_id=file_id,
            sha256=sha256_hash,
            size=file_size,
            filename=file.filename,
        )

        # TODO: Store file in MinIO
        # TODO: Create file record in database (upsert by sha256)
        # TODO: Create job record in database
        # TODO: Publish job to RabbitMQ

        return UploadResponse(
            job_id=job_id,
            file_id=file_id,
            sha256=sha256_hash,
            status="queued",
            created_at=datetime.now(timezone.utc),
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
async def get_job_status(job_id: str) -> JobStatusResponse:
    """
    Get the status of a job.

    Returns current stage, progress, and any error message.
    """
    # TODO: Query job from database
    log.info("job_status_requested", job_id=job_id)

    # Mock response for skeleton
    return JobStatusResponse(
        job_id=job_id,
        status="scanning",
        progress={
            "current_stage": "clamav",
            "stages_done": 1,
            "stages_total": 5,
            "percent": 20,
        },
        updated_at=datetime.now(timezone.utc),
        error_message=None,
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
