"""API routes for file upload, job status, and reports."""

import asyncio
import hashlib
import os
import tempfile
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from sse_starlette.sse import EventSourceResponse

from malscan.config import get_settings
from malscan.db import get_db, get_session_factory
from malscan.models import File, Job, JobStatus
from malscan.models.artifact import Artifact
from malscan.queue import publish_job
from malscan.report_explainability import build_explainability, ensure_artifact_tree_root
from malscan.schemas.requests import (
    JobStatusResponse,
    PasswordSubmitRequest,
    PasswordSubmitResponse,
    ReportResponse,
    UploadResponse,
)
from malscan.scoring.models import RiskDecision, ScoreBreakdown
from malscan.scoring.policy import POLICY_VERSION
from malscan.scoring.tree import merge_with_descendants
from malscan.storage import upload_file_path as upload_to_minio

router = APIRouter()
settings = get_settings()
log = structlog.get_logger()

CHUNK_SIZE = 1024 * 1024  # 1MB chunks


def _risk_level_from_score(score: int) -> str:
    if score >= 85:
        return "malicious"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 10:
        return "low"
    return "clean"


def _infer_level_from_legacy(verdict: str | None, score: int) -> str:
    if verdict == "malicious":
        return "malicious"
    if verdict == "clean":
        return "clean" if score == 0 else _risk_level_from_score(score)
    if verdict == "suspicious":
        return _risk_level_from_score(score) if score > 0 else "medium"
    return _risk_level_from_score(score)


def _normalize_risk_collection(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _normalize_risk_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _ensure_report_risk_shape(report: dict[str, Any]) -> dict[str, Any]:
    """Backfill risk fields for legacy stored reports."""
    score = int(report.get("score") or 0)
    verdict = str(report.get("verdict") or "clean")
    risk = report.get("risk")

    if isinstance(risk, dict):
        risk_score = int(risk.get("risk_score") or score)
        legacy_verdict = str(risk.get("legacy_verdict") or verdict)
        risk_level = str(
            risk.get("risk_level")
            or report.get("risk_level")
            or _infer_level_from_legacy(legacy_verdict, risk_score)
        )
        breakdown = risk.get("breakdown")
        if not isinstance(breakdown, dict):
            breakdown = {}
        risk["policy_version"] = str(risk.get("policy_version") or POLICY_VERSION)
        risk["risk_score"] = risk_score
        risk["risk_level"] = risk_level
        risk["legacy_verdict"] = legacy_verdict
        risk["malicious_gate_open"] = bool(
            risk.get("malicious_gate_open", risk_level == "malicious")
        )
        risk["high_gate_open"] = bool(
            risk.get("high_gate_open", risk_level in {"high", "malicious"})
        )
        risk["independent_source_count"] = int(risk.get("independent_source_count") or 0)
        breakdown.setdefault("local_score", risk_score)
        breakdown.setdefault("inherited_score", 0)
        breakdown.setdefault("synergy_bonus", 0)
        breakdown.setdefault("dampener", 0)
        breakdown.setdefault("final_score", risk_score)
        risk["breakdown"] = breakdown
        risk["evidence"] = _normalize_risk_collection(risk.get("evidence"))
        risk["top_evidence"] = _normalize_risk_collection(risk.get("top_evidence"))
        risk["descendant_summary"] = _normalize_risk_mapping(risk.get("descendant_summary"))
        risk["score_trace"] = _normalize_risk_mapping(risk.get("score_trace"))
        report["risk_level"] = risk_level
        report["risk"] = risk
        return report

    risk_level = str(report.get("risk_level") or _infer_level_from_legacy(verdict, score))
    report["risk_level"] = risk_level
    report["risk"] = {
        "policy_version": POLICY_VERSION,
        "risk_score": score,
        "risk_level": risk_level,
        "legacy_verdict": verdict,
        "malicious_gate_open": risk_level == "malicious",
        "high_gate_open": risk_level in {"high", "malicious"},
        "independent_source_count": 0,
        "breakdown": {
            "local_score": score,
            "inherited_score": 0,
            "synergy_bonus": 0,
            "dampener": 0,
            "final_score": score,
        },
        "evidence": [],
        "top_evidence": [],
        "descendant_summary": {},
        "score_trace": {},
    }
    return report


def _empty_explainability() -> dict[str, Any]:
    return {
        "summary": {
            "headline": "",
            "primary_artifact_id": None,
            "primary_artifact_path": None,
            "top_findings": [],
            "final_verdict_explainer": "",
        },
        "artifacts": [],
        "findings": [],
        "evidence": [],
        "iocs": [],
        "decoded_strings": [],
        "uncertainties": [],
        "timeline": [],
        "failure_diagnostics": {
            "status": "none",
            "headline": "",
            "diagnostics": [],
            "suspected_miss_stages": [],
        },
    }


def _ensure_report_explainability_shape(report: dict[str, Any]) -> dict[str, Any]:
    report["report_schema_version"] = str(report.get("report_schema_version") or "mswr-report-v2")
    if not isinstance(report.get("explainability"), dict):
        report["explainability"] = _empty_explainability()
    else:
        explainability = report["explainability"]
        empty = _empty_explainability()
        for key, value in empty.items():
            if key not in explainability or not isinstance(explainability.get(key), type(value)):
                explainability[key] = value
        summary = explainability.get("summary")
        if isinstance(summary, dict):
            for key, value in empty["summary"].items():
                summary.setdefault(key, value)
        failure = explainability.get("failure_diagnostics")
        if isinstance(failure, dict):
            for key, value in empty["failure_diagnostics"].items():
                failure.setdefault(key, value)
    return report


def _should_preserve_stored_explainability(report: dict[str, Any]) -> bool:
    explainability = report.get("explainability")
    if not isinstance(explainability, dict):
        return False
    failure = explainability.get("failure_diagnostics")
    if not isinstance(failure, dict):
        return False
    return str(failure.get("status") or "") == "blocked"


def _synthesize_root_artifact_tree(report: dict[str, Any]) -> dict[str, Any]:
    return ensure_artifact_tree_root(report, None)


def _artifact_level(node: dict[str, Any]) -> str:
    level = node.get("risk_level")
    if isinstance(level, str) and level:
        return level

    score = int(node.get("score") or 0)
    verdict = node.get("verdict")
    return _infer_level_from_legacy(str(verdict) if verdict is not None else None, score)


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
                            },
                            "parent_job_id": {
                                "type": "string",
                                "description": "Optional parent job ID",
                            },
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
        parent_job_id_str = form.get("parent_job_id")

        if file is None or isinstance(file, str):
            raise HTTPException(
                status_code=422,
                detail="No file field in form data or field is not a file",
            )

        # Validate parent_job_id if provided
        parent_job = None
        new_depth = 0
        if parent_job_id_str and isinstance(parent_job_id_str, str):
            try:
                parent_job_uuid = uuid.UUID(parent_job_id_str)
            except ValueError:
                raise HTTPException(
                    status_code=400, detail="Invalid parent_job_id format"
                ) from None

            stmt = select(Job).where(Job.id == parent_job_uuid)
            result = await db.execute(stmt)
            parent_job = result.scalar_one_or_none()

            if not parent_job:
                raise HTTPException(status_code=400, detail="Parent job not found")

            max_depth = getattr(settings, "max_job_depth", 3)
            if parent_job.depth >= max_depth:
                raise HTTPException(
                    status_code=400,
                    detail=f"Maximum recursion depth ({max_depth}) reached",
                )

            new_depth = parent_job.depth + 1

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
            parent_job_id=parent_job.id if parent_job else None,
            depth=new_depth,
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
            # Mark job as failed so it won't be stuck in QUEUED forever
            job_record.status = JobStatus.FAILED.value
            job_record.error_message = f"Failed to publish to queue: {e}"
            await db.commit()
            raise HTTPException(
                status_code=503,
                detail={
                    "error": {
                        "code": "QUEUE_PUBLISH_FAILED",
                        "message": "Failed to submit job to processing queue. Please try again.",
                        "job_id": str(job_record.id),
                    }
                },
            ) from e

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
        parent_job_id=str(job.parent_job_id) if job.parent_job_id else None,
        depth=job.depth,
        status=job.status,
        password_attempts=job.password_attempts,
        password_attempts_remaining=max(0, 3 - job.password_attempts),
        progress={
            "current_stage": job.current_stage,
            "stages_done": job.stages_done,
            "stages_total": job.stages_total,
            "percent": percent,
        },
        updated_at=job.updated_at,
        error_message=job.error_message,
        total_sub=job.total_sub,
        completed_sub=job.completed_sub,
        malicious_sub=job.malicious_sub,
    )


@router.post("/jobs/{job_id}/password", response_model=PasswordSubmitResponse)
async def submit_job_password(
    job_id: str,
    payload: PasswordSubmitRequest,
    db: AsyncSession = Depends(get_db),
) -> PasswordSubmitResponse:
    """Submit password for a password-protected archive job and requeue it."""
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job_id format") from None

    stmt = select(Job).where(Job.id == job_uuid).with_for_update()
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()

    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status != JobStatus.PASSWORD_REQUIRED.value:
        raise HTTPException(
            status_code=409,
            detail=f"Job not in password_required status. Current status: {job.status}",
        )

    if job.password_attempts >= 3:
        raise HTTPException(status_code=409, detail="Password attempts exhausted")

    file_stmt = select(File).where(File.id == job.file_id)
    file_result = await db.execute(file_stmt)
    file_obj = file_result.scalar_one_or_none()

    if not file_obj:
        raise HTTPException(status_code=500, detail="Job file metadata not found")

    attempts_used = job.password_attempts
    attempts_remaining = max(0, 3 - job.password_attempts)

    try:
        await publish_job(
            {
                "job_id": str(job.id),
                "file_id": str(file_obj.id),
                "storage_key": file_obj.sha256,
                "sha256": file_obj.sha256,
                "original_filename": file_obj.filename,
                "archive_password": payload.password,
            }
        )
    except Exception as e:
        log.error("password_submit_publish_failed", job_id=str(job.id), error=str(e))
        raise HTTPException(
            status_code=503,
            detail="Failed to submit password retry job",
        ) from e

    job.status = JobStatus.QUEUED.value
    job.current_stage = None
    job.error_message = None
    await db.commit()

    return PasswordSubmitResponse(
        job_id=str(job.id),
        status=JobStatus.QUEUED.value,
        message="Password accepted. Job requeued for analysis.",
        attempts_used=attempts_used,
        attempts_remaining=attempts_remaining,
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
                            parent_job_id=str(job.parent_job_id) if job.parent_job_id else None,
                            depth=job.depth,
                            status=job.status,
                            password_attempts=job.password_attempts,
                            password_attempts_remaining=max(0, 3 - job.password_attempts),
                            progress={
                                "current_stage": job.current_stage,
                                "stages_done": job.stages_done,
                                "stages_total": job.stages_total,
                                "percent": percent,
                            },
                            updated_at=job.updated_at,
                            error_message=job.error_message,
                            total_sub=job.total_sub,
                            completed_sub=job.completed_sub,
                            malicious_sub=job.malicious_sub,
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


async def _build_artifact_tree(root_job_id: str, db: AsyncSession) -> dict | None:
    """Build hierarchical artifact tree from flat records."""
    from uuid import UUID

    stmt = (
        select(Artifact)
        .where(Artifact.root_job_id == UUID(root_job_id))
        .order_by(Artifact.depth, Artifact.created_at)
    )
    result = await db.execute(stmt)
    artifacts = result.scalars().all()

    if not artifacts:
        return None

    nodes: dict[str, dict] = {}
    root = None
    extra_roots: list[dict[str, Any]] = []
    for art in artifacts:
        node = {
            "id": str(art.id),
            "filename": art.original_filename,
            "sha256": art.sha256,
            "mime": art.mime,
            "size": art.size,
            "depth": art.depth,
            "origin_path": art.origin_path,
            "extraction_source": art.extraction_source,
            "archive_type": art.archive_type,
            "extraction_note": art.extraction_note,
            "verdict": art.verdict,
            "score": art.score,
            "risk_level": art.risk_level,
            "policy_version": art.policy_version,
            "job_id": str(art.job_id) if art.job_id else None,
            "synthetic_root": False,
            "children": [],
        }
        nodes[str(art.id)] = node
        if art.parent_id and str(art.parent_id) in nodes:
            nodes[str(art.parent_id)]["children"].append(node)
        if art.depth == 0:
            if root is None:
                root = node
            else:
                node["synthetic_root"] = True
                extra_roots.append(node)

    if root is not None and extra_roots:
        root["children"].extend(extra_roots)

    return root


def _apply_tree_risk_rollup(
    report: dict[str, Any],
    artifact_tree: dict[str, Any] | None,
) -> dict[str, Any]:
    """Apply canonical descendant rollup to a stored local-risk report."""
    report = _ensure_report_risk_shape(report)
    risk = report.get("risk")
    if not artifact_tree or not isinstance(risk, dict):
        return report

    breakdown = risk.get("breakdown")
    if not isinstance(breakdown, dict):
        return report

    local = RiskDecision(
        risk_score=int(risk.get("risk_score") or 0),
        risk_level=str(risk.get("risk_level") or "clean"),
        legacy_verdict=str(risk.get("legacy_verdict") or report.get("verdict") or "clean"),
        evidence=[],
        top_evidence=[],
        breakdown=ScoreBreakdown(
            local_score=int(breakdown.get("local_score") or 0),
            inherited_score=int(breakdown.get("inherited_score") or 0),
            synergy_bonus=int(breakdown.get("synergy_bonus") or 0),
            dampener=int(breakdown.get("dampener") or 0),
            final_score=int(breakdown.get("final_score") or 0),
            malicious_gate_open=bool(risk.get("malicious_gate_open", False)),
            high_gate_open=bool(risk.get("high_gate_open", False)),
            independent_source_count=int(risk.get("independent_source_count") or 0),
        ),
        policy_version=str(risk.get("policy_version") or POLICY_VERSION),
    )

    descendants: list[dict[str, Any]] = []
    root_depth = int(artifact_tree.get("depth") or 0)

    def _collect(node: dict[str, Any]) -> None:
        for child in node.get("children", []):
            if child.get("synthetic_root"):
                continue
            if not child.get("synthetic_root"):
                descendants.append(
                    {
                        "artifact_id": child["id"],
                        "sha256": child["sha256"],
                        "relative_depth": max(1, int(child.get("depth") or 0) - root_depth),
                        "risk_level": _artifact_level(child),
                        "risk_score": int(child.get("score") or 0),
                        "origin_path": child.get("origin_path"),
                        "verdict": child.get("verdict"),
                        "extraction_note": child.get("extraction_note"),
                    }
                )
            _collect(child)

    _collect(artifact_tree)
    final = merge_with_descendants(local=local, descendants=descendants)

    report["score"] = final.risk_score
    report["verdict"] = final.legacy_verdict
    report["risk_level"] = final.risk_level
    risk["risk_score"] = final.risk_score
    risk["risk_level"] = final.risk_level
    risk["legacy_verdict"] = final.legacy_verdict
    risk["malicious_gate_open"] = final.breakdown.malicious_gate_open
    risk["high_gate_open"] = final.breakdown.high_gate_open
    risk["independent_source_count"] = final.breakdown.independent_source_count
    breakdown["inherited_score"] = final.breakdown.inherited_score
    breakdown["final_score"] = final.breakdown.final_score
    risk["descendant_summary"] = final.descendant_summary
    artifact_tree["score"] = final.risk_score
    artifact_tree["verdict"] = final.legacy_verdict
    artifact_tree["risk_level"] = final.risk_level
    artifact_tree["policy_version"] = final.policy_version
    return report


async def _count_pending_descendants(root_job_id: str, db: AsyncSession) -> int:
    """Count descendant jobs that are not in terminal status."""
    from uuid import UUID

    stmt = text(
        """
        WITH RECURSIVE descendants AS (
            SELECT id, status
            FROM jobs
            WHERE parent_job_id = :root_job_id
            UNION ALL
            SELECT j.id, j.status
            FROM jobs j
            JOIN descendants d ON j.parent_job_id = d.id
        )
        SELECT COUNT(*) AS pending_count
        FROM descendants
        WHERE status NOT IN ('done', 'failed')
        """
    )
    result = await db.execute(stmt, {"root_job_id": UUID(root_job_id)})
    return int(result.scalar() or 0)


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

    # Query job from database including its file and sub-jobs
    stmt = (
        select(Job)
        .where(Job.id == job_uuid)
        .options(joinedload(Job.file), joinedload(Job.sub_jobs).joinedload(Job.file))
    )
    result = await db.execute(stmt)
    job = result.unique().scalar_one_or_none()

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

    pending_descendants = await _count_pending_descendants(str(job.id), db)
    if pending_descendants > 0:
        raise HTTPException(
            status_code=409,
            detail=(
                "Report not ready. "
                f"Waiting for {pending_descendants} descendant job(s) to finish."
            ),
        )

    # Format child jobs summary
    child_jobs = []
    for sub in job.sub_jobs:
        # We need to get verdict from sub.result if it exists
        sub_verdict = "unknown"
        if sub.result and isinstance(sub.result, dict):
            sub_verdict = sub.result.get("verdict", "unknown")

        child_jobs.append(
            {
                "job_id": str(sub.id),
                "filename": sub.file.filename if sub.file else "unknown",
                "sha256": sub.file.sha256 if sub.file else "unknown",
                "status": sub.status,
                "verdict": sub_verdict,
            }
        )

    # Return stored result with created_at and child_jobs
    report = dict(job.result)
    report = _ensure_report_risk_shape(report)
    report = _ensure_report_explainability_shape(report)
    report["created_at"] = job.created_at.isoformat()
    report["parent_job_id"] = str(job.parent_job_id) if job.parent_job_id else None
    report["child_jobs"] = child_jobs

    # Build artifact tree (returns None for non-archive files)
    report["artifact_tree"] = await _build_artifact_tree(str(job.id), db)
    report = _apply_tree_risk_rollup(report, report["artifact_tree"])
    report["artifact_tree"] = ensure_artifact_tree_root(report, report["artifact_tree"])
    synthesized_explainability = build_explainability(
        report=report,
        artifact_tree=report["artifact_tree"],
    )
    if _should_preserve_stored_explainability(report):
        report_explainability = report.get("explainability")
        if isinstance(report_explainability, dict):
            synthesized_explainability["summary"] = report_explainability.get(
                "summary", synthesized_explainability["summary"]
            )
            synthesized_explainability["failure_diagnostics"] = report_explainability.get(
                "failure_diagnostics", synthesized_explainability["failure_diagnostics"]
            )
            synthesized_explainability["timeline"] = report_explainability.get(
                "timeline", synthesized_explainability["timeline"]
            )
    report["explainability"] = synthesized_explainability

    return report
