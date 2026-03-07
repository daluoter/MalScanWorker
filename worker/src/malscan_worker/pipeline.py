"""Pipeline orchestrator for running analysis stages."""

import asyncio
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from malscan_worker.config import get_settings
from malscan_worker.db import update_job_result, update_job_stage, update_job_status, get_job_for_context, _engine
from sqlalchemy.ext.asyncio import AsyncSession
from malscan_worker.metrics import stage_latency
from malscan_worker.stages.base import StageContext, StageResult
from malscan_worker.stages.clamav import ClamAVStage
from malscan_worker.stages.filetype import FileTypeStage
from malscan_worker.stages.ioc_extract import IocExtractStage
from malscan_worker.stages.archive_extract import ArchiveExtractStage
from malscan_worker.stages.sandbox import SandboxStage
from malscan_worker.stages.yara_scan import YaraStage
from malscan_worker.storage import download_file

log = structlog.get_logger()
settings = get_settings()


# Stages that can run in parallel
PARALLEL_STAGES = [
    FileTypeStage(),
    ClamAVStage(),
    YaraStage(),
    IocExtractStage(),
    ArchiveExtractStage(),
]

# Stages that should run sequentially after static analysis
# e.g., Sandbox might take a long time and depend on static results
SEQUENTIAL_STAGES = [
    SandboxStage(),
]


def _cleanup_temp_dir(job_id: str) -> None:
    """Clean up temporary directory for a job."""
    temp_dir = Path(f"/tmp/{job_id}")
    if temp_dir.exists():
        try:
            shutil.rmtree(temp_dir)
            log.info("temp_dir_cleaned", job_id=job_id, path=str(temp_dir))
        except Exception as e:
            log.warning("temp_dir_cleanup_failed", job_id=job_id, error=str(e))


def _build_analysis_result(
    job_id: str,
    file_id: str,
    ctx: StageContext,
    results: list[StageResult],
    total_ms: int,
) -> dict[str, Any]:
    """Build complete analysis result for storage.

    Args:
        job_id: Job UUID.
        file_id: File UUID.
        ctx: Stage context with file info.
        results: List of stage results.
        total_ms: Total pipeline duration in milliseconds.

    Returns:
        Complete analysis result as JSON-serializable dict.
    """
    # Extract key findings from stage results
    stage_findings = {r.stage_name: r.findings for r in results}

    # Determine verdict based on findings
    verdict = "clean"
    score = 0

    # Check ClamAV result
    clamav = stage_findings.get("clamav", {})
    if clamav.get("infected"):
        verdict = "malicious"
        score = max(score, 90)

    # Check YARA result
    yara = stage_findings.get("yara", {})
    yara_matches = yara.get("matches", [])
    if yara_matches:
        verdict = "suspicious" if verdict == "clean" else verdict
        score = max(score, 50 + len(yara_matches) * 10)

    # Build file info
    filetype = stage_findings.get("file-type", {})
    file_info = {
        "file_id": file_id,
        "sha256": ctx.sha256,
        "mime": filetype.get("mime_type", "application/octet-stream"),
        "size": filetype.get("file_size", 0),
        "original_filename": ctx.original_filename,
    }

    # Build IOC info
    ioc_findings = stage_findings.get("ioc-extract", {})
    iocs = {
        "urls": ioc_findings.get("urls", []),
        "domains": ioc_findings.get("domains", []),
        "ips": ioc_findings.get("ip_addresses", []),
        "hashes": {
            "md5": ioc_findings.get("md5", ""),
            "sha1": ioc_findings.get("sha1", ""),
            "sha256": ctx.sha256,
        },
    }

    # Build timing info
    timings = {
        "total_ms": total_ms,
        "stages": [
            {
                "name": r.stage_name,
                "status": r.status,
                "duration_ms": r.duration_ms,
            }
            for r in results
        ],
    }

    return {
        "job_id": job_id,
        "file": file_info,
        "verdict": verdict,
        "score": min(score, 100),
        "results": {
            "av_result": {
                "engine": "ClamAV",
                "infected": clamav.get("infected", False),
                "threat_name": clamav.get("threat_name"),
            },
            "yara_hits": yara_matches,
            "iocs": iocs,
            "sandbox": stage_findings.get("sandbox", {}),
        },
        "timings": timings,
    }


async def _run_stage(stage, ctx: StageContext) -> StageResult:
    """Run a single stage with error handling and timeout."""
    stage_name = stage.name
    job_id = ctx.job_id
    file_id = ctx.file_id

    log.info("stage_started", job_id=job_id, file_id=file_id, stage=stage_name)

    try:
        # Run stage with timeout
        result = await asyncio.wait_for(
            stage.execute(ctx),
            timeout=settings.stage_timeout_seconds,
        )
    except asyncio.TimeoutError:
        result = StageResult(
            stage_name=stage_name,
            status="failed",
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_ms=settings.stage_timeout_seconds * 1000,
            findings={},
            artifacts=[],
            error=f"Stage timeout after {settings.stage_timeout_seconds}s",
        )
    except Exception as e:
        log.error("stage_error", job_id=job_id, file_id=file_id, stage=stage_name, error=str(e))
        result = StageResult(
            stage_name=stage_name,
            status="failed",
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_ms=0,
            findings={},
            artifacts=[],
            error=str(e),
        )

    # Record metrics
    stage_latency.labels(stage=stage_name, status=result.status).observe(result.duration_ms / 1000)

    log.info(
        "stage_completed",
        job_id=job_id,
        file_id=file_id,
        stage=stage_name,
        status=result.status,
        duration_ms=result.duration_ms,
    )

    return result


async def run_pipeline(job_data: dict[str, Any]) -> dict[str, Any]:
    """
    Run the analysis pipeline.

    Args:
        job_data: Message from RabbitMQ containing job_id, file_id, storage_key, etc.

    Returns:
        Complete analysis results.

    Raises:
        RuntimeError: If any stage fails or file download fails.
    """
    job_id = job_data["job_id"]
    file_id = job_data["file_id"]
    storage_key = job_data.get("storage_key", "")

    total_stages = len(PARALLEL_STAGES) + len(SEQUENTIAL_STAGES)

    log.info(
        "pipeline_started",
        job_id=job_id,
        file_id=file_id,
        storage_key=storage_key,
        stages_total=total_stages,
    )

    # Create work directory
    work_dir = Path(f"/tmp/{job_id}")

    try:
        # Download file from MinIO
        try:
            file_path = await download_file(storage_key, work_dir)
            log.info("file_downloaded", job_id=job_id, file_path=str(file_path))
        except Exception as e:
            log.error("file_download_failed", job_id=job_id, storage_key=storage_key, error=str(e))
            await update_job_status(job_id, "failed", error_message=f"Failed to download file: {e}")
            raise RuntimeError(f"Failed to download file from MinIO: {e}") from e

        # Fetch Job instance for context
        job_instance = await get_job_for_context(job_id)

        # Create context inside a single DB session
        async with AsyncSession(_engine) as session:
            ctx = StageContext(
                job_id=job_id,
                file_id=file_id,
                storage_key=storage_key,
                sha256=job_data.get("sha256", ""),
                original_filename=job_data.get("original_filename", "unknown"),
                file_path=file_path,
                previous_results=[],
                job=job_instance,
                db=session,
            )

            results: list[StageResult] = []
            total_start = datetime.now(timezone.utc)
            stages_done = 0

        # Update status to indicate parallel static analysis
        await update_job_stage(job_id, "static_analysis", stages_done)

        # 1. Run Parallel Stages
        log.info("starting_parallel_stages", count=len(PARALLEL_STAGES))
        tasks = [_run_stage(stage, ctx) for stage in PARALLEL_STAGES]

        # gather will run all tasks concurrently and return results in the same order
        parallel_results = await asyncio.gather(*tasks)

        results.extend(parallel_results)
        ctx.previous_results.extend(parallel_results)

        stages_done += len(PARALLEL_STAGES)

        # Check for failures in parallel stages
        for res in parallel_results:
            if res.status == "failed":
                log.error(
                    "pipeline_failed",
                    job_id=job_id,
                    file_id=file_id,
                    stage=res.stage_name,
                    error=res.error,
                )
                await update_job_status(
                    job_id,
                    "failed",
                    error_message=f"Stage {res.stage_name} failed: {res.error}",
                    current_stage=res.stage_name,
                    stages_done=stages_done,
                )
                raise RuntimeError(f"Stage {res.stage_name} failed: {res.error}")

        # Update status after static analysis
        await update_job_stage(job_id, "dynamic_analysis", stages_done)

        # 2. Run Sequential Stages (like Sandbox)
        for stage in SEQUENTIAL_STAGES:
            res = await _run_stage(stage, ctx)
            results.append(res)
            ctx.previous_results.append(res)
            stages_done += 1

            if res.status == "failed":
                log.error(
                    "pipeline_failed",
                    job_id=job_id,
                    file_id=file_id,
                    stage=res.stage_name,
                    error=res.error,
                )
                await update_job_status(
                    job_id,
                    "failed",
                    error_message=f"Stage {res.stage_name} failed: {res.error}",
                    current_stage=res.stage_name,
                    stages_done=stages_done,
                )
                raise RuntimeError(f"Stage {res.stage_name} failed: {res.error}")

        total_end = datetime.now(timezone.utc)
        total_ms = int((total_end - total_start).total_seconds() * 1000)

        log.info("pipeline_completed", job_id=job_id, file_id=file_id, total_ms=total_ms)

        # Build complete result for storage
        analysis_result = _build_analysis_result(
            job_id=job_id,
            file_id=file_id,
            ctx=ctx,
            results=results,
            total_ms=total_ms,
        )

        # Store result in database
        await update_job_result(job_id, analysis_result)

        # Update job status to done
        await update_job_status(
            job_id,
            "done",
            current_stage=None,
            stages_done=total_stages,
        )

        return {
            "job_id": job_id,
            "stages": [r.__dict__ for r in results],
            "total_ms": total_ms,
        }

    finally:
        # Always clean up temp directory
        _cleanup_temp_dir(job_id)
