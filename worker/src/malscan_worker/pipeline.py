"""Pipeline orchestrator for running analysis stages."""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from malscan_worker.config import get_settings
from malscan_worker.metrics import stage_latency
from malscan_worker.stages.base import StageContext, StageResult
from malscan_worker.stages.filetype import FileTypeStage
from malscan_worker.stages.clamav import ClamAVStage
from malscan_worker.stages.yara_scan import YaraStage
from malscan_worker.stages.ioc_extract import IocExtractStage
from malscan_worker.stages.sandbox import SandboxStage

log = structlog.get_logger()
settings = get_settings()


# Stage order
STAGES = [
    FileTypeStage(),
    ClamAVStage(),
    YaraStage(),
    IocExtractStage(),
    SandboxStage(),
]


async def run_pipeline(job_data: dict[str, Any]) -> dict[str, Any]:
    """
    Run the analysis pipeline.

    Args:
        job_data: Message from RabbitMQ containing job_id, file_id, storage_key, etc.

    Returns:
        Complete analysis results.
    """
    job_id = job_data["job_id"]
    file_id = job_data["file_id"]

    log.info(
        "pipeline_started",
        job_id=job_id,
        file_id=file_id,
        stages_total=len(STAGES),
    )

    # Create context
    ctx = StageContext(
        job_id=job_id,
        file_id=file_id,
        storage_key=job_data.get("storage_key", ""),
        sha256=job_data.get("sha256", ""),
        original_filename=job_data.get("original_filename", "unknown"),
        file_path=None,  # Will be set after downloading
        previous_results=[],
    )

    # TODO: Download file from MinIO
    # For now, use a placeholder path
    ctx.file_path = Path("/tmp") / f"{job_id}.bin"

    results: list[StageResult] = []
    total_start = datetime.now(timezone.utc)

    for i, stage in enumerate(STAGES):
        stage_name = stage.name

        log.info(
            "stage_started",
            job_id=job_id,
            file_id=file_id,
            stage=stage_name,
            stage_number=i + 1,
            stages_total=len(STAGES),
        )

        # TODO: Update job.current_stage in database

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
            log.error(
                "stage_error",
                job_id=job_id,
                file_id=file_id,
                stage=stage_name,
                error=str(e),
            )
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

        results.append(result)
        ctx.previous_results.append(result)

        # Record metrics
        stage_latency.labels(stage=stage_name, status=result.status).observe(
            result.duration_ms / 1000
        )

        log.info(
            "stage_completed",
            job_id=job_id,
            file_id=file_id,
            stage=stage_name,
            status=result.status,
            duration_ms=result.duration_ms,
        )

        # Fail-fast: stop on failure
        if result.status == "failed":
            log.error(
                "pipeline_failed",
                job_id=job_id,
                file_id=file_id,
                stage=stage_name,
                error=result.error,
            )
            # TODO: Update job.status = 'failed' in database
            # TODO: Write partial report
            raise RuntimeError(f"Stage {stage_name} failed: {result.error}")

    total_end = datetime.now(timezone.utc)
    total_ms = int((total_end - total_start).total_seconds() * 1000)

    log.info(
        "pipeline_completed",
        job_id=job_id,
        file_id=file_id,
        total_ms=total_ms,
    )

    # Compile report
    # TODO: Write report to database

    return {
        "job_id": job_id,
        "stages": [r.__dict__ for r in results],
        "total_ms": total_ms,
    }
