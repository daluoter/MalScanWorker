"""Pipeline orchestrator for running analysis stages."""

import asyncio
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from malscan_worker.config import get_settings
from malscan_worker.db import (
    _engine,
    get_job_for_context,
    update_job_result,
    update_job_stage,
    update_job_status,
)
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.metrics import stage_latency
from malscan_worker.stages.archive_extract import ArchiveExtractStage
from malscan_worker.stages.base import StageContext, StageResult
from malscan_worker.stages.clamav import ClamAVStage
from malscan_worker.stages.filetype import FileTypeStage
from malscan_worker.stages.format_analysis import FormatAnalysisStage
from malscan_worker.stages.ioc_extract import IocExtractStage
from malscan_worker.stages.sandbox import SandboxStage
from malscan_worker.stages.yara_scan import YaraStage
from malscan_worker.storage import download_file

log = structlog.get_logger()
settings = get_settings()


class _PipelineStage(Protocol):
    @property
    def name(self) -> str:
        ...

    async def execute(self, ctx: StageContext) -> StageResult:
        ...


# Stages that can run in parallel (Strictly no database writers here!)
PARALLEL_STAGES = [
    FileTypeStage(),
    ClamAVStage(),
    YaraStage(),  # type: ignore[no-untyped-call]
    IocExtractStage(),
]

FORMAT_ANALYSIS_STAGE = FormatAnalysisStage()

# Stages that should run sequentially
# ArchiveExtractStage MUST be here because it writes to the DB,
# and AsyncSession is not concurrency-safe.
# DocumentAnalysisStage also creates sub-jobs for extracted artifacts.
SEQUENTIAL_STAGES = [
    ArchiveExtractStage(),
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
    """Build complete analysis result for storage."""
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

    # ------------------------------------------------------------------
    # Document analysis scoring
    # ------------------------------------------------------------------
    doc = stage_findings.get("document-analysis", {})
    exploit_indicators = doc.get("exploit_indicators", [])
    macros = doc.get("macros", {})
    embedded_objects = doc.get("embedded_objects", [])
    suspicious_keywords = doc.get("suspicious_keywords", [])

    # Exploit indicators — each one adds significant risk
    if exploit_indicators:
        # Any Equation Editor or CVE indicator → very high risk
        has_equation = any(
            "equation_editor" in ind.get("type", "") or ind.get("cves")
            for ind in exploit_indicators
        )
        has_external_template = any(
            ind.get("type") in ("external_template", "external_relationship")
            for ind in exploit_indicators
        )
        has_dde = any(ind.get("type") == "dde_field" for ind in exploit_indicators)
        has_dangerous_class = any(
            ind.get("type") == "dangerous_ole_class" for ind in exploit_indicators
        )

        if has_equation:
            verdict = "malicious"
            score = max(score, 85)
        if has_external_template:
            # External template injection is a strong exploit signal
            if verdict == "clean":
                verdict = "suspicious"
            score = max(score, 70)
        if has_dde:
            if verdict == "clean":
                verdict = "suspicious"
            score = max(score, 60)
        if has_dangerous_class:
            if verdict == "clean":
                verdict = "suspicious"
            score = max(score, 55)

        # General: each exploit indicator beyond the first adds 5 pts
        extra = max(0, len(exploit_indicators) - 1) * 5
        score = max(score, 50 + extra)
        if verdict == "clean":
            verdict = "suspicious"

    # Macros with auto-exec + suspicious keywords → elevated risk
    if macros.get("found"):
        if macros.get("auto_exec") and macros.get("suspicious"):
            # Auto-executing macros with suspicious API calls
            if verdict == "clean":
                verdict = "suspicious"
            score = max(score, 65 + min(len(suspicious_keywords), 10) * 2)
        elif macros.get("auto_exec"):
            # Auto-exec but no obviously suspicious keywords
            if verdict == "clean":
                verdict = "suspicious"
            score = max(score, 45)
        elif macros.get("suspicious"):
            # Suspicious keywords but no auto-exec
            if verdict == "clean":
                verdict = "suspicious"
            score = max(score, 40)
        else:
            # Macros exist but seem benign
            score = max(score, 15)

    # Embedded objects count — more objects = higher suspicion
    if len(embedded_objects) > 3:
        score = max(score, 30 + len(embedded_objects) * 2)
        if verdict == "clean":
            verdict = "suspicious"

    # ------------------------------------------------------------------
    # Format analysis scoring
    # ------------------------------------------------------------------
    fmt = stage_findings.get("format-analysis", {})
    fmt_risk_score = int(fmt.get("risk_score", 0) or 0)
    fmt_indicators = fmt.get("indicators", [])
    for indicator in fmt_indicators:
        severity = str(indicator.get("severity", "")).lower()
        if severity == "critical":
            verdict = "malicious"
            score = max(score, 85)
        elif severity == "high":
            if verdict == "clean":
                verdict = "suspicious"
            score = max(score, 60)
        elif severity == "medium":
            if verdict == "clean":
                verdict = "suspicious"
    score = max(score, fmt_risk_score)

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

    # Build document analysis summary for report
    doc_analysis: dict[str, Any] = {}
    if doc:
        doc_analysis = {
            "document_type": doc.get("document_type"),
            "exploit_indicators": exploit_indicators,
            "macros": macros,
            "embedded_objects_count": len(embedded_objects),
            "embedded_objects": embedded_objects[:20],  # cap for report size
            "extracted_artifacts_count": len(doc.get("extracted_artifacts", [])),
            "extracted_artifacts": [
                {
                    "filename": a.get("filename"),
                    "sha256": a.get("sha256"),
                    "size": a.get("size"),
                    "source": a.get("source"),
                }
                for a in doc.get("extracted_artifacts", [])
            ],
            "suspicious_keywords": suspicious_keywords,
            "sub_jobs_created": doc.get("sub_jobs_created", 0),
            "parser_findings": doc.get("parser_findings", [])[:50],
            "errors": doc.get("errors", []),
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
            "format_analysis": {
                "analyzer": fmt.get("analyzer"),
                "format_type": fmt.get("format_type"),
                "risk_score": fmt_risk_score,
                "risk_factors": fmt.get("risk_factors", []),
                "indicators": fmt_indicators,
                "features": fmt.get("features", {}),
            },
            "document_analysis": doc_analysis,
            "sandbox": stage_findings.get("sandbox", {}),
            "archive_extract": stage_findings.get("archive-extract", {}),
        },
        "timings": timings,
    }


async def _run_stage(stage: _PipelineStage, ctx: StageContext) -> StageResult:
    """Run a single stage with error handling and timeout."""
    stage_name = stage.name
    job_id = ctx.job_id

    log.info("stage_starting", job_id=job_id, stage=stage_name)
    start_time = datetime.now(timezone.utc)

    try:
        # Run stage with timeout
        timeout = getattr(settings, "stage_timeout_seconds", 300)

        result = await asyncio.wait_for(
            stage.execute(ctx),
            timeout=timeout,
        )

        # Record metrics
        stage_latency.labels(stage=stage_name, status=result.status).observe(
            result.duration_ms / 1000
        )

        log.info(
            "stage_completed",
            job_id=job_id,
            stage=stage_name,
            status=result.status,
            duration_ms=result.duration_ms,
        )
        return result

    except asyncio.TimeoutError:
        log.error("stage_timeout", job_id=job_id, stage=stage_name)
        now = datetime.now(timezone.utc)
        return StageResult(
            stage_name=stage_name,
            status="failed",
            started_at=start_time,
            ended_at=now,
            duration_ms=int((now - start_time).total_seconds() * 1000),
            findings={},
            artifacts=[],
            error=f"Stage timeout after {timeout}s",
        )
    except (ArchivePasswordRequiredError, ArchiveWrongPasswordError):
        raise
    except Exception as e:
        log.error("stage_error", job_id=job_id, stage=stage_name, error=str(e), exc_info=True)
        now = datetime.now(timezone.utc)
        return StageResult(
            stage_name=stage_name,
            status="failed",
            started_at=start_time,
            ended_at=now,
            duration_ms=int((now - start_time).total_seconds() * 1000),
            findings={},
            artifacts=[],
            error=str(e),
        )


async def run_pipeline(job_data: dict[str, Any]) -> dict[str, Any]:
    """Run the analysis pipeline with high resilience."""
    job_id = job_data["job_id"]
    file_id = job_data["file_id"]
    storage_key = job_data.get("storage_key", "")

    total_stages = len(PARALLEL_STAGES) + 1 + len(SEQUENTIAL_STAGES)

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

        results: list[StageResult] = []
        total_start = datetime.now(timezone.utc)
        stages_done = 0

        # Create context inside a single DB session that spans the entire pipeline.
        async with AsyncSession(_engine) as session:
            # Fetch job instance INSIDE the session
            job_instance = await get_job_for_context(job_id, session=session)

            ctx = StageContext(
                job_id=job_id,
                file_id=file_id,
                storage_key=storage_key,
                sha256=job_data.get("sha256", ""),
                original_filename=job_data.get("original_filename", "unknown"),
                file_path=file_path,
                archive_password=job_data.get("archive_password"),
                previous_results=[],
                job=job_instance,
                db=session,
                artifact_id=job_data.get("artifact_id"),
                root_artifact_id=job_data.get("root_artifact_id"),
                ancestor_hashes=set(job_data.get("ancestor_hashes", [])),
            )

            # Update status to indicate parallel static analysis
            await update_job_stage(job_id, "static_analysis", stages_done)

            # 1. Run Parallel Stages
            # IMPORTANT: We use gathering for I/O efficiency, but NONE of these stages
            # should use the shared 'session' concurrently.
            log.info("starting_parallel_stages", count=len(PARALLEL_STAGES))
            tasks = [_run_stage(stage, ctx) for stage in PARALLEL_STAGES]
            parallel_results = await asyncio.gather(*tasks)

            results.extend(parallel_results)
            ctx.previous_results.extend(parallel_results)
            stages_done += len(PARALLEL_STAGES)

            # 2. Run format analysis stage before sequential stages.
            format_result = await _run_stage(FORMAT_ANALYSIS_STAGE, ctx)
            results.append(format_result)
            ctx.previous_results.append(format_result)
            stages_done += 1

            # Check for critical failures?
            # For now, we remain resilient and continue even if some
            # parallel stages fail (like ClamAV).
            # Only if the whole system crashes do we stop.

            # Update status after static analysis
            await update_job_stage(job_id, "recursive_analysis", stages_done)

            # 3. Run Sequential Stages (like ArchiveExtract and Sandbox)
            for stage in SEQUENTIAL_STAGES:
                res = await _run_stage(stage, ctx)
                results.append(res)
                ctx.previous_results.append(res)
                stages_done += 1

                # We continue even if sub-jobs fail to create or sandbox fails,
                # as we still want to save the primary report.

        total_end = datetime.now(timezone.utc)
        total_ms = int((total_end - total_start).total_seconds() * 1000)

        log.info("pipeline_completed_saving_report", job_id=job_id, total_ms=total_ms)

        # Build complete result for storage
        # Even if some stages failed, this will contain what we HAVE.
        analysis_result = _build_analysis_result(
            job_id=job_id,
            file_id=file_id,
            ctx=ctx,
            results=results,
            total_ms=total_ms,
        )

        # Store result in database
        await update_job_result(job_id, analysis_result)

        # Update artifact verdict if this job is linked to an artifact
        if job_data.get("artifact_id"):
            try:
                from malscan_worker.db import update_artifact_verdict

                await update_artifact_verdict(
                    artifact_id=job_data["artifact_id"],
                    verdict=analysis_result["verdict"],
                    score=analysis_result["score"],
                )
            except Exception:
                log.exception(
                    "failed_to_update_artifact_verdict", artifact_id=job_data["artifact_id"]
                )

        # Determine final status
        # If we reached here, the job is technically "done",
        # even if it found malware or had partial failures.
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
            "verdict": analysis_result["verdict"],
        }

    finally:
        # Always clean up temp directory
        _cleanup_temp_dir(job_id)
