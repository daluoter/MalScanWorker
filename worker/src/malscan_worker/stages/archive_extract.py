"""Archive extraction stage for processing compressed files.

Uses the pluggable handler registry to detect and extract archives,
creates artifact records for extracted files, and submits sub-jobs.
"""

import asyncio
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import structlog

from malscan_worker.config import get_settings
from malscan_worker.db import create_artifact
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.extractors import (
    ExtractionLimits,
    get_default_registry,
)
from malscan_worker.extractors.safety import remove_symlinks
from malscan_worker.stages.base import Stage, StageContext, StageResult
from malscan_worker.utils.submission import InternalJobSubmitter

logger = structlog.get_logger()


class ArchiveExtractStage(Stage):
    """Extract files from archives and submit them as sub-jobs.

    Uses the handler registry to detect archive formats and delegates
    extraction to the appropriate format handler.  Creates artifact
    records for every extracted file and submits sub-jobs via MQ.
    """

    def __init__(self) -> None:
        self._registry = get_default_registry()

    @property
    def name(self) -> str:
        return "archive-extract"

    # ------------------------------------------------------------------
    # Main execute
    # ------------------------------------------------------------------

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)
        settings = get_settings()

        # --- Skip checks ---------------------------------------------------
        if not ctx.file_path or not os.path.exists(ctx.file_path):
            return self._skip_result(started_at, "File not found")

        max_depth = getattr(settings, "max_job_depth", 3)
        if ctx.job and ctx.job.depth >= max_depth:
            return self._skip_result(started_at, f"Max depth {max_depth} reached")

        # --- Detect format --------------------------------------------------
        mime = self._get_mime(ctx)
        handler = self._registry.detect(ctx.file_path, mime)
        if handler is None:
            return self._skip_result(started_at, "Not an archive")

        logger.info(
            "archive_format_detected",
            job_id=ctx.job_id,
            format=handler.name,
            file=str(ctx.file_path),
        )

        # --- Build limits ---------------------------------------------------
        limits = ExtractionLimits(
            max_files=settings.extraction_max_files,
            max_extracted_bytes=settings.extraction_max_bytes,
            max_single_file_bytes=settings.extraction_max_single_bytes,
            max_expansion_ratio=settings.extraction_max_ratio,
            timeout_seconds=settings.extraction_timeout,
        )

        # --- Create root artifact if depth-0 and no artifact context yet ----
        root_artifact_id = ctx.root_artifact_id
        parent_artifact_id = ctx.artifact_id
        root_job_id = ctx.job_id

        if not root_artifact_id and ctx.job:
            root_art = await create_artifact(
                parent_id=None,
                root_id=None,  # will self-reference after creation
                depth=0,
                sha256=ctx.sha256,
                size=os.path.getsize(ctx.file_path),
                original_filename=ctx.original_filename,
                extraction_source="archive-extract",
                archive_type=handler.name,
                root_job_id=ctx.job_id,
                job_id=ctx.job_id,
            )
            root_artifact_id = root_art["id"]
            parent_artifact_id = root_artifact_id

        # --- Extract with timeout -------------------------------------------
        extract_dir = Path(f"/tmp/{ctx.job_id}/extract")
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    handler.extract,
                    ctx.file_path,
                    extract_dir,
                    limits,
                    ctx.archive_password,
                ),
                timeout=limits.timeout_seconds,
            )
        except asyncio.TimeoutError:
            return self._error_result(started_at, "Extraction timed out")
        except (ArchivePasswordRequiredError, ArchiveWrongPasswordError):
            raise
        except Exception as exc:
            logger.error(
                "archive_extraction_failed",
                job_id=ctx.job_id,
                error=str(exc),
                exc_info=True,
            )
            return self._error_result(started_at, f"Extraction failed: {exc!s}")

        # --- Zip bomb check -------------------------------------------------
        if result.malicious:
            return self._malicious_result(
                started_at, result.reason or "Malicious archive", handler.name
            )

        # --- Remove symlinks for safety -------------------------------------
        remove_symlinks(str(extract_dir))

        # --- Process extracted files ----------------------------------------
        seen_hashes: set[str] = set()
        created_artifacts: list[str] = []
        sub_jobs_created = 0
        ancestor_hashes = ctx.ancestor_hashes or set()

        # Only initialise submitter when we have a real job context
        submitter = await InternalJobSubmitter.get_instance() if ctx.job else None

        for ef in result.files:
            # Compute SHA256
            file_sha256 = hashlib.sha256(open(ef.path, "rb").read()).hexdigest()

            # Cycle detection — skip if hash matches an ancestor
            if file_sha256 in ancestor_hashes:
                logger.warning(
                    "recursive_loop_detected",
                    sha256=file_sha256,
                    origin=ef.origin_path,
                )
                continue

            # Extraction-level dedup
            skip = file_sha256 in seen_hashes
            seen_hashes.add(file_sha256)

            # Create artifact record and submit sub-job only with a real job
            if ctx.job:
                art = await create_artifact(
                    parent_id=parent_artifact_id,
                    root_id=root_artifact_id,
                    depth=ctx.job.depth + 1,
                    sha256=file_sha256,
                    size=ef.size,
                    original_filename=ef.original_name,
                    origin_path=ef.origin_path,
                    extraction_source="archive-extract",
                    archive_type=handler.name,
                    root_job_id=root_job_id if root_job_id else ctx.job_id,
                    verdict="skipped" if skip else None,
                    extraction_note="duplicate_within_extraction" if skip else None,
                )
                created_artifacts.append(art["id"])

            if skip:
                continue

            # Submit sub-job
            if submitter:
                try:
                    sub_job_id = await submitter.submit_subjob(
                        file_path=ef.path,
                        filename=ef.original_name,
                        content_type="application/octet-stream",
                        sha256_hash=file_sha256,
                        file_size=ef.size,
                        parent_job_id=str(ctx.job.id),
                        parent_job_depth=ctx.job.depth,
                        artifact_id=art["id"],
                        root_artifact_id=root_artifact_id,
                        ancestor_hashes=ancestor_hashes | {ctx.sha256},
                    )
                    if sub_job_id:
                        sub_jobs_created += 1
                except Exception as exc:
                    logger.error(
                        "subjob_submission_failed",
                        job_id=ctx.job_id,
                        filename=ef.original_name,
                        error=str(exc),
                    )

        # --- Build final result ---------------------------------------------
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status="ok",
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings={
                "archive_type": handler.name,
                "extracted_count": len(result.files),
                "sub_jobs_created": sub_jobs_created,
                "artifacts_created": len(created_artifacts),
                "warnings": result.warnings,
                "total_extracted_bytes": sum(ef.size for ef in result.files),
            },
            artifacts=created_artifacts,
        )

    # ------------------------------------------------------------------
    # MIME helper — extracts MIME from previous file-type stage results
    # ------------------------------------------------------------------

    def _get_mime(self, ctx: StageContext) -> str:
        """Get MIME type from the file-type stage in previous results."""
        for res in ctx.previous_results:
            if res.stage_name == "file-type":
                return (res.findings.get("mime_type") or "").lower()
        return ""

    # ------------------------------------------------------------------
    # Result helpers
    # ------------------------------------------------------------------

    def _skip_result(self, started_at: datetime, reason: str) -> StageResult:
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status="skipped",
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings={"reason": reason},
            artifacts=[],
        )

    def _error_result(self, started_at: datetime, reason: str) -> StageResult:
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status="error",
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings={"reason": reason},
            artifacts=[],
        )

    def _malicious_result(
        self, started_at: datetime, reason: str, archive_type: str
    ) -> StageResult:
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status="malicious",
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings={
                "malicious": True,
                "reason": reason,
                "archive_type": archive_type,
            },
            artifacts=[],
        )
