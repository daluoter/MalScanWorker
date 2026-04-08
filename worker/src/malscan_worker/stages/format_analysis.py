"""Format analysis stage that dispatches to analyzer registry."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from malscan_worker.analyzers import get_default_analyzer_registry
from malscan_worker.analyzers.base import AnalyzerArtifact
from malscan_worker.config import get_settings
from malscan_worker.db import create_artifact
from malscan_worker.stages.base import Stage, StageContext, StageResult
from malscan_worker.utils.submission import InternalJobSubmitter

log = structlog.get_logger()


class FormatAnalysisStage(Stage):
    """Run format-specific analyzer and submit extracted artifacts."""

    def __init__(self) -> None:
        self._registry = get_default_analyzer_registry()

    @property
    def name(self) -> str:
        return "format-analysis"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        if not ctx.file_path or not ctx.file_path.exists():
            return self._result(started_at, "skipped", {"reason": "File not found"})

        mime = self._get_mime(ctx)
        analyzer = self._registry.detect(ctx.file_path, mime)
        if analyzer is None:
            return self._result(started_at, "skipped", {"reason": "No analyzer matched"})

        try:
            analysis = await analyzer.analyze(ctx.file_path, ctx)
        except Exception as exc:
            log.error("format_analysis_failed", job_id=ctx.job_id, error=str(exc), exc_info=True)
            return self._result(
                started_at,
                "failed",
                {"reason": "Analyzer execution failed"},
                error=str(exc),
            )

        artifact_ids: list[str] = []
        sub_jobs_created = 0
        errors = list(analysis.errors)

        if analysis.extracted_artifacts and ctx.job:
            try:
                sub_jobs_created, artifact_ids, submit_errors = await self._submit_artifacts(
                    ctx,
                    analysis.extracted_artifacts,
                    analysis.analyzer_name or analyzer.name,
                )
                errors.extend(submit_errors)
            except Exception as exc:
                log.error(
                    "format_analysis_artifact_submission_failed",
                    job_id=ctx.job_id,
                    error=str(exc),
                    exc_info=True,
                )
                errors.append(f"artifact submission failed: {exc}")

        findings = {
            "analyzer": analysis.analyzer_name or analyzer.name,
            "format_type": analysis.format_type,
            "risk_score": analysis.risk_score,
            "risk_factors": analysis.risk_factors,
            "indicators": analysis.indicators,
            "features": analysis.features,
            "extracted_strings": analysis.extracted_strings[:200],
            "extracted_artifacts_count": len(analysis.extracted_artifacts),
            "sub_jobs_created": sub_jobs_created,
            "errors": errors,
        }

        return self._result(started_at, "ok", findings, artifacts=artifact_ids)

    @staticmethod
    def _get_mime(ctx: StageContext) -> str:
        """Extract MIME from file-type stage result."""
        for result in ctx.previous_results:
            if result.stage_name == "file-type":
                return str(result.findings.get("mime_type", "")).lower()
        return ""

    async def _submit_artifacts(
        self,
        ctx: StageContext,
        artifacts: list[AnalyzerArtifact],
        analyzer_name: str,
    ) -> tuple[int, list[str], list[str]]:
        """Create artifact records and submit non-duplicate sub-jobs."""
        if not ctx.job:
            return 0, [], []

        settings = get_settings()
        max_depth = getattr(settings, "max_job_depth", 3)
        if ctx.job.depth >= max_depth:
            log.info(
                "format_analysis_max_depth_reached",
                job_id=ctx.job_id,
                depth=ctx.job.depth,
                max_depth=max_depth,
            )
            return 0, [], [f"max depth {max_depth} reached"]

        root_artifact_id = ctx.root_artifact_id
        parent_artifact_id = ctx.artifact_id
        parent_job_id = str(ctx.job.id)
        parent_job_depth = ctx.job.depth
        ancestor_hashes = ctx.ancestor_hashes or set()

        created_ids: list[str] = []
        errors: list[str] = []
        seen_hashes: set[str] = set()
        submitted = 0

        if not root_artifact_id and artifacts:
            root_art = await create_artifact(
                parent_id=None,
                root_id=None,
                depth=0,
                sha256=ctx.sha256,
                size=os.path.getsize(ctx.file_path) if ctx.file_path else 0,
                original_filename=ctx.original_filename,
                extraction_source="format-analysis",
                archive_type=analyzer_name,
                root_job_id=ctx.job_id,
                job_id=ctx.job_id,
            )
            root_artifact_id = root_art["id"]
            parent_artifact_id = root_artifact_id

        submitter: InternalJobSubmitter | None = None

        for art in artifacts:
            art_path_raw = art.get("path", "")
            if not isinstance(art_path_raw, str) or not art_path_raw:
                continue

            art_path = Path(art_path_raw)
            if not art_path.exists():
                continue

            file_sha256 = str(art.get("sha256", "")).strip()
            if not file_sha256:
                file_sha256 = self._hash_file_sha256(art_path)

            if file_sha256 in ancestor_hashes:
                log.warning("format_analysis_cycle_detected", sha256=file_sha256, job_id=ctx.job_id)
                continue

            duplicate = file_sha256 in seen_hashes
            seen_hashes.add(file_sha256)

            file_size = int(art.get("size", art_path.stat().st_size))
            filename = str(art.get("filename", art_path.name))
            source = str(art.get("source", filename))

            record = await create_artifact(
                parent_id=parent_artifact_id,
                root_id=root_artifact_id,
                depth=parent_job_depth + 1,
                sha256=file_sha256,
                size=file_size,
                original_filename=filename,
                origin_path=source,
                extraction_source="format-analysis",
                archive_type=analyzer_name,
                root_job_id=ctx.job_id,
                verdict="skipped" if duplicate else None,
                extraction_note="duplicate_within_extraction" if duplicate else None,
            )
            created_ids.append(record["id"])

            if duplicate:
                continue

            try:
                if submitter is None:
                    submitter = await InternalJobSubmitter.get_instance()

                sub_job_id = await submitter.submit_subjob(
                    file_path=str(art_path),
                    filename=filename,
                    content_type="application/octet-stream",
                    sha256_hash=file_sha256,
                    file_size=file_size,
                    parent_job_id=parent_job_id,
                    parent_job_depth=parent_job_depth,
                    artifact_id=record["id"],
                    root_artifact_id=root_artifact_id,
                    ancestor_hashes=ancestor_hashes | {ctx.sha256},
                )
                if sub_job_id:
                    submitted += 1
            except Exception as exc:
                log.error(
                    "format_analysis_subjob_failed",
                    job_id=ctx.job_id,
                    artifact=filename,
                    error=str(exc),
                )
                errors.append(f"sub-job submit failed for {filename}: {exc}")

        return submitted, created_ids, errors

    @staticmethod
    def _hash_file_sha256(file_path: Path) -> str:
        hasher = hashlib.sha256()
        with file_path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

    def _result(
        self,
        started_at: datetime,
        status: str,
        findings: dict[str, Any],
        *,
        artifacts: list[str] | None = None,
        error: str | None = None,
    ) -> StageResult:
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status=status,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings=findings,
            artifacts=artifacts or [],
            error=error,
        )
