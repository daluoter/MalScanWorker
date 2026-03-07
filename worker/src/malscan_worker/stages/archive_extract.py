"""Archive extraction stage for processing ZIP files."""

import hashlib
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from malscan.config import get_settings

from malscan_worker.stages.base import Stage, StageContext, StageResult
from malscan_worker.utils.submission import InternalJobSubmitter


class ArchiveExtractStage(Stage):
    """Extract files from archives (e.g., ZIP) and submit them as sub-jobs."""

    @property
    def name(self) -> str:
        return "archive-extract"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)
        settings = get_settings()

        max_depth = getattr(settings, "max_job_depth", 3)

        if not ctx.file_path or not ctx.file_path.exists():
            return self._build_result(
                started_at, "skipped", {"reason": "File not found"}
            )

        # Skip if max recursion depth reached
        if ctx.job and ctx.job.depth >= max_depth:
            return self._build_result(
                started_at, "skipped", {"reason": "Max recursion depth reached"}
            )

        # Proceed only if it's a ZIP file
        if not zipfile.is_zipfile(ctx.file_path):
            return self._build_result(
                started_at, "skipped", {"reason": "Not a valid ZIP archive"}
            )

        extracted_files = []
        sub_jobs_created = 0
        is_malicious = False
        malicious_reason = None

        # Defense limits
        max_files = 10
        max_total_size = 150 * 1024 * 1024  # 150MB
        max_single_size = getattr(
            settings, "max_file_size", 100 * 1024 * 1024
        )
        max_expansion_ratio = 100

        archive_size = ctx.file_path.stat().st_size
        total_extracted_size = 0

        extract_dir = Path(f"/tmp/{ctx.job_id}/extracted")
        extract_dir.mkdir(parents=True, exist_ok=True)
        base_dir_abs = os.path.abspath(str(extract_dir))

        try:
            with zipfile.ZipFile(ctx.file_path, "r") as zf:
                for i, info in enumerate(zf.infolist()):
                    if i >= max_files:
                        break  # Limit number of files

                    if info.is_dir():
                        continue

                    # Zip Slip Defense
                    target_path = os.path.join(base_dir_abs, info.filename)
                    abs_target = os.path.abspath(target_path)
                    if not abs_target.startswith(base_dir_abs):
                        continue  # Malicious path traversal attempt

                    # Zip Bomb Defense (Single Size)
                    if info.file_size > max_single_size:
                        is_malicious = True
                        malicious_reason = (
                            f"File {info.filename} exceeds single file size limit."
                        )
                        break

                    # Zip Bomb Defense (Total Size)
                    total_extracted_size += info.file_size
                    if total_extracted_size > max_total_size:
                        is_malicious = True
                        malicious_reason = (
                            "Total extracted size exceeds allowed maximum."
                        )
                        break

                    # Zip Bomb Defense (Expansion Ratio)
                    if archive_size > 0:
                        expansion_ratio = info.file_size / archive_size
                        if expansion_ratio > max_expansion_ratio:
                            is_malicious = True
                            malicious_reason = (
                                f"Expansion ratio ({expansion_ratio:.1f}x) "
                                f"exceeds limit ({max_expansion_ratio}x)."
                            )
                            break

                    # Extract file securely
                    extracted_path = zf.extract(info, path=base_dir_abs)
                    extracted_files.append(
                        (extracted_path, info.filename, info.file_size)
                    )

            if is_malicious:
                ended_at = datetime.now(timezone.utc)
                dur = int((ended_at - started_at).total_seconds() * 1000)
                return StageResult(
                    stage_name=self.name,
                    status="ok",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=dur,
                    findings={
                        "malicious": True,
                        "reason": malicious_reason,
                        "high_risk": True,
                    },
                    artifacts=[],
                )

            # Submit extracted files as sub-jobs
            if ctx.job and ctx.db:
                submitter = await InternalJobSubmitter.get_instance()

                for file_path, original_filename, file_size in extracted_files:
                    path_obj = Path(file_path)

                    # Calculate SHA256 of extracted file
                    hasher = hashlib.sha256()
                    with open(path_obj, "rb") as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            hasher.update(chunk)
                    file_sha256 = hasher.hexdigest()

                    # Submit sub-job
                    await submitter.submit_subjob(
                        db=ctx.db,
                        file_path=str(path_obj),
                        filename=original_filename,
                        content_type="application/octet-stream",
                        sha256_hash=file_sha256,
                        file_size=file_size,
                        parent_job=ctx.job,
                    )
                    sub_jobs_created += 1

        except zipfile.BadZipFile as e:
            return self._build_result(
                started_at, "failed", {"error": f"Bad zip file: {e!s}"}
            )
        except Exception as e:
            return self._build_result(
                started_at, "failed", {"error": str(e)}
            )

        return self._build_result(started_at, "ok", {
            "extracted_count": len(extracted_files),
            "sub_jobs_created": sub_jobs_created,
            "total_extracted_bytes": total_extracted_size,
        })

    def _build_result(
        self, started_at: datetime, status: str, findings: dict
    ) -> StageResult:
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status=status,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings=findings,
            artifacts=[],
        )
