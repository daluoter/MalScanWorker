"""Archive extraction stage for processing compressed files.

Supports ZIP, 7z, RAR, tar (gz/bz2/xz), gzip, and bz2 formats.
"""

import bz2
import gzip
import hashlib
import os
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
from malscan.config import get_settings

from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.stages.base import Stage, StageContext, StageResult
from malscan_worker.utils.submission import InternalJobSubmitter

log = structlog.get_logger()

# Optional dependencies — graceful degradation if not installed
try:
    import py7zr

    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False

try:
    import rarfile

    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False


class ArchiveExtractStage(Stage):
    """Extract files from archives and submit them as sub-jobs.

    Supported formats: ZIP, 7z, RAR, tar(.gz/.bz2/.xz), gzip, bz2.
    """

    @property
    def name(self) -> str:
        return "archive-extract"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        log.info("archive_extract_start", job_id=ctx.job_id, file=str(ctx.file_path))

        settings = get_settings()
        max_depth = getattr(settings, "max_job_depth", 3)

        if not ctx.file_path or not ctx.file_path.exists():
            log.warning("archive_extract_file_not_found", job_id=ctx.job_id)
            return self._build_result(started_at, "skipped", {"reason": "File not found"})

        # Skip if max recursion depth reached
        current_depth = getattr(ctx.job, "depth", 0)
        if current_depth >= max_depth:
            log.info("archive_extract_max_depth_reached", job_id=ctx.job_id, depth=current_depth)
            return self._build_result(
                started_at, "skipped", {"reason": "Max recursion depth reached"}
            )

        # Detect archive format
        archive_type = self._detect_format(ctx)
        if archive_type is None:
            log.info("archive_extract_not_supported_format", job_id=ctx.job_id)
            return self._build_result(
                started_at, "skipped", {"reason": "Not a supported archive format"}
            )

        log.info(
            "archive_format_detected",
            job_id=ctx.job_id,
            format=archive_type,
            file=str(ctx.file_path),
        )

        # Defense limits
        max_files = 15  # Increased slightly
        max_total_size = 200 * 1024 * 1024  # 200MB
        max_single_size = getattr(settings, "max_file_size", 100 * 1024 * 1024)
        max_expansion_ratio = 100

        archive_size = ctx.file_path.stat().st_size

        extract_dir = Path(f"/tmp/{ctx.job_id}/extracted")
        extract_dir.mkdir(parents=True, exist_ok=True)

        log.info("archive_extracting", job_id=ctx.job_id, dir=str(extract_dir))

        try:
            result = self._extract(
                archive_type=archive_type,
                file_path=ctx.file_path,
                extract_dir=extract_dir,
                archive_size=archive_size,
                max_files=max_files,
                max_total_size=max_total_size,
                max_single_size=max_single_size,
                max_expansion_ratio=max_expansion_ratio,
                archive_password=ctx.archive_password,
            )
        except (ArchivePasswordRequiredError, ArchiveWrongPasswordError):
            raise
        except Exception as e:
            log.error("archive_extraction_failed", job_id=ctx.job_id, error=str(e), exc_info=True)
            return self._build_result(started_at, "failed", {"error": f"Extraction failed: {e!s}"})

        # If malicious archive detected (e.g. zip bomb)
        if result.get("malicious"):
            log.warning(
                "archive_malicious_detected",
                job_id=ctx.job_id,
                reason=result.get("reason"),
            )
            return self._build_result(started_at, "ok", result)

        extracted_files = result.get("files", [])
        log.info("archive_extracted_files_collected", job_id=ctx.job_id, count=len(extracted_files))

        sub_jobs_created = 0

        # Submit extracted files as sub-jobs
        if ctx.job and extracted_files:
            # Pre-capture parent job attributes as plain values BEFORE any
            # async operations that might expire the ORM object.
            parent_job_id = str(ctx.job.id)
            parent_job_depth = ctx.job.depth

            try:
                submitter = await InternalJobSubmitter.get_instance()

                for file_path, original_filename, file_size in extracted_files:
                    path_obj = Path(file_path)

                    if not path_obj.exists():
                        log.warning("extracted_file_missing_on_disk", path=str(path_obj))
                        continue

                    # Calculate SHA256 of extracted file
                    hasher = hashlib.sha256()
                    with open(path_obj, "rb") as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            hasher.update(chunk)
                    file_sha256 = hasher.hexdigest()

                    log.info(
                        "submitting_subjob",
                        job_id=ctx.job_id,
                        filename=original_filename,
                        sha256=file_sha256,
                    )

                    # Submit sub-job (uses its own independent DB session)
                    try:
                        result_id = await submitter.submit_subjob(
                            file_path=str(path_obj),
                            filename=original_filename,
                            content_type="application/octet-stream",
                            sha256_hash=file_sha256,
                            file_size=file_size,
                            parent_job_id=parent_job_id,
                            parent_job_depth=parent_job_depth,
                        )
                        if result_id:
                            sub_jobs_created += 1
                    except Exception as e:
                        log.error(
                            "subjob_submission_failed",
                            job_id=ctx.job_id,
                            filename=original_filename,
                            error=str(e),
                        )
            except Exception as e:
                log.error(
                    "submitter_initialization_failed",
                    job_id=ctx.job_id,
                    error=str(e),
                    exc_info=True,
                )
                return self._build_result(
                    started_at,
                    "failed",
                    {"error": f"Failed to initialize sub-job submitter: {e!s}"},
                )

        log.info("archive_extract_finished", job_id=ctx.job_id, sub_jobs=sub_jobs_created)

        return self._build_result(
            started_at,
            "ok",
            {
                "archive_type": archive_type,
                "extracted_count": len(extracted_files),
                "sub_jobs_created": sub_jobs_created,
                "total_extracted_bytes": sum(f[2] for f in extracted_files),
            },
        )

    # ------------------------------------------------------------------
    # Format detection
    # ------------------------------------------------------------------

    def _detect_format(self, ctx: StageContext) -> str | None:
        """Detect archive format using multiple signals."""
        file_path = ctx.file_path

        # Priority 1: Magic number detection (most reliable)
        try:
            with open(file_path, "rb") as f:
                magic = f.read(8)
            if magic.startswith(b"PK\x03\x04"):
                return "zip"
            if magic.startswith(b"7z\xbc\xaf\x27\x1c"):
                return "7z"
            if magic.startswith(b"Rar!\x1a\x07"):
                return "rar"
            if magic.startswith(b"\x1f\x8b"):
                return "gzip"
            if magic.startswith(b"BZ"):
                return "bz2"
        except Exception:
            pass

        # Priority 2: Use results from FileTypeStage and extension
        file_type_findings = {}
        for res in ctx.previous_results:
            if res.stage_name == "file-type":
                file_type_findings = res.findings
                break

        mime = file_type_findings.get("mime_type", "").lower()
        ext = file_path.suffix.lower()

        # Also check original filename extension when downloaded file has no extension
        original_ext = ""
        if ctx.original_filename:
            from pathlib import PurePosixPath

            original_ext = PurePosixPath(ctx.original_filename).suffix.lower()

        log.debug("detecting_format", mime=mime, extension=ext)

        # ZIP
        if "zip" in mime or ext == ".zip" or zipfile.is_zipfile(file_path):
            return "zip"

        # 7z
        if (
            "7z" in mime
            or ext == ".7z"
            or original_ext == ".7z"
            or mime == "application/x-compressed"
        ):
            if HAS_PY7ZR:
                # Use string path for py7zr compatibility in some environments
                if py7zr.is_7zfile(str(file_path)):
                    return "7z"
                log.warning(
                    "7z_signature_check_failed_but_detected_by_mime_ext",
                    file=str(file_path),
                )
                # Fallback to 7z if mime/ext says so, extractor will try anyway
                return "7z"

        # RAR
        if "rar" in mime or ext == ".rar":
            if HAS_RARFILE:
                if rarfile.is_rarfile(str(file_path)):
                    return "rar"
                return "rar"

        # Tar
        if "tar" in mime or ext in [".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz"]:
            if tarfile.is_tarfile(file_path):
                return "tar"

        # Gzip / Bzip2
        if mime == "application/gzip" or ext == ".gz":
            return "gzip"
        if mime == "application/x-bzip2" or ext == ".bz2":
            return "bz2"

        # Magic number fallbacks
        try:
            with open(file_path, "rb") as f:
                magic = f.read(8)
            if magic.startswith(b"PK\x03\x04"):
                return "zip"
            if magic.startswith(b"7z\xbc\xaf\x27\x1c"):
                return "7z"
            if magic.startswith(b"Rar!\x1a\x07"):
                return "rar"
            if magic.startswith(b"\x1f\x8b"):
                return "gzip"
            if magic.startswith(b"BZ"):
                return "bz2"
        except Exception:
            pass

        return None

    # ------------------------------------------------------------------
    # Extraction dispatcher
    # ------------------------------------------------------------------

    def _extract(self, **args: Any) -> dict[str, Any]:
        """Extract files from archive."""
        archive_type = args["archive_type"]
        extractors = {
            "zip": self._extract_zip,
            "7z": self._extract_7z,
            "rar": self._extract_rar,
            "tar": self._extract_tar,
            "gzip": self._extract_single_compressed,
            "bz2": self._extract_single_compressed,
        }
        extractor = extractors.get(archive_type)
        if extractor is None:
            return {"files": []}

        return extractor(**args)

    # ------------------------------------------------------------------
    # Extractor implementations
    # ------------------------------------------------------------------

    def _extract_zip(self, file_path: Path, extract_dir: Path, **limits: Any) -> dict[str, Any]:
        extracted_files: list[tuple[str, str, int]] = []
        total_extracted_size = 0
        base_dir_abs = os.path.abspath(str(extract_dir))
        archive_password: str | None = limits.get("archive_password")
        password_bytes = archive_password.encode() if archive_password else None

        with zipfile.ZipFile(file_path, "r") as zf:
            for i, info in enumerate(zf.infolist()):
                if i >= limits["max_files"]:
                    break
                if info.is_dir():
                    continue

                is_encrypted = bool(getattr(info, "flag_bits", 0) & 0x1)
                if is_encrypted and not password_bytes:
                    raise ArchivePasswordRequiredError("zip")

                # Path traversal defense
                target_path = os.path.join(base_dir_abs, info.filename)
                if not os.path.abspath(target_path).startswith(base_dir_abs):
                    continue

                # Size checks
                res = self._check_size_limits(
                    info.file_size, total_extracted_size, limits, info.filename
                )
                if res:
                    return res

                total_extracted_size += info.file_size
                try:
                    extracted_path = zf.extract(info, path=base_dir_abs, pwd=password_bytes)
                except RuntimeError as exc:
                    msg = str(exc).lower()
                    if "bad password" in msg or "wrong password" in msg:
                        raise ArchiveWrongPasswordError("zip") from exc
                    if "password required" in msg or "encrypted" in msg:
                        raise ArchivePasswordRequiredError("zip") from exc
                    raise
                extracted_files.append((extracted_path, info.filename, info.file_size))

        return {"files": extracted_files}

    def _extract_7z(self, file_path: Path, extract_dir: Path, **limits: Any) -> dict[str, Any]:
        if not HAS_PY7ZR:
            return {"files": []}
        extracted_files: list[tuple[str, str, int]] = []
        base_dir_abs = os.path.abspath(str(extract_dir))

        with py7zr.SevenZipFile(str(file_path), mode="r") as szf:
            # We skip pre-check size logic due to py7zr's all-or-nothing extraction
            # and rely on the fact that we follow up with os.walk
            szf.extractall(path=base_dir_abs)

            for root, _, files in os.walk(base_dir_abs):
                for fname in files:
                    abs_path = os.path.join(root, fname)
                    rel_path = os.path.relpath(abs_path, base_dir_abs)
                    size = os.path.getsize(abs_path)
                    extracted_files.append((abs_path, rel_path, size))

        return {"files": extracted_files}

    def _extract_rar(self, file_path: Path, extract_dir: Path, **limits: Any) -> dict[str, Any]:
        if not HAS_RARFILE:
            return {"files": []}
        extracted_files: list[tuple[str, str, int]] = []
        base_dir_abs = os.path.abspath(str(extract_dir))

        with rarfile.RarFile(str(file_path), "r") as rf:
            for i, info in enumerate(rf.infolist()):
                if i >= limits["max_files"]:
                    break
                if info.is_dir():
                    continue

                target_path = os.path.join(base_dir_abs, info.filename)
                if not os.path.abspath(target_path).startswith(base_dir_abs):
                    continue

                res = self._check_size_limits(info.file_size, 0, limits, info.filename)
                if res:
                    return res

                rf.extract(info, path=base_dir_abs)
                extracted_files.append((target_path, info.filename, info.file_size))

        return {"files": extracted_files}

    def _extract_tar(self, file_path: Path, extract_dir: Path, **limits: Any) -> dict[str, Any]:
        extracted_files: list[tuple[str, str, int]] = []
        base_dir_abs = os.path.abspath(str(extract_dir))

        with tarfile.open(file_path, "r:*") as tf:
            count = 0
            for member in tf:
                if count >= limits["max_files"]:
                    break
                if not member.isreg():
                    continue

                target_path = os.path.join(base_dir_abs, member.name)
                if not os.path.abspath(target_path).startswith(base_dir_abs):
                    continue

                res = self._check_size_limits(member.size, 0, limits, member.name)
                if res:
                    return res

                tf.extract(member, path=base_dir_abs)
                extracted_files.append((target_path, member.name, member.size))
                count += 1

        return {"files": extracted_files}

    def _extract_single_compressed(
        self, file_path: Path, extract_dir: Path, **limits: Any
    ) -> dict[str, Any]:
        archive_type = limits.get("archive_type", "gzip")
        base_dir_abs = os.path.abspath(str(extract_dir))
        stem = file_path.stem or "decompressed"
        output_path = os.path.join(base_dir_abs, stem)

        opener = gzip.open if archive_type == "gzip" else bz2.open
        total_size = 0
        with opener(file_path, "rb") as fin, open(output_path, "wb") as fout:
            while True:
                chunk = fin.read(65536)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > limits["max_single_size"]:
                    os.remove(output_path)
                    return {"malicious": True, "reason": "Decompressed size limit exceeded"}
                fout.write(chunk)

        return {"files": [(output_path, stem, total_size)]}

    def _check_size_limits(
        self, size: int, total_so_far: int, limits: dict, filename: str
    ) -> dict | None:
        if size > limits["max_single_size"]:
            return {"malicious": True, "reason": f"File {filename} too large"}
        if total_so_far + size > limits["max_total_size"]:
            return {"malicious": True, "reason": "Total extracted size too large"}
        return None

    def _build_result(self, started_at: datetime, status: str, findings: dict) -> StageResult:
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
