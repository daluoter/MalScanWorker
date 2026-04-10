"""7z format handler."""

from __future__ import annotations

import os
from pathlib import Path

import structlog

try:
    import py7zr  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - optional dependency fallback
    py7zr = None

from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)
from malscan_worker.extractors.safety import check_expansion_ratio, safe_extract_path

logger = structlog.get_logger(__name__)

SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"


class SevenZipHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "7z"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:6] == SEVENZ_MAGIC:
            return True
        if mime in ("application/x-7z-compressed",):
            return True
        if file_path.suffix.lower() == ".7z":
            return True
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        if py7zr is None:
            raise RuntimeError("py7zr not available")

        files: list[ExtractedFile] = []
        warnings: list[str] = []
        with py7zr.SevenZipFile(file_path, mode="r", password=password) as archive:
            members = [item for item in archive.list() if getattr(item, "filename", None)]
            password_protected = bool(archive.needs_password())

            reason = _preflight_reason(
                archive_size=file_path.stat().st_size,
                member_count=len(members),
                member_sizes=[int(getattr(item, "uncompressed", 0) or 0) for item in members],
                limits=limits,
            )
            if reason is not None:
                return ExtractionResult(
                    files=[],
                    malicious=True,
                    reason=reason,
                    archive_type="7z",
                    password_protected=password_protected,
                )

            total_extracted_bytes = 0
            for member in members:
                member_name = str(member.filename)

                if len(files) >= limits.max_files:
                    warnings.append(f"Max files limit ({limits.max_files}) reached")
                    break

                target = safe_extract_path(str(extract_dir), member_name)
                if target is None:
                    warnings.append(f"Path traversal skipped: {member_name}")
                    continue

                member_size = int(getattr(member, "uncompressed", 0) or 0)
                if member_size > limits.max_single_file_bytes:
                    warnings.append(f"File too large, skipped: {member_name} ({member_size} bytes)")
                    continue

                if total_extracted_bytes + member_size > limits.max_extracted_bytes:
                    warnings.append("Max total extracted bytes reached")
                    break

                os.makedirs(os.path.dirname(target), exist_ok=True)
                try:
                    archive.extract(path=extract_dir, targets=[member_name])
                except Exception as exc:
                    if _is_password_required_error(exc):
                        raise ArchivePasswordRequiredError("7z") from exc
                    if _is_wrong_password_error(exc, password_protected, password):
                        raise ArchiveWrongPasswordError("7z") from exc
                    raise

                written = os.path.getsize(target)

                reason = _stream_limit_reason(
                    archive_size=file_path.stat().st_size,
                    current_total_extracted_bytes=total_extracted_bytes,
                    current_file_written=written,
                    limits=limits,
                )
                if reason is not None:
                    if os.path.exists(target):
                        os.remove(target)
                    archive.reset()
                    return ExtractionResult(
                        files=files,
                        malicious=True,
                        reason=reason,
                        archive_type="7z",
                        password_protected=password_protected,
                    )

                archive.reset()
                total_extracted_bytes += written
                files.append(
                    ExtractedFile(
                        path=target,
                        original_name=os.path.basename(member_name),
                        size=written,
                        origin_path=member_name,
                    )
                )

        return ExtractionResult(
            files=files,
            warnings=warnings,
            archive_type="7z",
            password_protected=password_protected,
        )


def _preflight_reason(
    *,
    archive_size: int,
    member_count: int,
    member_sizes: list[int],
    limits: ExtractionLimits,
) -> str | None:
    if member_count > limits.max_files:
        return "Max files limit exceeded before extraction"

    if any(size > limits.max_single_file_bytes for size in member_sizes):
        return "Single file size limit exceeded before extraction"

    total_uncompressed = sum(member_sizes)
    if total_uncompressed > limits.max_extracted_bytes:
        return "Max total extracted bytes exceeded before extraction"

    if check_expansion_ratio(archive_size, total_uncompressed, limits) is not None:
        return "Expansion ratio exceeded before extraction"

    return None


def _is_password_required_error(exc: Exception) -> bool:
    if py7zr is not None and isinstance(exc, getattr(py7zr, "PasswordRequired", ())):
        return True
    return "password required" in str(exc).lower()


def _is_wrong_password_error(
    exc: Exception, password_protected: bool, password: str | None
) -> bool:
    if not password_protected or not password:
        return False
    message = str(exc).lower()
    return "wrong password" in message or "corrupt input data" in message


def _stream_limit_reason(
    *,
    archive_size: int,
    current_total_extracted_bytes: int,
    current_file_written: int,
    limits: ExtractionLimits,
) -> str | None:
    if current_file_written > limits.max_single_file_bytes:
        return "Zip bomb: single file bytes exceeded during extraction"

    cumulative_written = current_total_extracted_bytes + current_file_written
    if cumulative_written > limits.max_extracted_bytes:
        return "Zip bomb: total extracted bytes exceeded during extraction"

    if archive_size > 0 and cumulative_written / archive_size > limits.max_expansion_ratio:
        return "Zip bomb: expansion ratio exceeded during extraction"

    return None
