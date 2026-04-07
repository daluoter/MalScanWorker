# worker/src/malscan_worker/extractors/rar_handler.py
"""RAR format handler."""

import os
import subprocess
from pathlib import Path

import structlog

from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)
from malscan_worker.extractors.safety import remove_symlinks, safe_extract_path

logger = structlog.get_logger(__name__)

RAR_MAGIC = b"Rar!\x1a\x07"


class RarHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "rar"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:7] == RAR_MAGIC:
            return True
        if mime in ("application/x-rar-compressed", "application/vnd.rar"):
            return True
        if file_path.suffix.lower() == ".rar":
            return True
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        files: list[ExtractedFile] = []
        warnings: list[str] = []

        cmd = ["unrar", "x", "-y", "-o+"]
        if password:
            cmd.append(f"-p{password}")
        else:
            cmd.append("-p-")  # no password, skip prompt
        cmd.extend([str(file_path), str(extract_dir) + "/"])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=limits.timeout_seconds,
            )

            if proc.returncode != 0:
                stderr = proc.stderr.lower() + proc.stdout.lower()
                if "password" in stderr or "encrypted" in stderr:
                    if password:
                        raise ArchiveWrongPasswordError("rar")
                    raise ArchivePasswordRequiredError("rar")
                warnings.append(f"unrar exit code {proc.returncode}: {proc.stderr[:200]}")

        except subprocess.TimeoutExpired:
            warnings.append(f"unrar extraction timed out after {limits.timeout_seconds}s")
            return ExtractionResult(files=files, warnings=warnings, archive_type="rar")

        remove_symlinks(str(extract_dir))

        total_bytes = 0
        for root, _dirs, filenames in os.walk(extract_dir):
            for fname in filenames:
                if len(files) >= limits.max_files:
                    warnings.append(f"Max files limit ({limits.max_files}) reached")
                    return ExtractionResult(files=files, warnings=warnings, archive_type="rar")

                full = os.path.join(root, fname)
                rel = os.path.relpath(full, extract_dir)

                if safe_extract_path(str(extract_dir), rel) is None:
                    warnings.append(f"Path traversal skipped: {rel}")
                    continue

                fsize = os.path.getsize(full)
                if fsize > limits.max_single_file_bytes:
                    warnings.append(f"File too large, skipped: {rel} ({fsize} bytes)")
                    continue

                total_bytes += fsize
                if total_bytes > limits.max_extracted_bytes:
                    warnings.append("Max total extracted bytes reached")
                    return ExtractionResult(files=files, warnings=warnings, archive_type="rar")

                files.append(
                    ExtractedFile(path=full, original_name=fname, size=fsize, origin_path=rel)
                )

        return ExtractionResult(files=files, warnings=warnings, archive_type="rar")
