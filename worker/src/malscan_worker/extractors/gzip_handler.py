# worker/src/malscan_worker/extractors/gzip_handler.py
"""Gzip single-file handler."""

import gzip
import os
from pathlib import Path

import structlog

from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)

logger = structlog.get_logger(__name__)

GZIP_MAGIC = b"\x1f\x8b"


class GzipHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "gzip"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:2] == GZIP_MAGIC:
            return True
        if mime in ("application/gzip", "application/x-gzip"):
            return True
        if file_path.suffix.lower() == ".gz":
            return True
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        warnings: list[str] = []
        archive_size = os.path.getsize(file_path)

        # Derive output filename by stripping .gz
        stem = (
            file_path.stem
            if file_path.suffix.lower() == ".gz"
            else f"{file_path.name}.decompressed"
        )
        out_path = extract_dir / stem

        try:
            with gzip.open(str(file_path), "rb") as src, open(out_path, "wb") as dst:
                written = 0
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > limits.max_single_file_bytes:
                        os.remove(out_path)
                        warnings.append(
                            "Decompressed file exceeds limit "
                            f"({limits.max_single_file_bytes} bytes)"
                        )
                        return ExtractionResult(files=[], warnings=warnings, archive_type="gzip")
                    if archive_size > 0 and written / archive_size > limits.max_expansion_ratio:
                        os.remove(out_path)
                        return ExtractionResult(
                            files=[],
                            malicious=True,
                            reason="Zip bomb: gzip expansion ratio exceeded",
                            archive_type="gzip",
                        )
                    dst.write(chunk)

            return ExtractionResult(
                files=[
                    ExtractedFile(
                        path=str(out_path),
                        original_name=stem,
                        size=written,
                        origin_path=stem,
                    )
                ],
                warnings=warnings,
                archive_type="gzip",
            )

        except Exception as e:
            logger.error("gzip_extraction_error", error=str(e))
            warnings.append(f"Gzip error: {e}")
            return ExtractionResult(files=[], warnings=warnings, archive_type="gzip")
