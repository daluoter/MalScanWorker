# worker/src/malscan_worker/extractors/iso_handler.py
"""ISO format handler — stub for future implementation."""

from pathlib import Path

from malscan_worker.extractors.base import (
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)


class IsoHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "iso"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if mime in ("application/x-iso9660-image",):
            return True
        if file_path.suffix.lower() == ".iso":
            return True
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        raise NotImplementedError("ISO support planned")
