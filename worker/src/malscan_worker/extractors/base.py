# worker/src/malscan_worker/extractors/base.py
"""Base types for pluggable format handlers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExtractedFile:
    """A single file extracted from an archive."""

    path: str  # absolute path on disk
    original_name: str  # filename within archive
    size: int  # bytes
    origin_path: str  # full path within archive hierarchy


@dataclass
class ExtractionLimits:
    """Configurable safety limits for extraction."""

    max_files: int = 100
    max_extracted_bytes: int = 500_000_000  # 500MB
    max_single_file_bytes: int = 100_000_000  # 100MB
    max_expansion_ratio: float = 100.0
    timeout_seconds: int = 120


@dataclass
class ExtractionResult:
    """Result of an extraction attempt."""

    files: list[ExtractedFile]
    malicious: bool = False
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    archive_type: str | None = None


class FormatHandler(ABC):
    """Abstract base class for archive format handlers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this format (e.g. 'zip', '7z')."""
        ...

    @abstractmethod
    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        """Return True if this handler can extract the given file."""
        ...

    @abstractmethod
    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        """Extract files from the archive into extract_dir."""
        ...
