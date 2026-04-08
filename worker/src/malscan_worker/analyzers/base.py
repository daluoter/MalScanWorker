"""Base classes for format-specific analyzers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from malscan_worker.stages.base import StageContext


@dataclass
class AnalyzerResult:
    """Standardized result from a format-specific analyzer."""

    analyzer_name: str
    format_type: str
    indicators: list[dict[str, Any]] = field(default_factory=list)
    features: dict[str, Any] = field(default_factory=dict)
    extracted_strings: list[str] = field(default_factory=list)
    risk_score: int = 0
    risk_factors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    extracted_artifacts: list[dict[str, Any]] = field(default_factory=list)


class FormatAnalyzer(ABC):
    """Base class for format-specific analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this analyzer."""
        ...

    @abstractmethod
    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        """Return True if this analyzer should process the file."""
        ...

    @abstractmethod
    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        """Run format-specific analysis and return standardized findings."""
        ...
