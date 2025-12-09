"""Base classes for pipeline stages."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class StageContext:
    """Context passed to each stage."""

    job_id: str
    file_id: str
    storage_key: str
    sha256: str
    original_filename: str
    file_path: Path | None
    previous_results: list["StageResult"] = field(default_factory=list)


@dataclass
class StageResult:
    """Result from a stage execution."""

    stage_name: str
    status: str  # "ok", "failed", "skipped"
    started_at: datetime
    ended_at: datetime
    duration_ms: int
    findings: dict[str, Any]
    artifacts: list[str]
    error: str | None = None


class Stage(ABC):
    """Abstract base class for analysis stages."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stage name identifier."""
        pass

    @abstractmethod
    async def execute(self, ctx: StageContext) -> StageResult:
        """
        Execute the stage.

        Args:
            ctx: Stage context with job info and file path.

        Returns:
            StageResult with findings and status.
        """
        pass
