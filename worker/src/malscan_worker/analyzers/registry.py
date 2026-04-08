"""Analyzer registry and format dispatch."""

import logging
from importlib import import_module
from pathlib import Path

from malscan_worker.analyzers.base import FormatAnalyzer

logger = logging.getLogger(__name__)


class AnalyzerRegistry:
    """Stores analyzers and selects the first matching analyzer."""

    def __init__(self) -> None:
        self._analyzers: list[FormatAnalyzer] = []

    def register(self, analyzer: FormatAnalyzer) -> None:
        """Register an analyzer in matching order."""
        self._analyzers.append(analyzer)

    def detect(self, file_path: Path, mime: str) -> FormatAnalyzer | None:
        """Return the first analyzer that can handle this file."""
        magic = self._read_magic(file_path)
        for analyzer in self._analyzers:
            if analyzer.can_handle(file_path, mime, magic):
                return analyzer
        return None

    @staticmethod
    def _read_magic(file_path: Path) -> bytes:
        """Read up to the first 32 bytes for lightweight format checks."""
        try:
            with file_path.open("rb") as handle:
                return handle.read(32)
        except OSError as exc:
            logger.debug("failed to read magic bytes from %s: %s", file_path, exc)
            return b""


def get_default_analyzer_registry() -> AnalyzerRegistry:
    """Create registry with default analyzer precedence."""
    registry = AnalyzerRegistry()

    analyzer_specs = [
        ("malscan_worker.analyzers.pe_analyzer", "PEAnalyzer"),
        ("malscan_worker.analyzers.office_adapter", "OfficeAnalyzerAdapter"),
        ("malscan_worker.analyzers.pdf_analyzer", "PDFAnalyzer"),
        ("malscan_worker.analyzers.lnk_analyzer", "LNKAnalyzer"),
        ("malscan_worker.analyzers.script_analyzer", "ScriptAnalyzer"),
    ]

    for module_name, class_name in analyzer_specs:
        try:
            module = import_module(module_name)
            analyzer_class = getattr(module, class_name)
            registry.register(analyzer_class())
        except (ImportError, AttributeError) as exc:
            logger.warning(
                "skipping analyzer %s.%s: %s",
                module_name,
                class_name,
                exc,
            )

    return registry
