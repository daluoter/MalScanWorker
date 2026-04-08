"""Analyzer registry and format dispatch."""

from pathlib import Path

from malscan_worker.analyzers.base import FormatAnalyzer


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
        except OSError:
            return b""


def get_default_analyzer_registry() -> AnalyzerRegistry:
    """Create registry with default analyzer precedence."""
    from malscan_worker.analyzers.lnk import LNKAnalyzer
    from malscan_worker.analyzers.office import OfficeAnalyzer
    from malscan_worker.analyzers.pdf import PDFAnalyzer
    from malscan_worker.analyzers.pe import PEAnalyzer
    from malscan_worker.analyzers.script import ScriptAnalyzer

    registry = AnalyzerRegistry()
    registry.register(PEAnalyzer())
    registry.register(OfficeAnalyzer())
    registry.register(PDFAnalyzer())
    registry.register(LNKAnalyzer())
    registry.register(ScriptAnalyzer())
    return registry
