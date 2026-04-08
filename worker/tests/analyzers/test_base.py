"""Tests for FormatAnalyzer ABC and AnalyzerResult dataclass."""

from pathlib import Path

import pytest
from malscan_worker.analyzers.base import AnalyzerResult, FormatAnalyzer
from malscan_worker.stages.base import StageContext


class TestAnalyzerResult:
    def test_default_fields(self) -> None:
        result = AnalyzerResult(
            analyzer_name="test",
            format_type="TEST/FILE",
        )

        assert result.analyzer_name == "test"
        assert result.format_type == "TEST/FILE"
        assert result.indicators == []
        assert result.features == {}
        assert result.extracted_strings == []
        assert result.risk_score == 0
        assert result.risk_factors == []
        assert result.errors == []
        assert result.extracted_artifacts == []

    def test_custom_fields(self) -> None:
        result = AnalyzerResult(
            analyzer_name="pe",
            format_type="PE/EXE",
            indicators=[{"type": "packer_detected", "severity": "medium", "detail": "UPX"}],
            features={"is_dll": False},
            extracted_strings=["CreateRemoteThread"],
            risk_score=45,
            risk_factors=["Packer detected"],
            errors=[],
            extracted_artifacts=[
                {
                    "filename": "payload.bin",
                    "sha256": "abc",
                    "size": 100,
                    "path": "/tmp/x",
                    "source": "overlay",
                }
            ],
        )

        assert result.risk_score == 45
        assert len(result.indicators) == 1
        assert result.indicators[0]["severity"] == "medium"
        assert result.extracted_artifacts[0]["filename"] == "payload.bin"


class TestFormatAnalyzerABC:
    def test_cannot_instantiate_abc(self) -> None:
        """FormatAnalyzer is abstract, so instantiation should fail."""
        with pytest.raises(TypeError):
            FormatAnalyzer()  # type: ignore[abstract]

    def test_concrete_subclass(self, tmp_path: Path) -> None:
        """A concrete subclass with all methods implemented works."""

        class DummyAnalyzer(FormatAnalyzer):
            @property
            def name(self) -> str:
                return "dummy"

            def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
                return mime == "application/x-dummy"

            async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
                return AnalyzerResult(analyzer_name="dummy", format_type="DUMMY")

        analyzer = DummyAnalyzer()
        assert analyzer.name == "dummy"
        assert analyzer.can_handle(tmp_path / "f", "application/x-dummy", b"") is True
        assert analyzer.can_handle(tmp_path / "f", "text/plain", b"") is False
