"""Tests for PDFAnalyzer behavior."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from malscan_worker.analyzers.pdf_analyzer import PDFAnalyzer
from malscan_worker.stages.base import StageContext


def _ctx(file_path: Path) -> StageContext:
    return StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="key",
        sha256="0" * 64,
        original_filename=file_path.name,
        file_path=file_path,
    )


def test_can_handle_pdf_by_magic_mime_and_bom_prefix(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.pdf"
    file_path.write_bytes(b"irrelevant")

    analyzer = PDFAnalyzer()

    assert analyzer.can_handle(file_path, "application/pdf", b"not-pdf") is True
    assert (
        analyzer.can_handle(
            file_path,
            "application/octet-stream",
            b"\xef\xbb\xbf \t\r\n%PDF-1.7",
        )
        is True
    )


def test_can_handle_rejects_non_pdf(tmp_path: Path) -> None:
    file_path = tmp_path / "plain.bin"
    file_path.write_bytes(b"hello")

    analyzer = PDFAnalyzer()

    assert analyzer.can_handle(file_path, "text/plain", b"hello") is False


@pytest.mark.asyncio
async def test_analyze_minimal_structured_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "minimal.pdf"
    file_path.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n"
        b"xref\n0 3\n0000000000 65535 f\n"
        b"0000000010 00000 n\n0000000050 00000 n\n"
        b"trailer\n<< /Root 1 0 R /Size 3 >>\nstartxref\n90\n%%EOF\n"
    )

    class _FakeReader:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.pdf_header = "%PDF-1.4"
            self.pages: list[dict[str, Any]] = []
            self.is_encrypted = False
            self.trailer: dict[str, Any] = {"/Root": {}}

        def get_fields(self) -> dict[str, Any]:
            return {}

    monkeypatch.setattr("malscan_worker.analyzers.pdf_analyzer.PdfReader", _FakeReader)

    analyzer = PDFAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    assert result.analyzer_name == "pdf"
    assert result.format_type == "PDF"
    required = {
        "version",
        "page_count",
        "encrypted",
        "object_count",
        "js_code",
        "launch_actions",
        "open_actions",
        "uri_actions",
        "embedded_files",
        "annotations",
        "form_fields",
        "stream_info",
        "suspicious_names",
    }
    assert required.issubset(set(result.features.keys()))
    assert result.errors == []


@pytest.mark.asyncio
async def test_corrupt_pdf_uses_regex_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "corrupt.pdf"
    file_path.write_bytes(
        b"%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (evil) >> >>\n"
        b"/Jav#61Script /ObjStm\nstream\nabc\nendstream\nendobj\n%%EOF\n"
    )

    class _BoomReader:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise ValueError("broken xref")

    monkeypatch.setattr("malscan_worker.analyzers.pdf_analyzer.PdfReader", _BoomReader)

    analyzer = PDFAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    indicator_types = {str(ind["type"]) for ind in result.indicators}
    assert result.errors
    assert "broken xref" in result.errors[0].lower()
    assert result.features["object_count"] == 1
    assert "embedded_javascript" in indicator_types
    assert "name_obfuscation" in indicator_types


@pytest.mark.asyncio
async def test_javascript_open_action_indicator_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "open-js.pdf"
    file_path.write_bytes(b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n")

    class _ReaderWithOpenJavaScript:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.pdf_header = "%PDF-1.7"
            self.pages: list[dict[str, Any]] = []
            self.is_encrypted = False
            self.trailer = {
                "/Root": {
                    "/OpenAction": {"/S": "/JavaScript", "/JS": "app.alert('x')"},
                }
            }

        def get_fields(self) -> dict[str, Any]:
            return {}

    monkeypatch.setattr(
        "malscan_worker.analyzers.pdf_analyzer.PdfReader",
        _ReaderWithOpenJavaScript,
    )

    analyzer = PDFAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    indicator_types = {str(ind["type"]) for ind in result.indicators}
    assert "embedded_javascript" in indicator_types
    assert "auto_open_action" in indicator_types


@pytest.mark.asyncio
async def test_launch_action_indicator_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "launch.pdf"
    file_path.write_bytes(b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n")

    class _ReaderWithLaunchAction:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.pdf_header = "%PDF-1.7"
            self.pages: list[dict[str, Any]] = []
            self.is_encrypted = False
            self.trailer = {
                "/Root": {
                    "/OpenAction": {"/S": "/Launch", "/F": "cmd.exe"},
                }
            }

        def get_fields(self) -> dict[str, Any]:
            return {}

    monkeypatch.setattr(
        "malscan_worker.analyzers.pdf_analyzer.PdfReader",
        _ReaderWithLaunchAction,
    )

    analyzer = PDFAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    indicators = {str(ind["type"]): ind for ind in result.indicators}
    assert "launch_action" in indicators
    assert str(indicators["launch_action"]["severity"]) == "critical"
