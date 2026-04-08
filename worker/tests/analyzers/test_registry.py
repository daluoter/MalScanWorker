"""Tests for analyzer registry dispatch behavior."""

import sys
from pathlib import Path
from types import ModuleType

import pytest
from malscan_worker.analyzers.base import AnalyzerResult, FormatAnalyzer
from malscan_worker.analyzers.registry import AnalyzerRegistry, get_default_analyzer_registry


class SpyAnalyzer(FormatAnalyzer):
    def __init__(self, name: str, should_handle: bool) -> None:
        self._name = name
        self._should_handle = should_handle
        self.calls: list[tuple[Path, str, bytes]] = []

    @property
    def name(self) -> str:
        return self._name

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        self.calls.append((file_path, mime, magic))
        return self._should_handle

    async def analyze(self, file_path: Path, ctx: object) -> AnalyzerResult:
        raise NotImplementedError


def test_empty_registry_returns_none(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"MZ")

    registry = AnalyzerRegistry()

    assert registry.detect(file_path, "application/octet-stream") is None


def test_first_match_by_mime(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"not-a-real-header")

    first = SpyAnalyzer("first", should_handle=True)
    second = SpyAnalyzer("second", should_handle=False)
    registry = AnalyzerRegistry()
    registry.register(first)
    registry.register(second)

    found = registry.detect(file_path, "application/pdf")

    assert found is first
    assert len(first.calls) == 1
    assert second.calls == []


def test_first_match_by_magic(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"%PDF-1.7")

    first = SpyAnalyzer("first", should_handle=False)
    second = SpyAnalyzer("second", should_handle=True)
    registry = AnalyzerRegistry()
    registry.register(first)
    registry.register(second)

    found = registry.detect(file_path, "application/octet-stream")

    assert found is second
    assert len(first.calls) == 1
    assert len(second.calls) == 1


def test_first_match_wins(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"MZ")

    first = SpyAnalyzer("first", should_handle=True)
    second = SpyAnalyzer("second", should_handle=True)
    registry = AnalyzerRegistry()
    registry.register(first)
    registry.register(second)

    found = registry.detect(file_path, "application/x-msdownload")

    assert found is first
    assert len(first.calls) == 1
    assert second.calls == []


def test_missing_file_uses_empty_magic(tmp_path: Path) -> None:
    missing_file = tmp_path / "does-not-exist.bin"

    analyzer = SpyAnalyzer("first", should_handle=False)
    registry = AnalyzerRegistry()
    registry.register(analyzer)

    found = registry.detect(missing_file, "application/octet-stream")

    assert found is None
    assert len(analyzer.calls) == 1
    assert analyzer.calls[0][2] == b""


def test_no_match_returns_none(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"#!/usr/bin/env python3")

    first = SpyAnalyzer("first", should_handle=False)
    second = SpyAnalyzer("second", should_handle=False)
    registry = AnalyzerRegistry()
    registry.register(first)
    registry.register(second)

    assert registry.detect(file_path, "text/x-python") is None


def test_detect_reads_first_32_bytes(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.bin"
    payload = b"A" * 32 + b"B" * 64
    file_path.write_bytes(payload)

    analyzer = SpyAnalyzer("spy", should_handle=False)
    registry = AnalyzerRegistry()
    registry.register(analyzer)

    registry.detect(file_path, "application/octet-stream")

    assert len(analyzer.calls) == 1
    assert analyzer.calls[0][2] == payload[:32]


def test_default_registry_registers_expected_order(monkeypatch: pytest.MonkeyPatch) -> None:
    class PEAnalyzer(SpyAnalyzer):
        def __init__(self) -> None:
            super().__init__("pe", should_handle=False)

    class OfficeAnalyzerAdapter(SpyAnalyzer):
        def __init__(self) -> None:
            super().__init__("office", should_handle=False)

    class PDFAnalyzer(SpyAnalyzer):
        def __init__(self) -> None:
            super().__init__("pdf", should_handle=False)

    class LNKAnalyzer(SpyAnalyzer):
        def __init__(self) -> None:
            super().__init__("lnk", should_handle=False)

    class ScriptAnalyzer(SpyAnalyzer):
        def __init__(self) -> None:
            super().__init__("script", should_handle=False)

    modules = {
        "malscan_worker.analyzers.pe_analyzer": ("PEAnalyzer", PEAnalyzer),
        "malscan_worker.analyzers.office_adapter": (
            "OfficeAnalyzerAdapter",
            OfficeAnalyzerAdapter,
        ),
        "malscan_worker.analyzers.pdf_analyzer": ("PDFAnalyzer", PDFAnalyzer),
        "malscan_worker.analyzers.lnk_analyzer": ("LNKAnalyzer", LNKAnalyzer),
        "malscan_worker.analyzers.script_analyzer": ("ScriptAnalyzer", ScriptAnalyzer),
    }

    for module_name, (class_name, klass) in modules.items():
        module = ModuleType(module_name)
        setattr(module, class_name, klass)
        monkeypatch.setitem(sys.modules, module_name, module)

    registry = get_default_analyzer_registry()

    names = [analyzer.name for analyzer in registry._analyzers]
    assert names == ["pe", "office", "pdf", "lnk", "script"]


def test_default_registry_missing_modules_does_not_raise() -> None:
    registry = get_default_analyzer_registry()

    assert isinstance(registry, AnalyzerRegistry)
