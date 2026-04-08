"""Tests for PE format analyzer behavior."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pefile
import pytest
from malscan_worker.analyzers.pe_analyzer import PEAnalyzer
from malscan_worker.stages.base import StageContext


def _build_magic_pe(path: Path, *, valid_pe: bool) -> bytes:
    data = bytearray(512)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    if valid_pe:
        data[0x80:0x84] = b"PE\x00\x00"
    path.write_bytes(bytes(data))
    return bytes(data)


def _ctx(file_path: Path) -> StageContext:
    return StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="key",
        sha256="0" * 64,
        original_filename=file_path.name,
        file_path=file_path,
    )


class _FakeImportSymbol:
    def __init__(self, name: bytes | None) -> None:
        self.name = name


class _FakeImportEntry:
    def __init__(self, dll: bytes, names: list[bytes]) -> None:
        self.dll = dll
        self.imports = [_FakeImportSymbol(name) for name in names]


class _FakeExportSymbol:
    def __init__(self, name: bytes | None) -> None:
        self.name = name


class _FakeSection:
    def __init__(self, name: str, entropy: float, data: bytes) -> None:
        self.Name = name.encode("ascii") + b"\x00"
        self.Misc_VirtualSize = len(data)
        self.SizeOfRawData = len(data)
        self.PointerToRawData = 0
        self._entropy = entropy
        self._data = data

    def get_entropy(self) -> float:
        return self._entropy

    def get_data(self) -> bytes:
        return self._data


class _FakePE:
    def __init__(
        self,
        sections: list[_FakeSection],
        imports: list[_FakeImportEntry],
        *,
        timestamp: int = 1_700_000_000,
    ) -> None:
        self.FILE_HEADER = SimpleNamespace(
            Machine=0x8664,
            TimeDateStamp=timestamp,
            Characteristics=0x0002,
        )
        self.OPTIONAL_HEADER = SimpleNamespace(Magic=0x20B, Subsystem=2)
        self.sections = sections
        self.DIRECTORY_ENTRY_IMPORT = imports
        self.DIRECTORY_ENTRY_EXPORT = SimpleNamespace(symbols=[])
        self.DIRECTORY_ENTRY_RESOURCE = None
        self.DIRECTORY_ENTRY_DEBUG: list[Any] = []
        self.DIRECTORY_ENTRY_TLS = None

    def is_dll(self) -> bool:
        return False

    def get_overlay_data_start_offset(self) -> int | None:
        return None

    def get_overlay(self) -> bytes:
        return b""

    def close(self) -> None:
        return None


def test_can_handle_by_magic(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.exe"
    magic = _build_magic_pe(file_path, valid_pe=True)

    analyzer = PEAnalyzer()

    assert analyzer.can_handle(file_path, "application/octet-stream", magic) is True


@pytest.mark.parametrize(
    "mime",
    [
        "application/x-dosexec",
        "application/x-msdownload",
        "application/vnd.microsoft.portable-executable",
    ],
)
def test_can_handle_by_mime(tmp_path: Path, mime: str) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"not-a-pe")

    analyzer = PEAnalyzer()

    assert analyzer.can_handle(file_path, mime, b"not-a-pe") is True


def test_reject_non_pe_and_invalid_mz_without_pe(tmp_path: Path) -> None:
    analyzer = PEAnalyzer()

    text_file = tmp_path / "plain.txt"
    text_file.write_text("hello")
    assert analyzer.can_handle(text_file, "text/plain", b"hello") is False

    mz_file = tmp_path / "broken.exe"
    magic = _build_magic_pe(mz_file, valid_pe=False)
    assert analyzer.can_handle(mz_file, "application/octet-stream", magic) is False


@pytest.mark.asyncio
async def test_analyze_minimal_valid_pe_returns_structured_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "sample.exe"
    _build_magic_pe(file_path, valid_pe=True)

    fake_pe = _FakePE(
        sections=[_FakeSection(".text", 5.2, b"\x90" * 128)],
        imports=[_FakeImportEntry(b"KERNEL32.dll", [b"Sleep"])],
    )

    monkeypatch.setattr(
        "malscan_worker.analyzers.pe_analyzer.pefile.PE",
        lambda *args, **kwargs: fake_pe,
    )

    analyzer = PEAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    assert result.analyzer_name == "pe"
    assert result.format_type == "PE"
    required = {
        "imports",
        "exports",
        "sections",
        "headers",
        "resources",
        "packer_clues",
        "tls_callbacks",
        "debug_info",
        "overlay",
        "is_dll",
        "is_64bit",
    }
    assert required.issubset(set(result.features.keys()))
    assert result.errors == []


@pytest.mark.asyncio
async def test_corrupt_pe_is_handled_gracefully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "corrupt.exe"
    _build_magic_pe(file_path, valid_pe=True)

    def _raise_pe_error(*args: object, **kwargs: object) -> object:
        raise pefile.PEFormatError("invalid pe")

    monkeypatch.setattr("malscan_worker.analyzers.pe_analyzer.pefile.PE", _raise_pe_error)

    analyzer = PEAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    assert result.errors
    assert "invalid pe" in result.errors[0].lower()
    assert result.risk_score == 0


@pytest.mark.asyncio
async def test_oversized_file_is_skipped(tmp_path: Path) -> None:
    file_path = tmp_path / "too-big.exe"
    with file_path.open("wb") as handle:
        handle.seek((101 * 1024 * 1024) - 1)
        handle.write(b"\x00")

    analyzer = PEAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    assert result.errors
    assert "100mb" in result.errors[0].lower()


@pytest.mark.asyncio
async def test_timestamp_anomaly_indicator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "old.exe"
    _build_magic_pe(file_path, valid_pe=True)

    fake_pe = _FakePE(
        sections=[_FakeSection(".text", 4.0, b"\x00" * 64)],
        imports=[_FakeImportEntry(b"KERNEL32.dll", [b"Sleep"])],
        timestamp=1,
    )

    monkeypatch.setattr(
        "malscan_worker.analyzers.pe_analyzer.pefile.PE",
        lambda *args, **kwargs: fake_pe,
    )

    analyzer = PEAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    indicator_types = {indicator["type"] for indicator in result.indicators}
    assert "timestamp_anomaly" in indicator_types


@pytest.mark.asyncio
async def test_high_entropy_indicator_behavior(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "entropy.exe"
    _build_magic_pe(file_path, valid_pe=True)

    high_entropy_data = bytes(range(256)) * 2
    fake_pe = _FakePE(
        sections=[_FakeSection(".text", 7.95, high_entropy_data)],
        imports=[
            _FakeImportEntry(b"KERNEL32.dll", [b"Sleep"]),
            _FakeImportEntry(b"USER32.dll", [b"MessageBoxA"]),
        ],
    )

    monkeypatch.setattr(
        "malscan_worker.analyzers.pe_analyzer.pefile.PE",
        lambda *args, **kwargs: fake_pe,
    )

    analyzer = PEAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    indicators = {indicator["type"]: indicator for indicator in result.indicators}
    assert "high_entropy_section" in indicators
    assert indicators["high_entropy_section"]["severity"] == "medium"
    assert result.risk_score == 8
