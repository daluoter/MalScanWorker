"""Tests for PDF heuristic synthesis."""

from __future__ import annotations

from malscan_worker.heuristics.pdf import build_pdf_heuristics


def test_build_pdf_heuristics_emits_launch_and_embedded_executable_hits() -> None:
    features = {
        "launch_actions": ["cmd.exe"],
        "open_actions": ["/Launch"],
        "js_code": [],
        "embedded_files": [
            {"name": "payload.exe", "executable": True},
            {"name": "readme.txt", "executable": False},
        ],
        "suspicious_names": [],
        "stream_info": {
            "stream_count": 1,
            "filter_count": 1,
            "filters": ["/FlateDecode"],
            "has_object_stream": False,
        },
    }

    heuristics = build_pdf_heuristics(features)

    assert [heuristic.key for heuristic in heuristics] == [
        "pdf.launch_action_executable",
        "resource.embedded_executable",
    ]
    assert heuristics[0].scope == "pdf"
    assert heuristics[0].evidence["targets"] == ("cmd.exe",)
    assert heuristics[1].evidence["files"] == ({"name": "payload.exe", "executable": True},)


def test_build_pdf_heuristics_ignores_placeholder_and_benign_launch_targets() -> None:
    features = {
        "launch_actions": ["/Launch", "launch", "document.txt", "https://example.com"],
        "open_actions": ["/Launch"],
        "js_code": [],
        "embedded_files": [],
        "suspicious_names": [],
        "stream_info": {
            "stream_count": 0,
            "filter_count": 0,
            "filters": [],
            "has_object_stream": False,
        },
    }

    heuristics = build_pdf_heuristics(features)

    assert [heuristic.key for heuristic in heuristics] == []


def test_build_pdf_heuristics_ignores_non_string_launch_targets() -> None:
    features = {
        "launch_actions": [None, 123, {"target": "cmd.exe"}, ["calc.exe"]],
        "open_actions": ["/Launch"],
        "js_code": [],
        "embedded_files": [],
        "suspicious_names": [],
        "stream_info": {
            "stream_count": 0,
            "filter_count": 0,
            "filters": [],
            "has_object_stream": False,
        },
    }

    heuristics = build_pdf_heuristics(features)

    assert [heuristic.key for heuristic in heuristics] == []


def test_build_pdf_heuristics_accepts_executable_command_lines_and_jar_targets() -> None:
    features = {
        "launch_actions": [
            "cmd.exe /c calc.exe",
            r"C:\Windows\System32\wscript.exe foo.js",
            "payload.jar",
        ],
        "open_actions": ["/Launch"],
        "js_code": [],
        "embedded_files": [],
        "suspicious_names": [],
        "stream_info": {
            "stream_count": 0,
            "filter_count": 0,
            "filters": [],
            "has_object_stream": False,
        },
    }

    heuristics = build_pdf_heuristics(features)

    assert [heuristic.key for heuristic in heuristics] == ["pdf.launch_action_executable"]
    assert heuristics[0].evidence["targets"] == (
        r"C:\Windows\System32\wscript.exe foo.js",
        "cmd.exe /c calc.exe",
        "payload.jar",
    )
