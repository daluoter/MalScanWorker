"""Tests for PE heuristic synthesis."""

from __future__ import annotations

from malscan_worker.heuristics.pe import build_pe_heuristics


def test_build_pe_heuristics_emits_required_signals() -> None:
    features = {
        "imports": [{"dll": "KERNEL32.dll", "functions": ["Sleep"]}],
        "sections": [
            {"name": "UPX0", "entropy": 7.95},
            {"name": ".text", "entropy": 7.61},
        ],
        "packer_clues": [
            {"type": "section_name", "value": "upx0"},
            {
                "type": "high_entropy_with_sparse_imports",
                "high_entropy_sections": 2,
                "imports": 1,
            },
        ],
        "overlay": {"present": True, "size": 4096, "offset": 1337, "file_size": 8192},
    }

    heuristics = build_pe_heuristics(features)
    heuristic_names = {heuristic.key for heuristic in heuristics}

    assert "entropy.high_region_cluster" in heuristic_names
    assert "packer.known_section_name" in heuristic_names
    assert "packer.sparse_imports_high_entropy" in heuristic_names
    assert "api.process_injection_cluster" not in heuristic_names
    assert "structure.overlay_anomaly" in heuristic_names


def test_build_pe_heuristics_emits_process_injection_cluster() -> None:
    features = {
        "imports": [
            {
                "dll": "KERNEL32.dll",
                "functions": [
                    "CreateRemoteThread",
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                ],
            }
        ],
        "sections": [{"name": ".text", "entropy": 5.1}],
        "packer_clues": [],
        "overlay": {"present": False, "size": 0, "offset": None, "file_size": 1024},
    }

    heuristics = build_pe_heuristics(features)

    assert [heuristic.key for heuristic in heuristics] == ["api.process_injection_cluster"]


def test_build_pe_heuristics_ignores_small_overlay() -> None:
    features = {
        "imports": [],
        "sections": [{"name": ".text", "entropy": 7.9}],
        "packer_clues": [],
        "overlay": {"present": True, "size": 512, "offset": 900, "file_size": 4096},
    }

    heuristics = build_pe_heuristics(features)

    assert all(heuristic.key != "structure.overlay_anomaly" for heuristic in heuristics)


def test_build_pe_heuristics_treats_single_dll_with_few_symbols_as_sparse() -> None:
    features = {
        "imports": [
            {
                "dll": "KERNEL32.dll",
                "functions": [
                    "Sleep",
                    "GetProcAddress",
                    "LoadLibraryA",
                    "VirtualAlloc",
                    "CreateFileW",
                ],
            }
        ],
        "sections": [
            {"name": "UPX0", "entropy": 7.95},
            {"name": ".text", "entropy": 7.61},
        ],
        "packer_clues": [],
        "overlay": {"present": False, "size": 0, "offset": None, "file_size": 8192},
    }

    heuristics = build_pe_heuristics(features)

    assert "packer.sparse_imports_high_entropy" in {heuristic.key for heuristic in heuristics}


def test_build_pe_heuristics_deduplicates_injection_cluster_apis_deterministically() -> None:
    features = {
        "imports": [
            {
                "dll": "KERNEL32.dll",
                "functions": [
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "WriteProcessMemory",
                    "VirtualAllocEx",
                    "CreateRemoteThread",
                ],
            }
        ],
        "sections": [],
        "packer_clues": [],
        "overlay": {"present": False, "size": 0, "offset": None, "file_size": 1024},
    }

    heuristics = build_pe_heuristics(features)
    assert [heuristic.key for heuristic in heuristics] == ["api.process_injection_cluster"]
    assert heuristics[0].evidence["apis"] == (
        "createremotethread",
        "virtualallocex",
        "writeprocessmemory",
    )


def test_build_pe_heuristics_normalizes_and_deduplicates_known_packer_section_names() -> None:
    features = {
        "imports": [],
        "sections": [],
        "packer_clues": [
            {"type": "section_name", "value": "UPX1"},
            {"type": "section_name", "value": "upx0"},
            {"type": "section_name", "value": "UPX0"},
            {"type": "section_name", "value": "upx1"},
        ],
        "overlay": {"present": False, "size": 0, "offset": None, "file_size": 1024},
    }

    heuristics = build_pe_heuristics(features)

    assert [heuristic.key for heuristic in heuristics] == ["packer.known_section_name"]
    assert heuristics[0].evidence["section_names"] == ("upx0", "upx1")
