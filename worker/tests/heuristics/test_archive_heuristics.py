"""Tests for archive summary synthesis and heuristic emission."""

from __future__ import annotations

from malscan_worker.extractors.base import ExtractedFile
from malscan_worker.heuristics.archive import build_archive_heuristics, build_archive_summary


def test_build_archive_summary_counts_archive_characteristics() -> None:
    files = [
        ExtractedFile(
            path="/tmp/run.exe",
            original_name="run.exe",
            size=10,
            origin_path="run.exe",
        ),
        ExtractedFile(
            path="/tmp/launch.lnk",
            original_name="launch.lnk",
            size=5,
            origin_path="nested/launch.js",
        ),
        ExtractedFile(
            path="/tmp/archive.zip",
            original_name="archive.zip",
            size=15,
            origin_path="nested/inner/archive.zip",
        ),
        ExtractedFile(
            path="/tmp/other-run.exe",
            original_name="run.exe",
            size=20,
            origin_path="other/run.exe",
        ),
        ExtractedFile(
            path="/tmp/duplicate-note.txt",
            original_name="note.txt",
            size=7,
            origin_path="nested/deeper/note.txt",
        ),
        ExtractedFile(
            path="/tmp/another-note.txt",
            original_name="note.txt",
            size=8,
            origin_path="nested/deeper/even-more/note.txt",
        ),
    ]

    summary = build_archive_summary(
        files=files,
        warnings=[
            "Path traversal skipped: ../evil.exe",
            "Path traversal skipped: ../../runner.js",
            "Max files limit (100) reached",
        ],
        password_protected=True,
    )

    assert summary == {
        "entry_count": 6,
        "executable_member_count": 3,
        "nested_archive_count": 1,
        "duplicate_basename_count": 2,
        "max_member_depth": 4,
        "password_protected": True,
        "path_traversal_skipped": 2,
        "total_extracted_bytes": 65,
        "member_extension_histogram": {
            "exe": 2,
            "lnk": 1,
            "txt": 2,
            "zip": 1,
        },
    }


def test_build_archive_heuristics_emits_required_signals() -> None:
    summary = {
        "entry_count": 6,
        "executable_member_count": 2,
        "nested_archive_count": 1,
        "duplicate_basename_count": 1,
        "max_member_depth": 4,
        "password_protected": True,
        "path_traversal_skipped": 2,
        "total_extracted_bytes": 50,
        "member_extension_histogram": {
            "exe": 1,
            "lnk": 1,
            "txt": 3,
            "zip": 1,
        },
    }

    heuristics = build_archive_heuristics(summary)

    assert [heuristic.key for heuristic in heuristics] == [
        "archive.executable_concentration",
        "archive.password_protected",
        "archive.path_traversal_member",
        "archive.deep_nesting",
    ]
    assert heuristics[0].scope == "archive"
    assert heuristics[0].category == "archive"
    assert heuristics[0].role == "corroborating"
    assert heuristics[0].severity == "medium"
    assert heuristics[0].confidence == 0.8
    assert heuristics[0].summary == "Archive contains multiple executable-like members"
    assert heuristics[0].evidence == {
        "executable_member_count": 2,
    }
    assert heuristics[0].tags == ("archive", "embedded-executable")
    assert heuristics[1].category == "archive"
    assert heuristics[1].role == "evidence_only"
    assert heuristics[1].severity == "low"
    assert heuristics[1].confidence == 0.7
    assert heuristics[1].summary == "Archive requires a password for extraction"
    assert heuristics[1].evidence["password_protected"] is True
    assert heuristics[1].tags == ("archive", "encrypted")
    assert heuristics[2].category == "archive"
    assert heuristics[2].role == "evidence_only"
    assert heuristics[2].severity == "low"
    assert heuristics[2].confidence == 0.75
    assert heuristics[2].summary == "Archive contains unsafe path traversal members"
    assert heuristics[2].evidence["path_traversal_skipped"] == 2
    assert heuristics[2].tags == ("archive", "path-traversal")
    assert heuristics[3].category == "archive"
    assert heuristics[3].role == "evidence_only"
    assert heuristics[3].severity == "low"
    assert heuristics[3].confidence == 0.6
    assert heuristics[3].summary == "Archive member paths are deeply nested"
    assert heuristics[3].evidence["max_member_depth"] == 4
    assert heuristics[3].tags == ("archive", "nesting")


def test_build_archive_heuristics_returns_empty_for_benign_summary() -> None:
    summary = {
        "entry_count": 3,
        "executable_member_count": 0,
        "nested_archive_count": 0,
        "duplicate_basename_count": 0,
        "max_member_depth": 3,
        "password_protected": False,
        "path_traversal_skipped": 0,
        "total_extracted_bytes": 120,
        "member_extension_histogram": {
            "md": 1,
            "txt": 2,
        },
    }

    assert build_archive_heuristics(summary) == []


def test_build_archive_heuristics_ignores_single_executable_entry_archive() -> None:
    summary = {
        "entry_count": 1,
        "executable_member_count": 1,
        "nested_archive_count": 0,
        "duplicate_basename_count": 0,
        "max_member_depth": 1,
        "password_protected": False,
        "path_traversal_skipped": 0,
        "total_extracted_bytes": 42,
        "member_extension_histogram": {"js": 1},
    }

    assert [heuristic.key for heuristic in build_archive_heuristics(summary)] == []


def test_build_archive_heuristics_ignores_deep_nesting_below_plan_threshold() -> None:
    summary = {
        "entry_count": 5,
        "executable_member_count": 2,
        "nested_archive_count": 0,
        "duplicate_basename_count": 0,
        "max_member_depth": 3,
        "password_protected": False,
        "path_traversal_skipped": 0,
        "total_extracted_bytes": 42,
        "member_extension_histogram": {"exe": 2},
    }

    assert [heuristic.key for heuristic in build_archive_heuristics(summary)] == [
        "archive.executable_concentration"
    ]


def test_build_archive_summary_normalizes_basenames_and_keeps_extensionless_members() -> None:
    files = [
        ExtractedFile(
            path="/tmp/Run.EXE",
            original_name="Run.EXE",
            size=10,
            origin_path="Run.EXE",
        ),
        ExtractedFile(
            path="/tmp/run.exe",
            original_name="run.exe",
            size=11,
            origin_path="nested/run.exe",
        ),
        ExtractedFile(
            path="/tmp/README",
            original_name="README",
            size=12,
            origin_path="nested/README",
        ),
    ]

    summary = build_archive_summary(files=files, warnings=[], password_protected=False)

    assert summary["duplicate_basename_count"] == 1
    assert summary["member_extension_histogram"] == {"": 1, "exe": 2}


def test_build_archive_summary_uses_task_6_extension_sets() -> None:
    files = [
        ExtractedFile(
            path="/tmp/archive.tgz",
            original_name="archive.tgz",
            size=10,
            origin_path="archive.tgz",
        ),
        ExtractedFile(
            path="/tmp/runner.jar",
            original_name="runner.jar",
            size=12,
            origin_path="runner.jar",
        ),
    ]

    summary = build_archive_summary(files=files, warnings=[], password_protected=False)

    assert summary["nested_archive_count"] == 0
    assert summary["executable_member_count"] == 0
