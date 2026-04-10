"""Archive-specific summary synthesis and heuristic emission."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

from malscan_worker.extractors.base import ExtractedFile
from malscan_worker.heuristics.models import HeuristicHit, make_hit

_EXECUTABLE_EXTENSIONS = frozenset(
    {
        ".bat",
        ".cmd",
        ".dll",
        ".exe",
        ".js",
        ".lnk",
        ".ps1",
        ".scr",
        ".vbs",
    }
)
_ARCHIVE_EXTENSIONS = frozenset(
    {
        ".7z",
        ".bz2",
        ".gz",
        ".iso",
        ".rar",
        ".tar",
        ".zip",
    }
)
_EXECUTABLE_CONCENTRATION_MIN_COUNT = 2
_DEEP_NESTING_THRESHOLD = 4


def build_archive_summary(
    files: list[ExtractedFile],
    warnings: list[str],
    password_protected: bool,
) -> dict[str, Any]:
    """Build a stable archive extraction summary for downstream findings."""

    basenames = [file.original_name.lower() for file in files if file.original_name]
    duplicate_basename_count = sum(1 for count in Counter(basenames).values() if count > 1)

    extension_histogram = Counter(
        _normalized_suffix(file.original_name).lstrip(".") for file in files
    )
    member_extension_histogram = dict(sorted(extension_histogram.items()))

    return {
        "entry_count": len(files),
        "executable_member_count": sum(
            1 for file in files if _normalized_suffix(file.original_name) in _EXECUTABLE_EXTENSIONS
        ),
        "nested_archive_count": sum(
            1 for file in files if _normalized_suffix(file.original_name) in _ARCHIVE_EXTENSIONS
        ),
        "duplicate_basename_count": duplicate_basename_count,
        "max_member_depth": max((_path_depth(file.origin_path) for file in files), default=0),
        "password_protected": password_protected,
        "path_traversal_skipped": sum(
            1 for warning in warnings if warning.lower().startswith("path traversal skipped:")
        ),
        "total_extracted_bytes": sum(file.size for file in files),
        "member_extension_histogram": member_extension_histogram,
    }


def build_archive_heuristics(summary: Mapping[str, object]) -> list[HeuristicHit]:
    """Build deterministic archive heuristics from extraction summary."""

    heuristics: list[HeuristicHit] = []

    executable_member_count = _as_int(summary.get("executable_member_count"))
    max_member_depth = _as_int(summary.get("max_member_depth"))
    path_traversal_skipped = _as_int(summary.get("path_traversal_skipped"))
    password_protected = bool(summary.get("password_protected"))

    if executable_member_count >= _EXECUTABLE_CONCENTRATION_MIN_COUNT:
        heuristics.append(
            make_hit(
                key="archive.executable_concentration",
                category="archive",
                scope="archive",
                role="corroborating",
                severity="medium",
                confidence=0.8,
                summary="Archive contains multiple executable-like members",
                evidence={"executable_member_count": executable_member_count},
                tags=("archive", "embedded-executable"),
            )
        )

    if password_protected:
        heuristics.append(
            make_hit(
                key="archive.password_protected",
                category="archive",
                scope="archive",
                role="evidence_only",
                severity="low",
                confidence=0.7,
                summary="Archive requires a password for extraction",
                evidence={"password_protected": True},
                tags=("archive", "encrypted"),
            )
        )

    if path_traversal_skipped > 0:
        heuristics.append(
            make_hit(
                key="archive.path_traversal_member",
                category="archive",
                scope="archive",
                role="evidence_only",
                severity="low",
                confidence=0.75,
                summary="Archive contains unsafe path traversal members",
                evidence={"path_traversal_skipped": path_traversal_skipped},
                tags=("archive", "path-traversal"),
            )
        )

    if max_member_depth >= _DEEP_NESTING_THRESHOLD:
        heuristics.append(
            make_hit(
                key="archive.deep_nesting",
                category="archive",
                scope="archive",
                role="evidence_only",
                severity="low",
                confidence=0.6,
                summary="Archive member paths are deeply nested",
                evidence={"max_member_depth": max_member_depth},
                tags=("archive", "nesting"),
            )
        )

    return heuristics


def _normalized_suffix(name: str) -> str:
    return PurePosixPath(name).suffix.lower()


def _path_depth(path: str) -> int:
    normalized = path.replace("\\", "/").strip("/")
    if not normalized:
        return 0
    return normalized.count("/") + 1


def _as_int(value: object) -> int:
    return value if isinstance(value, int) else 0


__all__ = ["build_archive_heuristics", "build_archive_summary"]
