"""PDF-specific heuristic synthesis."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from malscan_worker.heuristics.models import HeuristicHit, make_hit

_EXECUTABLE_SUFFIXES = (
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".jar",
    ".js",
    ".ps1",
    ".scr",
    ".vbs",
)
_COMMAND_NAMES = frozenset(
    {
        "cmd",
        "cmd.exe",
        "mshta",
        "mshta.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "regsvr32",
        "regsvr32.exe",
        "rundll32",
        "rundll32.exe",
        "wscript",
        "wscript.exe",
        "cscript",
        "cscript.exe",
    }
)
_TOKEN_SPLIT_RE = re.compile(r"[\s\"']+")


def build_pdf_heuristics(features: Mapping[str, object]) -> list[HeuristicHit]:
    """Build deterministic PDF heuristics from extracted features."""

    heuristics: list[HeuristicHit] = []

    launch_targets = _normalize_launch_targets(features.get("launch_actions"))
    if launch_targets:
        heuristics.append(
            make_hit(
                key="pdf.launch_action_executable",
                category="behavior",
                scope="pdf",
                role="detection",
                severity="high",
                confidence=0.89,
                summary="PDF launch action targets an executable or command payload",
                evidence={"targets": launch_targets},
                tags=("pdf", "launch", "executable"),
            )
        )

    executable_embeds = _normalize_embedded_files(features.get("embedded_files"))
    if executable_embeds:
        heuristics.append(
            make_hit(
                key="resource.embedded_executable",
                category="resource",
                scope="pdf",
                role="detection",
                severity="high",
                confidence=0.91,
                summary="PDF contains embedded executable-like files",
                evidence={"files": executable_embeds},
                tags=("pdf", "embedded", "executable"),
            )
        )

    return heuristics


def _normalize_launch_targets(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return ()

    normalized = {
        item.strip()
        for item in value
        if isinstance(item, str) and _is_executable_or_command_target(item.strip())
    }
    return tuple(sorted(normalized))


def _is_executable_or_command_target(value: str) -> bool:
    if not value:
        return False

    lowered = value.lower()
    if lowered in {"launch", "/launch"}:
        return False

    if "://" in lowered:
        return False

    if lowered in _COMMAND_NAMES:
        return True

    if lowered.endswith(_EXECUTABLE_SUFFIXES):
        return True

    for token in _TOKEN_SPLIT_RE.split(lowered):
        token = token.strip()
        if not token:
            continue
        if token in _COMMAND_NAMES or token.endswith(_EXECUTABLE_SUFFIXES):
            return True

    return False


def _normalize_embedded_files(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return ()

    normalized: dict[str, dict[str, object]] = {}
    for item in value:
        if not isinstance(item, Mapping) or not bool(item.get("executable")):
            continue

        name = str(item.get("name", "")).strip()
        if not name:
            continue

        normalized[name] = {"name": name, "executable": True}

    return tuple(normalized[name] for name in sorted(normalized))


__all__ = ["build_pdf_heuristics"]
