"""Script-like heuristic synthesis."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from malscan_worker.heuristics.common import evaluate_lolbin_chain
from malscan_worker.heuristics.models import HeuristicHit, make_hit

_AMSI_RE = re.compile(
    r"(amsiutils|amsiinitfailed|system\.management\.automation\.amsi|bypass\s+amsi)",
    re.IGNORECASE,
)
_LONG_LINE_MIN = 500
_OBFUSCATION_SIGNAL_MIN = 20


def build_script_heuristics(
    features: Mapping[str, object],
    *,
    scope: str = "script",
) -> list[HeuristicHit]:
    """Build deterministic script-like heuristics from extracted features."""

    heuristics: list[HeuristicHit] = []

    text_preview = _as_text(features.get("text_preview"))
    text_for_detection = _as_text(features.get("text_for_heuristics")) or text_preview
    encoded_strings = _as_string_tuple(features.get("encoded_strings"))
    network_indicators = _as_string_tuple(features.get("network_indicators"))
    process_operations = _as_string_tuple(features.get("process_operations"))
    registry_operations = _as_string_tuple(features.get("registry_operations"))
    file_operations = _as_string_tuple(features.get("file_operations"))
    download_operations = _as_string_tuple(features.get("download_operations"))
    exec_operations = _as_string_tuple(features.get("exec_operations"))
    max_line_length = _as_int(features.get("max_line_length"))
    obfuscation_score = _as_int(features.get("obfuscation_score"))

    execution_context = bool(
        exec_operations or process_operations or registry_operations or file_operations
    )
    if not execution_context and text_for_detection:
        execution_context = bool(
            re.search(
                r"\b(?:powershell|cmd(?:\.exe)?|mshta|wscript|cscript)\b",
                text_for_detection,
                re.IGNORECASE,
            )
        )

    if encoded_strings and execution_context:
        heuristics.append(
            make_hit(
                key="script.encoded_command_execution",
                category="behavior",
                scope=scope,
                role="detection",
                severity="high",
                confidence=0.87,
                summary="Encoded content appears alongside command execution context",
                evidence={
                    "encoded_strings": list(encoded_strings),
                    "exec_operations": list(exec_operations),
                },
                tags=("script", "encoded", "execution"),
            )
        )

    amsi_match = _extract_amsi_match(text_for_detection)
    if amsi_match is not None:
        heuristics.append(
            make_hit(
                key="script.amsi_bypass",
                category="behavior",
                scope=scope,
                role="detection",
                severity="high",
                confidence=0.9,
                summary="Script text contains AMSI bypass markers",
                evidence={"text_preview": text_preview, "matched_marker": amsi_match},
                tags=("script", "amsi", "defense-evasion"),
            )
        )

    if max_line_length >= _LONG_LINE_MIN and (
        obfuscation_score >= _OBFUSCATION_SIGNAL_MIN or encoded_strings
    ):
        heuristics.append(
            make_hit(
                key="script.long_line_entropy_cluster",
                category="content",
                scope=scope,
                role="signal",
                severity="medium",
                confidence=0.76,
                summary="Long script lines appear with obfuscation signals",
                evidence={
                    "max_line_length": max_line_length,
                    "obfuscation_score": obfuscation_score,
                    "encoded_strings": list(encoded_strings),
                },
                tags=("script", "obfuscation", "long-line"),
            )
        )

    if download_operations and (exec_operations or process_operations):
        heuristics.append(
            make_hit(
                key="script.download_execute_chain",
                category="behavior",
                scope=scope,
                role="detection",
                severity="high",
                confidence=0.88,
                summary="Script combines download behavior with execution operations",
                evidence={
                    "download_operations": list(download_operations),
                    "exec_operations": list(exec_operations),
                    "process_operations": list(process_operations),
                    "network_indicators": list(network_indicators),
                },
                tags=("script", "download", "execution"),
            )
        )

    if text_for_detection:
        heuristics.extend(evaluate_lolbin_chain(scope=scope, text=text_for_detection))

    return heuristics


def _as_text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _as_string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return ()
    return tuple(sorted({str(item) for item in value if isinstance(item, str) and item}))


def _as_int(value: object) -> int:
    return value if isinstance(value, int) else 0


def _extract_amsi_match(text: str) -> str | None:
    if not text:
        return None
    match = _AMSI_RE.search(text)
    if match is None:
        return None
    return match.group(0).lower()


__all__ = ["build_script_heuristics"]
