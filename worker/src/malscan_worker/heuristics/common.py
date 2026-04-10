"""Shared deterministic heuristic evaluators."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from malscan_worker.heuristics.models import HeuristicHit, make_hit

_ENTROPY_THRESHOLD = 7.2
_LOLBINS = ("certutil", "mshta", "powershell", "regsvr32", "rundll32", "wmic")
_LOLBIN_RE = re.compile(
    r"\b(?:certutil|mshta|powershell|regsvr32|rundll32|wmic)(?:\.exe)?\b", re.IGNORECASE
)
_REMOTE_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_ENCODED_PAYLOAD_RE = re.compile(r"(?:^|\s)(?:-|/)(?:enc|encodedcommand)(?=\s|$)", re.IGNORECASE)
_EXECUTION_PRIMITIVE_RE = re.compile(
    r"\b(?:start-process|invoke-expression|iex|cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-c)\b",
    re.IGNORECASE,
)
_CONTEXT_WINDOW = 48
_SENTENCE_BOUNDARY_RE = re.compile(r"[.!?]\s+[A-Z]")
_COMMAND_FLAG_RE = re.compile(
    r"^\s+(?:-[A-Za-z][\w-]*|/[A-Za-z][\w-]*)(?:\s+(?:-[A-Za-z][\w-]*|/[A-Za-z][\w-]*))*\s+https?://",
    re.IGNORECASE,
)


def evaluate_entropy_regions(
    scope: str, regions: Iterable[Mapping[str, object]]
) -> list[HeuristicHit]:
    """Emit a hit when multiple regions have high entropy."""

    high_regions: list[dict[str, object]] = []
    for region in regions:
        entropy = region.get("entropy")
        if isinstance(entropy, int | float) and entropy >= _ENTROPY_THRESHOLD:
            high_regions.append({"name": region.get("name"), "entropy": entropy})

    if len(high_regions) < 2:
        return []

    return [
        make_hit(
            key="entropy.high_region_cluster",
            category="content",
            scope=scope,
            role="signal",
            severity="medium",
            confidence=0.72,
            summary="Multiple regions have high entropy",
            evidence={
                "regions": tuple(high_regions),
                "count": len(high_regions),
                "threshold": _ENTROPY_THRESHOLD,
            },
            tags=("entropy", "regions"),
        )
    ]


def evaluate_lolbin_chain(scope: str, text: str) -> list[HeuristicHit]:
    """Classify LOLBIN references by surrounding execution context."""

    matched_lolbins: list[str] = []
    signals: list[str] = []

    for match in _LOLBIN_RE.finditer(text):
        lolbin = match.group(0).removesuffix(".exe").lower()
        if lolbin not in matched_lolbins:
            matched_lolbins.append(lolbin)

        trailing_context = text[match.end() : min(len(text), match.end() + _CONTEXT_WINDOW * 2)]
        sentence_boundary = _SENTENCE_BOUNDARY_RE.search(trailing_context)
        if sentence_boundary is not None:
            trailing_context = trailing_context[: sentence_boundary.start() + 1]

        if (
            re.match(r'^\s+["\']?https?://', trailing_context, re.IGNORECASE)
            or _COMMAND_FLAG_RE.match(trailing_context)
        ) and "remote_url" not in signals:
            signals.append("remote_url")
        if _ENCODED_PAYLOAD_RE.search(trailing_context[:32]) and "encoded_payload" not in signals:
            signals.append("encoded_payload")
        if (
            _EXECUTION_PRIMITIVE_RE.search(trailing_context)
            and "execution_primitive" not in signals
        ):
            signals.append("execution_primitive")

    matched_lolbins_tuple = tuple(matched_lolbins)
    if not matched_lolbins_tuple:
        return []

    if signals:
        signal_tags = {
            "remote_url": "network",
            "encoded_payload": "encoded",
            "execution_primitive": "execution",
        }
        tags = ["lolbin", "execution"]
        for signal in signals:
            tag = signal_tags[signal]
            if tag not in tags:
                tags.append(tag)

        return [
            make_hit(
                key="lolbin.execution_chain",
                category="behavior",
                scope=scope,
                role="detection",
                severity="medium",
                confidence=0.8,
                summary="LOLBIN appears with execution-chain context",
                evidence={"lolbins": matched_lolbins_tuple, "signals": tuple(signals)},
                tags=tuple(tags),
            )
        ]

    return [
        make_hit(
            key="lolbin.reference_only",
            category="behavior",
            scope=scope,
            role="signal",
            severity="weak",
            confidence=0.52,
            summary="LOLBIN reference found without execution context",
            evidence={"lolbins": matched_lolbins_tuple},
            tags=("lolbin", "reference"),
        )
    ]


__all__ = ["evaluate_entropy_regions", "evaluate_lolbin_chain", "make_hit", "HeuristicHit"]
