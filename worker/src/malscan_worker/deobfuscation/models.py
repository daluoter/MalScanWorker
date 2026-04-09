"""Core models for deobfuscation candidates and provenance."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

StopReason = Literal["candidate_cap", "wall_time"]


@dataclass
class CandidateProvenance:
    """Source metadata describing where a candidate was discovered."""

    decoder: str
    offset: int
    length: int
    key: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class DeobfuscationCandidate:
    """Decoded candidate produced by a deobfuscation technique."""

    content: bytes
    provenance: CandidateProvenance
    confidence: float = 0.0
    technique: str = ""
    truncated: bool = False
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.technique == "":
            self.technique = self.provenance.decoder


@dataclass
class DeobfuscationRunStats:
    """Execution metrics for a deobfuscation engine run."""

    input_bytes: int
    raw_candidate_count: int = 0
    deduplicated_candidate_count: int = 0
    filtered_low_confidence_count: int = 0
    final_candidate_count: int = 0
    applied_decoders: list[str] = field(default_factory=list)
    per_decoder_candidate_counts: dict[str, int] = field(default_factory=dict)
    candidate_cap_reached: bool = False
    wall_time_reached: bool = False
    stop_reason: StopReason | None = None
    truncated: bool = False


@dataclass
class DeobfuscationResult:
    """Engine output with candidates, extracted IOCs, and run stats."""

    candidates: list[DeobfuscationCandidate] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(
        default_factory=lambda: {
            "urls": [],
            "domains": [],
            "ips": [],
            "commands": [],
        }
    )
    stats: DeobfuscationRunStats = field(
        default_factory=lambda: DeobfuscationRunStats(input_bytes=0)
    )
