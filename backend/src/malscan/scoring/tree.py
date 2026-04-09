"""Tree-aware descendant rollup scoring helpers."""

from __future__ import annotations

from math import floor
from typing import Any

from malscan.scoring.models import RiskDecision, ScoreBreakdown
from malscan.scoring.policy import (
    DEPTH_DECAY,
    INHERITANCE_BASE,
    INHERITED_SCORE_CAP,
    LEGACY_VERDICT_MAP,
)


def _level_from_score(score: int) -> str:
    if score >= 85:
        return "malicious"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 10:
        return "low"
    return "clean"


def merge_with_descendants(
    *,
    local: RiskDecision,
    descendants: list[dict[str, Any]],
) -> RiskDecision:
    seen_hashes: set[str] = set()
    top_descendants: list[dict[str, Any]] = []
    branch_scores: list[int] = []
    malicious_descendants = 0
    high_descendants = 0
    direct_child_malicious = False
    any_nearby_high_or_malicious = False

    for descendant in descendants:
        if descendant.get("verdict") == "skipped":
            continue
        if descendant.get("extraction_note") == "duplicate_within_extraction":
            continue

        sha256 = descendant.get("sha256")
        if sha256 in seen_hashes:
            continue
        seen_hashes.add(sha256)

        level = descendant.get("risk_level", "clean")
        depth = descendant.get("relative_depth") or 0
        base = INHERITANCE_BASE.get(level, 0)
        multiplier = DEPTH_DECAY.get(depth, 0.35)
        inherited_points = floor(base * multiplier)

        descendant_copy = dict(descendant)
        descendant_copy["inherited_points"] = inherited_points
        top_descendants.append(descendant_copy)
        branch_scores.append(inherited_points)

        if level == "malicious":
            malicious_descendants += 1
            if depth == 1:
                direct_child_malicious = True
        if level == "high":
            high_descendants += 1
        if level in {"high", "malicious"}:
            if depth <= 2:
                any_nearby_high_or_malicious = True

    top_descendants.sort(key=lambda item: item.get("inherited_points", 0), reverse=True)
    branch_scores.sort(reverse=True)
    inherited_score = min(INHERITED_SCORE_CAP, sum(branch_scores[:3]))
    final_score = min(100, local.risk_score + inherited_score)

    malicious_gate_open = local.breakdown.malicious_gate_open
    high_gate_open = local.breakdown.high_gate_open

    if direct_child_malicious:
        final_score = max(final_score, 60)
        high_gate_open = True
    if any_nearby_high_or_malicious:
        high_gate_open = True

    if malicious_descendants >= 2:
        malicious_gate_open = True
        final_score = max(final_score, 85)
    elif direct_child_malicious and local.breakdown.local_score >= 20:
        malicious_gate_open = True
        final_score = max(final_score, 85)

    if not malicious_gate_open:
        final_score = min(final_score, 84)
    if not high_gate_open:
        final_score = min(final_score, 59)

    final_level = _level_from_score(final_score)
    breakdown = ScoreBreakdown(
        local_score=local.breakdown.local_score,
        inherited_score=inherited_score,
        synergy_bonus=local.breakdown.synergy_bonus,
        dampener=local.breakdown.dampener,
        final_score=final_score,
        malicious_gate_open=malicious_gate_open,
        high_gate_open=high_gate_open,
        independent_source_count=local.breakdown.independent_source_count,
    )
    return RiskDecision(
        risk_score=final_score,
        risk_level=final_level,
        legacy_verdict=LEGACY_VERDICT_MAP[final_level],
        evidence=local.evidence,
        top_evidence=local.top_evidence,
        breakdown=breakdown,
        descendant_summary={
            "total_descendants": len(top_descendants),
            "malicious_descendants": malicious_descendants,
            "high_descendants": high_descendants,
            "top_descendants": top_descendants[:3],
        },
        policy_version=local.policy_version,
    )
