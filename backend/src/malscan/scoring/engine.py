"""Local direct-evidence scoring engine."""

from collections import defaultdict

from malscan.scoring.models import EvidenceRecord, RiskDecision, ScoreBreakdown
from malscan.scoring.policy import (
    CAP_GROUP_LIMITS,
    LEGACY_VERDICT_MAP,
    LEVEL_THRESHOLDS,
    NO_HIGH_GATE_CAP,
    NO_MALICIOUS_GATE_CAP,
    POLICY_VERSION,
    PURE_DEOB_CAP,
    SYNERGY_CAP,
    WEAK_ONLY_CAP,
)


def _resolve_risk_level(score: int) -> str:
    for level, (lower, upper) in LEVEL_THRESHOLDS.items():
        if lower <= score <= upper:
            return level
    return "malicious"


def score_direct_evidence(*, direct_evidence: list[EvidenceRecord]) -> RiskDecision:
    ordered = sorted(direct_evidence, key=lambda ev: ev.points, reverse=True)
    scored_evidence: list[EvidenceRecord] = []
    local_score = 0
    synergy_bonus = 0
    weak_only = True
    confirmed_present = False
    confirmed_sources: set[str] = set()
    strong_sources: set[str] = set()
    medium_sources: set[str] = set()
    non_benign_sources: set[str] = set()
    cap_totals: dict[str, int] = defaultdict(int)

    for ev in ordered:
        if ev.tier == "benign_context":
            continue

        scored_evidence.append(ev)

        non_benign_sources.add(ev.source)
        if ev.tier != "weak":
            weak_only = False
        if ev.tier == "confirmed":
            confirmed_present = True
            confirmed_sources.add(ev.source)
        if ev.tier == "strong":
            strong_sources.add(ev.source)
        elif ev.tier == "medium":
            medium_sources.add(ev.source)

        effective_points = ev.points
        limit = CAP_GROUP_LIMITS.get(ev.cap_group)
        if limit is not None:
            remaining = max(0, limit - cap_totals[ev.cap_group])
            effective_points = min(effective_points, remaining)

        cap_totals[ev.cap_group] += effective_points
        local_score += effective_points

    if len(strong_sources) >= 2:
        synergy_bonus += 10
    elif confirmed_present and ((strong_sources | medium_sources) - confirmed_sources):
        synergy_bonus += 5

    if any(ev.kind.startswith("deobfuscated_payload") for ev in scored_evidence) and any(
        ev.source in {"yara", "sandbox", "intel"} for ev in scored_evidence
    ):
        synergy_bonus += 8

    synergy_bonus = min(synergy_bonus, SYNERGY_CAP)
    score = max(0, min(100, local_score + synergy_bonus))

    high_gate_open = bool(confirmed_present or strong_sources or len(medium_sources) >= 2)
    malicious_gate_open = False
    if confirmed_present:
        malicious_gate_open = True
    elif len(strong_sources) >= 2 and score >= 85:
        malicious_gate_open = True
    elif len(strong_sources) >= 1 and len(medium_sources - strong_sources) >= 2 and score >= 85:
        malicious_gate_open = True

    if weak_only:
        score = min(score, WEAK_ONLY_CAP)
    if not high_gate_open:
        score = min(score, NO_HIGH_GATE_CAP)
    if not malicious_gate_open:
        score = min(score, NO_MALICIOUS_GATE_CAP)
    if non_benign_sources == {"deobfuscation"}:
        score = min(score, PURE_DEOB_CAP)

    level = _resolve_risk_level(score)
    breakdown = ScoreBreakdown(
        local_score=local_score,
        inherited_score=0,
        synergy_bonus=synergy_bonus,
        dampener=0,
        final_score=score,
        malicious_gate_open=malicious_gate_open,
        high_gate_open=high_gate_open,
        independent_source_count=len(non_benign_sources),
    )
    return RiskDecision(
        risk_score=score,
        risk_level=level,
        legacy_verdict=LEGACY_VERDICT_MAP[level],
        evidence=ordered,
        top_evidence=ordered[:10],
        breakdown=breakdown,
        policy_version=POLICY_VERSION,
    )
