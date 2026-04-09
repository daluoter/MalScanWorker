"""Tests for scoring model skeleton and policy constants."""

from types import MappingProxyType
from typing import get_type_hints

from malscan.scoring import EvidenceRecord, RiskDecision, ScoreBreakdown
from malscan.scoring.policy import LEGACY_VERDICT_MAP, LEVEL_THRESHOLDS, POLICY_VERSION


def test_evidence_record_defaults() -> None:
    record = EvidenceRecord(
        evidence_id="ev-1",
        source="sandbox",
        kind="behavior",
        tier="strong",
        severity="high",
        confidence=0.6,
        points=25,
        cap_group="behavior",
        scope="local",
        artifact_id="artifact-1",
        related_artifact_id=None,
        depth=0,
        reason="Triggered suspicious API sequence",
    )

    assert record.tags == ()
    assert record.raw == {}


def test_evidence_record_raw_cannot_be_mutated() -> None:
    record = EvidenceRecord(
        evidence_id="ev-1",
        source="sandbox",
        kind="behavior",
        tier="strong",
        severity="high",
        confidence=0.6,
        points=25,
        cap_group="behavior",
        scope="local",
        artifact_id="artifact-1",
        related_artifact_id=None,
        depth=0,
        reason="Triggered suspicious API sequence",
        raw={"score": 1},
    )

    try:
        record.raw["score"] = 2
    except TypeError:
        pass
    else:
        raise AssertionError("record.raw should be immutable after construction")


def test_risk_decision_defaults() -> None:
    breakdown = ScoreBreakdown(final_score=42)
    decision = RiskDecision(
        risk_score=42,
        risk_level="medium",
        legacy_verdict="suspicious",
        evidence=[],
        top_evidence=[],
        breakdown=breakdown,
    )

    assert decision.policy_version == POLICY_VERSION
    assert decision.breakdown is breakdown
    assert decision.descendant_summary == {}


def test_legacy_verdict_map_dual_track_mapping() -> None:
    assert LEGACY_VERDICT_MAP == {
        "clean": "clean",
        "low": "suspicious",
        "medium": "suspicious",
        "high": "suspicious",
        "malicious": "malicious",
    }


def test_level_thresholds_exact_ranges() -> None:
    assert LEVEL_THRESHOLDS == {
        "clean": (0, 9),
        "low": (10, 29),
        "medium": (30, 59),
        "high": (60, 84),
        "malicious": (85, 100),
    }


def test_policy_mappings_cannot_be_mutated() -> None:
    assert isinstance(LEVEL_THRESHOLDS, MappingProxyType)
    assert isinstance(LEGACY_VERDICT_MAP, MappingProxyType)

    try:
        LEVEL_THRESHOLDS["clean"] = (0, 10)
    except TypeError:
        pass
    else:
        raise AssertionError("LEVEL_THRESHOLDS should be immutable")

    try:
        LEGACY_VERDICT_MAP["low"] = "clean"
    except TypeError:
        pass
    else:
        raise AssertionError("LEGACY_VERDICT_MAP should be immutable")


def test_evidence_record_type_contract() -> None:
    hints = get_type_hints(EvidenceRecord)

    assert hints["confidence"] is float
    assert hints["artifact_id"] == str | None
