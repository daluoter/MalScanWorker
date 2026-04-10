"""Tests for the local direct-evidence scoring engine."""

from malscan.scoring import EvidenceRecord
from malscan.scoring.engine import score_direct_evidence


def _ev(
    source: str,
    kind: str,
    tier: str,
    points: int,
    cap_group: str = "misc",
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=f"{source}:{kind}",
        source=source,
        kind=kind,
        tier=tier,
        severity="medium",
        confidence=0.8,
        points=points,
        cap_group=cap_group,
        scope="direct",
        artifact_id="artifact-1",
        related_artifact_id=None,
        depth=0,
        reason=kind,
    )


def test_ev_helper_builds_direct_evidence_record() -> None:
    record = _ev("static", "macro_autoexec", "medium", 30, "macro")

    assert record == EvidenceRecord(
        evidence_id="static:macro_autoexec",
        source="static",
        kind="macro_autoexec",
        tier="medium",
        severity="medium",
        confidence=0.8,
        points=30,
        cap_group="macro",
        scope="direct",
        artifact_id="artifact-1",
        related_artifact_id=None,
        depth=0,
        reason="macro_autoexec",
    )


def test_weak_only_evidence_is_capped_to_low_risk() -> None:
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("ioc", "generic_ioc_1", "weak", 20, "ioc_raw"),
            _ev("static", "generic_ioc_2", "weak", 18, "generic"),
        ]
    )

    assert decision.risk_score == 29
    assert decision.risk_level == "low"
    assert decision.legacy_verdict == "suspicious"


def test_missing_high_gate_caps_score_to_medium() -> None:
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("static", "macro_autoexec", "medium", 50, "macro"),
            _ev("ioc", "generic_ioc", "weak", 40, "ioc_raw"),
        ]
    )

    assert decision.risk_score == 59
    assert decision.risk_level == "medium"
    assert decision.breakdown.high_gate_open is False


def test_confirmed_signal_opens_malicious_gate() -> None:
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("intel", "confirmed_malware_family", "confirmed", 80, "family"),
            _ev("static", "macro_autoexec", "medium", 10, "macro"),
        ]
    )

    assert decision.risk_score == 95
    assert decision.risk_level == "malicious"
    assert decision.breakdown.malicious_gate_open is True


def test_two_strong_independent_sources_open_malicious_path() -> None:
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("yara", "yara_ransomware", "strong", 45, "yara"),
            _ev("sandbox", "sandbox_ransom_behavior", "strong", 45, "behavior"),
        ]
    )

    assert decision.risk_score == 100
    assert decision.risk_level == "malicious"
    assert decision.breakdown.synergy_bonus == 10


def test_pure_deobfuscation_is_capped_to_low_risk() -> None:
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("deobfuscation", "deobfuscated_payload_execution", "medium", 40, "deob"),
        ]
    )

    assert decision.risk_score == 20
    assert decision.risk_level == "low"


def test_benign_context_deobfuscation_does_not_open_extra_synergy() -> None:
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("deobfuscation", "deobfuscated_payload_execution", "benign_context", 40, "deob"),
            _ev("yara", "yara_ransomware", "weak", 15, "yara"),
        ]
    )

    assert decision.breakdown.synergy_bonus == 0
    assert decision.risk_score == 15


def test_confirmed_plus_one_strong_source_gets_only_five_point_synergy() -> None:
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("intel", "confirmed_malware_family", "confirmed", 40, "family"),
            _ev("yara", "yara_ransomware", "strong", 30, "yara"),
        ]
    )

    assert decision.breakdown.synergy_bonus == 5


def test_confirmed_plus_same_source_strong_evidence_gets_no_five_point_synergy() -> None:
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("intel", "confirmed_malware_family", "confirmed", 40, "family"),
            _ev("intel", "intel_cluster_match", "strong", 30, "intel_cluster"),
        ]
    )

    assert decision.breakdown.synergy_bonus == 0


def test_deobfuscated_payload_with_raw_ioc_does_not_get_extra_synergy() -> None:
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("deobfuscation", "deobfuscated_payload_execution", "medium", 12, "deob"),
            _ev("ioc", "generic_ioc", "weak", 15, "ioc_raw"),
        ]
    )

    assert decision.breakdown.synergy_bonus == 0
    assert decision.risk_score == 27


def test_overlapping_sources_do_not_open_one_strong_plus_two_medium_malicious_gate() -> None:
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("yara", "yara_ransomware", "strong", 45, "yara"),
            _ev("yara", "secondary_yara_family", "medium", 20, "yara_secondary"),
            _ev("static", "macro_autoexec", "medium", 25, "macro"),
        ]
    )

    assert decision.breakdown.malicious_gate_open is False
    assert decision.risk_score == 84
    assert decision.risk_level == "high"


def test_ev_helper_defaults_cap_group_to_misc() -> None:
    record = _ev("static", "macro_autoexec", "medium", 30)

    assert record.cap_group == "misc"


def test_entropy_heuristics_are_capped_by_entropy_family() -> None:
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("format-analysis", "entropy.high_region_cluster", "weak", 8, "heuristic_entropy"),
            _ev("format-analysis", "entropy.high_region_cluster", "weak", 8, "heuristic_entropy"),
            _ev("format-analysis", "entropy.high_region_cluster", "weak", 8, "heuristic_entropy"),
        ]
    )

    assert decision.breakdown.local_score == 12
    assert decision.risk_score == 12


def test_archive_heuristics_are_capped_by_archive_family() -> None:
    decision = score_direct_evidence(
        direct_evidence=[
            _ev(
                "archive-extract",
                "archive.executable_concentration",
                "medium",
                18,
                "heuristic_archive",
            ),
            _ev(
                "archive-extract", "archive.path_traversal_member", "weak", 10, "heuristic_archive"
            ),
            _ev("archive-extract", "archive.deep_nesting", "weak", 8, "heuristic_archive"),
        ]
    )

    assert decision.breakdown.local_score == 25
