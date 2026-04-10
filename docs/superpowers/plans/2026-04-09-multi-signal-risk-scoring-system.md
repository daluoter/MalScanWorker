# Multi-Signal Risk Scoring System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current thin final verdict logic with an evidence-driven multi-signal scoring framework that produces `risk_score`, `risk_level`, explainable evidence, and tree-aware aggregation while preserving legacy `verdict` compatibility.

**Architecture:** Put the canonical scoring core in a shared backend package `backend/src/malscan/scoring/` so both backend and worker can use the same policy. Worker computes direct/local risk for the current artifact when a job finishes and persists compatible top-level report fields; backend computes final tree-aware risk when `/reports/{job_id}` is requested after all descendants have completed. This avoids stale parent scoring while preserving one policy engine.

**Tech Stack:** Python 3.11, FastAPI, SQLAlchemy async, pytest/pytest-asyncio, Poetry, Alembic, JSONB reports

**Spec:** `docs/superpowers/specs/2026-04-09-multi-signal-risk-scoring-system-design.md`

---

## Scope Notes

This implementation plan intentionally splits the work into two scoring phases that share one policy core:

1. **Worker local scoring:** score the current artifact from direct evidence only and persist `risk_score`, `risk_level`, compatibility `verdict`, and normalized evidence in the job result.
2. **Backend tree rollup:** when `/reports/{job_id}` is requested and all descendants are done, compute descendant inheritance and return the canonical tree-aware final risk block.

This split is required because parent jobs usually finish before descendant jobs complete. Computing full tree-aware final risk inside `worker/src/malscan_worker/pipeline.py` would produce stale parent risk.

The plan also preserves the current special-case `verdict="unknown"` password-exhausted report path. That path is not a completed analysis result, so it will keep `unknown` and get a conservative zeroed `risk` block instead of being forced into the new five-level mapping.

---

## File Structure

### New files (create)

| File | Responsibility |
|------|---------------|
| `backend/src/malscan/scoring/__init__.py` | Public exports for shared scoring core |
| `backend/src/malscan/scoring/models.py` | Evidence and scoring dataclasses |
| `backend/src/malscan/scoring/policy.py` | Thresholds, weights, caps, decay, mapping constants |
| `backend/src/malscan/scoring/adapters.py` | Stage-finding to evidence normalization adapters |
| `backend/src/malscan/scoring/engine.py` | Local scoring, gate logic, compatibility mapping |
| `backend/src/malscan/scoring/tree.py` | Tree-aware aggregation and descendant rollup helpers |
| `backend/alembic/versions/005_add_artifact_risk_fields.py` | Add `risk_level` and `policy_version` to artifacts |
| `backend/tests/test_scoring_models.py` | Shared scorer model tests |
| `backend/tests/test_scoring_adapters.py` | Stage adapter tests |
| `backend/tests/test_scoring_engine.py` | Local scoring gate/cap tests |
| `backend/tests/test_scoring_tree.py` | Descendant aggregation tests |
| `worker/tests/test_pipeline_risk_scoring.py` | Worker `_build_analysis_result()` risk payload tests |

### Existing files (modify)

| File | Change |
|------|--------|
| `worker/src/malscan_worker/pipeline.py` | Replace final verdict logic with shared local scorer integration and new `risk` block |
| `worker/src/malscan_worker/reporting.py` | Add zeroed `risk` block for password-exhausted `unknown` reports |
| `worker/src/malscan_worker/db.py` | Extend artifact persistence/update helpers for `risk_level` and `policy_version`; add helper to attach artifact to sub-job |
| `worker/src/malscan_worker/utils/submission.py` | Reuse shared scoring package import path safely and update artifact `job_id` after sub-job creation |
| `worker/src/malscan_worker/stages/yara_scan.py` | Emit YARA metadata needed for scoring classification |
| `worker/tests/test_pipeline.py` | Update pipeline result expectations |
| `worker/tests/test_deobfuscation_pipeline_integration.py` | Replace old additive deobfuscation score tests with new evidence-driven expectations |
| `worker/tests/test_password_flow.py` | Assert `unknown` reports include zeroed `risk` block |
| `worker/tests/test_db_artifact_insert.py` | Cover new artifact persistence fields |
| `worker/tests/test_internal_job_submission.py` | Assert artifact row is linked to created sub-job |
| `backend/src/malscan/models/artifact.py` | Add `risk_level` and `policy_version` model fields |
| `backend/src/malscan/api/routes.py` | Compute tree-aware final risk on report read, expose `risk_level`, update artifact tree node fields |
| `backend/src/malscan/schemas/requests.py` | Add `risk` and `risk_level` response schemas |
| `backend/tests/test_api.py` | Validate report response carries tree-aware risk data |
| `backend/tests/test_models.py` | Cover new artifact model fields |
| `backend/src/malscan/main.py` | Extend schema compatibility repair for new artifact columns |

---

## Task 1: Create shared scoring models and policy constants

**Files:**
- Create: `backend/src/malscan/scoring/__init__.py`
- Create: `backend/src/malscan/scoring/models.py`
- Create: `backend/src/malscan/scoring/policy.py`
- Create: `backend/tests/test_scoring_models.py`

- [ ] **Step 1: Write failing tests for evidence and decision dataclasses**

Create `backend/tests/test_scoring_models.py`:

```python
"""Tests for shared scoring models and policy constants."""

from malscan.scoring.models import EvidenceRecord, RiskDecision, ScoreBreakdown
from malscan.scoring.policy import LEGACY_VERDICT_MAP, LEVEL_THRESHOLDS


def test_evidence_record_defaults():
    record = EvidenceRecord(
        evidence_id="ev-1",
        source="yara",
        kind="yara_generic_heuristic",
        tier="weak",
        severity="medium",
        confidence=0.6,
        points=25,
        cap_group="yara",
        scope="direct",
        artifact_id=None,
        related_artifact_id=None,
        depth=0,
        reason="Generic downloader string hit",
    )

    assert record.tags == ()
    assert record.raw == {}


def test_risk_decision_holds_breakdown_and_policy_version():
    decision = RiskDecision(
        risk_score=59,
        risk_level="medium",
        legacy_verdict="suspicious",
        evidence=[],
        top_evidence=[],
        breakdown=ScoreBreakdown(final_score=59),
    )

    assert decision.policy_version == "msrs-v1"
    assert decision.breakdown.final_score == 59


def test_legacy_mapping_matches_dual_track_contract():
    assert LEGACY_VERDICT_MAP["clean"] == "clean"
    assert LEGACY_VERDICT_MAP["low"] == "suspicious"
    assert LEGACY_VERDICT_MAP["medium"] == "suspicious"
    assert LEGACY_VERDICT_MAP["high"] == "suspicious"
    assert LEGACY_VERDICT_MAP["malicious"] == "malicious"


def test_level_thresholds_cover_full_range_without_gap():
    assert LEVEL_THRESHOLDS["clean"] == (0, 9)
    assert LEVEL_THRESHOLDS["low"] == (10, 29)
    assert LEVEL_THRESHOLDS["medium"] == (30, 59)
    assert LEVEL_THRESHOLDS["high"] == (60, 84)
    assert LEVEL_THRESHOLDS["malicious"] == (85, 100)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && poetry run pytest tests/test_scoring_models.py -v`

Expected: `ModuleNotFoundError: No module named 'malscan.scoring'`

- [ ] **Step 3: Create shared scoring package exports**

Create `backend/src/malscan/scoring/__init__.py`:

```python
"""Shared scoring package used by backend and worker."""

from malscan.scoring.models import EvidenceRecord, RiskDecision, ScoreBreakdown

__all__ = ["EvidenceRecord", "RiskDecision", "ScoreBreakdown"]
```

- [ ] **Step 4: Implement scoring dataclasses**

Create `backend/src/malscan/scoring/models.py`:

```python
"""Shared dataclasses for multi-signal risk scoring."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    source: str
    kind: str
    tier: str
    severity: str
    confidence: float
    points: int
    cap_group: str
    scope: str
    artifact_id: str | None
    related_artifact_id: str | None
    depth: int
    reason: str
    tags: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScoreBreakdown:
    local_score: int = 0
    inherited_score: int = 0
    synergy_bonus: int = 0
    dampener: int = 0
    final_score: int = 0
    malicious_gate_open: bool = False
    high_gate_open: bool = False
    independent_source_count: int = 0


@dataclass
class RiskDecision:
    risk_score: int
    risk_level: str
    legacy_verdict: str
    evidence: list[EvidenceRecord]
    top_evidence: list[EvidenceRecord]
    breakdown: ScoreBreakdown
    descendant_summary: dict[str, Any] = field(default_factory=dict)
    policy_version: str = "msrs-v1"
```

- [ ] **Step 5: Implement policy constants**

Create `backend/src/malscan/scoring/policy.py`:

```python
"""Constants for multi-signal risk scoring policy."""

LEVEL_THRESHOLDS = {
    "clean": (0, 9),
    "low": (10, 29),
    "medium": (30, 59),
    "high": (60, 84),
    "malicious": (85, 100),
}

LEGACY_VERDICT_MAP = {
    "clean": "clean",
    "low": "suspicious",
    "medium": "suspicious",
    "high": "suspicious",
    "malicious": "malicious",
}

INHERITANCE_BASE = {
    "malicious": 35,
    "high": 25,
    "medium": 15,
    "low": 6,
    "clean": 0,
}

DEPTH_DECAY = {
    1: 1.00,
    2: 0.70,
    3: 0.50,
}

WEAK_ONLY_CAP = 29
NO_HIGH_GATE_CAP = 59
NO_MALICIOUS_GATE_CAP = 84
RAW_IOC_CAP = 15
PURE_DEOB_CAP = 20
INHERITED_SCORE_CAP = 40
SYNERGY_CAP = 15
POLICY_VERSION = "msrs-v1"
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd backend && poetry run pytest tests/test_scoring_models.py -v`

Expected: `4 passed`

- [ ] **Step 7: Commit**

```bash
git add backend/src/malscan/scoring/__init__.py backend/src/malscan/scoring/models.py backend/src/malscan/scoring/policy.py backend/tests/test_scoring_models.py
git commit -m "feat(scoring): add shared scoring models and policy constants"
```

---

## Task 2: Normalize stage outputs into evidence records

**Files:**
- Create: `backend/src/malscan/scoring/adapters.py`
- Create: `backend/tests/test_scoring_adapters.py`
- Modify: `worker/src/malscan_worker/stages/yara_scan.py`

- [ ] **Step 1: Write failing adapter tests for ClamAV, YARA, IOC, format-analysis, and deobfuscation**

Create `backend/tests/test_scoring_adapters.py`:

```python
"""Tests for scoring adapters that normalize stage findings into EvidenceRecord objects."""

from malscan.scoring.adapters import build_direct_evidence


def test_clamav_hit_becomes_confirmed_evidence():
    evidence = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "clamav": {"infected": True, "threat_name": "Win.Test.EICAR"},
            "yara": {"matches": []},
            "ioc-extract": {"urls": [], "domains": [], "ips": []},
            "format-analysis": {},
            "deobfuscation": {},
            "sandbox": {},
        },
    )

    assert any(ev.kind == "confirmed_malware_signature" for ev in evidence)
    assert any(ev.tier == "confirmed" for ev in evidence)


def test_yara_metadata_controls_classification_instead_of_rule_name_guessing():
    evidence = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "clamav": {"infected": False, "threat_name": None},
            "yara": {
                "matches": [
                    {
                        "rule": "AgentTesla_Family",
                        "namespace": "malware",
                        "severity": "high",
                        "classification": "malicious_family",
                        "confidence": "high",
                        "family": "AgentTesla",
                        "tags": ["stealer"],
                        "strings": ["$a"],
                    }
                ]
            },
            "ioc-extract": {"urls": [], "domains": [], "ips": []},
            "format-analysis": {},
            "deobfuscation": {},
            "sandbox": {},
        },
    )

    match = next(ev for ev in evidence if ev.source == "yara")
    assert match.kind == "yara_malicious_family"
    assert match.tier == "confirmed"
    assert match.raw["family"] == "AgentTesla"


def test_raw_iocs_are_emitted_as_weak_capped_evidence():
    evidence = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "clamav": {"infected": False, "threat_name": None},
            "yara": {"matches": []},
            "ioc-extract": {
                "urls": ["http://a.test", "http://b.test"],
                "domains": ["a.test"],
                "ips": ["8.8.8.8"],
            },
            "format-analysis": {},
            "deobfuscation": {},
            "sandbox": {},
        },
    )

    raw_ioc = [ev for ev in evidence if ev.source == "ioc"]
    assert len(raw_ioc) == 5
    assert all(ev.tier == "weak" for ev in raw_ioc)


def test_format_analysis_uses_indicators_before_support_score():
    evidence = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "clamav": {"infected": False, "threat_name": None},
            "yara": {"matches": []},
            "ioc-extract": {"urls": [], "domains": [], "ips": []},
            "format-analysis": {
                "risk_score": 64,
                "indicators": [
                    {"type": "equation_editor", "severity": "critical", "detail": "CVE chain"},
                    {"type": "suspicious_resource", "severity": "medium", "detail": "embedded shellcode"},
                ],
            },
            "deobfuscation": {},
            "sandbox": {},
        },
    )

    kinds = {ev.kind for ev in evidence if ev.source == "format-analysis"}
    assert "format_execution_or_exploit_critical" in kinds
    assert "format_structural_anomaly_medium" in kinds
    assert "format_risk_score_support" not in kinds


def test_deobfuscation_without_downstream_hits_stays_weak_or_medium():
    evidence = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "clamav": {"infected": False, "threat_name": None},
            "yara": {"matches": []},
            "ioc-extract": {"urls": [], "domains": [], "ips": []},
            "format-analysis": {},
            "deobfuscation": {
                "techniques_found": ["base64", "powershell_encoded"],
                "decoded_strings_preview": ["powershell -enc ..."],
            },
            "sandbox": {},
        },
    )

    deob = [ev for ev in evidence if ev.source == "deobfuscation"]
    assert len(deob) >= 2
    assert all(ev.tier in {"weak", "medium"} for ev in deob)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && poetry run pytest tests/test_scoring_adapters.py -v`

Expected: `ModuleNotFoundError` or `ImportError` because `malscan.scoring.adapters` does not exist.

- [ ] **Step 3: Expand YARA stage output to include scoring metadata**

Modify `worker/src/malscan_worker/stages/yara_scan.py` so each match carries YARA `meta` fields needed by the scorer:

```python
matches.append(
    {
        "rule": match.rule,
        "namespace": match.namespace,
        "description": meta_dict.get("description", ""),
        "severity": meta_dict.get("severity", "medium"),
        "author": meta_dict.get("author", ""),
        "classification": meta_dict.get("classification", "generic"),
        "confidence": meta_dict.get("confidence", "medium"),
        "family": meta_dict.get("family", ""),
        "tags": match.tags,
        "strings": strings_list,
    }
)
```

Do not guess YARA classification from rule names in the scorer. The scoring adapter should trust metadata first and default conservatively to `generic` if metadata is missing.

- [ ] **Step 4: Implement direct evidence adapters**

Create `backend/src/malscan/scoring/adapters.py`:

```python
"""Adapters that normalize raw stage findings into EvidenceRecord objects."""

from __future__ import annotations

from typing import Any

from malscan.scoring.models import EvidenceRecord


def _append(records: list[EvidenceRecord], **kwargs: Any) -> None:
    records.append(EvidenceRecord(**kwargs))


def build_direct_evidence(*, artifact_id: str | None, stage_findings: dict[str, Any]) -> list[EvidenceRecord]:
    records: list[EvidenceRecord] = []

    clamav = stage_findings.get("clamav", {}) or {}
    if clamav.get("infected"):
        _append(
            records,
            evidence_id="clamav:hit",
            source="clamav",
            kind="confirmed_malware_signature",
            tier="confirmed",
            severity="critical",
            confidence=1.0,
            points=95,
            cap_group="signature",
            scope="direct",
            artifact_id=artifact_id,
            related_artifact_id=None,
            depth=0,
            reason=f"ClamAV detected {clamav.get('threat_name') or 'malware'}",
            raw=dict(clamav),
        )

    yara = stage_findings.get("yara", {}) or {}
    for index, match in enumerate(yara.get("matches", []) or []):
        classification = str(match.get("classification", "generic")).lower()
        if classification == "malicious_family":
            kind, tier, points = "yara_malicious_family", "confirmed", 85
        elif classification == "exploit":
            kind, tier, points = "yara_exploit_rule", "strong", 75
        elif classification == "suspicious":
            kind, tier, points = "yara_suspicious_behavior", "strong", 55
        else:
            kind, tier, points = "yara_generic_heuristic", "weak", 25
        _append(
            records,
            evidence_id=f"yara:{index}",
            source="yara",
            kind=kind,
            tier=tier,
            severity=str(match.get("severity", "medium")).lower(),
            confidence={"low": 0.4, "medium": 0.7, "high": 0.95}.get(str(match.get("confidence", "medium")).lower(), 0.7),
            points=points,
            cap_group="yara",
            scope="direct",
            artifact_id=artifact_id,
            related_artifact_id=None,
            depth=0,
            reason=f"YARA rule {match.get('rule')} matched",
            raw=dict(match),
        )

    ioc = stage_findings.get("ioc-extract", {}) or {}
    urls = list(ioc.get("urls", []) or [])
    domains = list(ioc.get("domains", []) or [])
    ips = list(ioc.get("ips", ioc.get("ip_addresses", [])) or [])
    for index, url in enumerate(urls[:4]):
        _append(
            records,
            evidence_id=f"ioc:url:{index}",
            source="ioc",
            kind="raw_url_ioc",
            tier="weak",
            severity="low",
            confidence=0.5,
            points=3,
            cap_group="ioc_raw",
            scope="direct",
            artifact_id=artifact_id,
            related_artifact_id=None,
            depth=0,
            reason=f"Raw URL IOC extracted: {url}",
            raw={"value": url},
        )
    for index, domain in enumerate(domains[:4]):
        _append(
            records,
            evidence_id=f"ioc:domain:{index}",
            source="ioc",
            kind="raw_domain_ioc",
            tier="weak",
            severity="low",
            confidence=0.5,
            points=3,
            cap_group="ioc_raw",
            scope="direct",
            artifact_id=artifact_id,
            related_artifact_id=None,
            depth=0,
            reason=f"Raw domain IOC extracted: {domain}",
            raw={"value": domain},
        )
    for index, ip in enumerate(ips[:3]):
        _append(
            records,
            evidence_id=f"ioc:ip:{index}",
            source="ioc",
            kind="raw_ip_ioc",
            tier="weak",
            severity="low",
            confidence=0.5,
            points=4,
            cap_group="ioc_raw",
            scope="direct",
            artifact_id=artifact_id,
            related_artifact_id=None,
            depth=0,
            reason=f"Raw IP IOC extracted: {ip}",
            raw={"value": ip},
        )
    non_empty_types = sum(1 for values in (urls, domains, ips) if values)
    if non_empty_types >= 2:
        _append(
            records,
            evidence_id="ioc:multi-type",
            source="ioc",
            kind="ioc_multiple_types_bonus",
            tier="weak",
            severity="low",
            confidence=0.6,
            points=5,
            cap_group="ioc_raw",
            scope="direct",
            artifact_id=artifact_id,
            related_artifact_id=None,
            depth=0,
            reason="Multiple IOC types extracted from one artifact",
            raw={"urls": len(urls), "domains": len(domains), "ips": len(ips)},
        )

    fmt = stage_findings.get("format-analysis", {}) or {}
    indicators = list(fmt.get("indicators", []) or [])
    for index, indicator in enumerate(indicators):
        severity = str(indicator.get("severity", "medium")).lower()
        kind = str(indicator.get("type", "")).lower()
        if severity == "critical":
            mapped_kind, tier, points = "format_execution_or_exploit_critical", "strong", 70
        elif severity == "high":
            mapped_kind, tier, points = "format_execution_or_exploit_high", "strong", 50
        elif severity == "medium":
            mapped_kind, tier, points = "format_structural_anomaly_medium", "medium", 20
        else:
            mapped_kind, tier, points = "format_structural_anomaly_low", "weak", 8
        if kind in {"macro_auto_exec", "embedded_executable", "suspicious_launcher"}:
            mapped_kind, tier, points = "format_loader_or_dropper_pattern", "medium", 35
        _append(
            records,
            evidence_id=f"format:{index}",
            source="format-analysis",
            kind=mapped_kind,
            tier=tier,
            severity=severity,
            confidence=0.8 if tier in {"strong", "confirmed"} else 0.6,
            points=points,
            cap_group="format_structural",
            scope="direct",
            artifact_id=artifact_id,
            related_artifact_id=None,
            depth=0,
            reason=str(indicator.get("detail", indicator.get("type", "format indicator"))),
            raw=dict(indicator),
        )
    if len(indicators) < 2:
        risk_score = int(fmt.get("risk_score", 0) or 0)
        support_points = min(15, risk_score // 4)
        if support_points > 0:
            _append(
                records,
                evidence_id="format:support",
                source="format-analysis",
                kind="format_risk_score_support",
                tier="weak",
                severity="low",
                confidence=0.4,
                points=support_points,
                cap_group="format_structural",
                scope="direct",
                artifact_id=artifact_id,
                related_artifact_id=None,
                depth=0,
                reason="Analyzer fallback support score",
                raw={"risk_score": risk_score, "risk_factors": fmt.get("risk_factors", [])},
            )

    deob = stage_findings.get("deobfuscation", {}) or {}
    for index, technique in enumerate(list(deob.get("techniques_found", []) or [])[:3]):
        _append(
            records,
            evidence_id=f"deob:technique:{index}",
            source="deobfuscation",
            kind="deobfuscation_technique_found",
            tier="weak",
            severity="low",
            confidence=0.6,
            points=4,
            cap_group="deob",
            scope="direct",
            artifact_id=artifact_id,
            related_artifact_id=None,
            depth=0,
            reason=f"Obfuscation technique detected: {technique}",
            raw={"technique": technique},
        )
    for preview in list(deob.get("decoded_strings_preview", []) or [])[:3]:
        lowered = str(preview).lower()
        if any(token in lowered for token in ("powershell", "cmd.exe", "rundll32", "regsvr32")):
            _append(
                records,
                evidence_id=f"deob:exec:{abs(hash(preview))}",
                source="deobfuscation",
                kind="deobfuscated_payload_execution",
                tier="medium",
                severity="medium",
                confidence=0.75,
                points=12,
                cap_group="deob",
                scope="direct",
                artifact_id=artifact_id,
                related_artifact_id=None,
                depth=0,
                reason="Decoded content reveals execution-oriented payload",
                raw={"preview": preview},
            )

    sandbox = stage_findings.get("sandbox", {}) or {}
    behaviors = list(sandbox.get("behaviors", []) or [])
    network = list(sandbox.get("network_connections", []) or [])
    behavior_types = {str(item.get('type', '')).lower() for item in behaviors}
    if {"process_injection", "credential_theft", "ransomware"} & behavior_types:
        _append(
            records,
            evidence_id="sandbox:confirmed",
            source="sandbox",
            kind="sandbox_confirmed_malicious_behavior",
            tier="confirmed",
            severity="critical",
            confidence=1.0,
            points=95,
            cap_group="dynamic",
            scope="direct",
            artifact_id=artifact_id,
            related_artifact_id=None,
            depth=0,
            reason="Sandbox observed confirmed malicious behavior",
            raw={"behaviors": behaviors, "network_connections": network},
        )

    return records
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && poetry run pytest tests/test_scoring_adapters.py -v`

Expected: `5 passed`

- [ ] **Step 6: Commit**

```bash
git add backend/src/malscan/scoring/adapters.py backend/tests/test_scoring_adapters.py worker/src/malscan_worker/stages/yara_scan.py
git commit -m "feat(scoring): normalize stage findings into evidence records"
```

---

## Task 3: Implement local scoring engine with gates, caps, and compatibility mapping

**Files:**
- Create: `backend/src/malscan/scoring/engine.py`
- Create: `backend/tests/test_scoring_engine.py`

- [ ] **Step 1: Write failing engine tests for caps and malicious gates**

Create `backend/tests/test_scoring_engine.py`:

```python
"""Tests for local multi-signal scoring engine."""

from malscan.scoring.engine import score_direct_evidence
from malscan.scoring.models import EvidenceRecord


def _ev(source: str, kind: str, tier: str, points: int, cap_group: str = "misc") -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=f"{source}:{kind}:{points}",
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


def test_weak_only_evidence_is_capped_at_low_band():
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("ioc", "raw_url_ioc", "weak", 3, "ioc_raw"),
            _ev("ioc", "raw_ip_ioc", "weak", 4, "ioc_raw"),
            _ev("deobfuscation", "deobfuscation_technique_found", "weak", 4, "deob"),
            _ev("yara", "yara_generic_heuristic", "weak", 25, "yara"),
        ]
    )

    assert decision.risk_score == 29
    assert decision.risk_level == "low"
    assert decision.legacy_verdict == "suspicious"


def test_no_high_gate_caps_single_medium_source_at_medium():
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("format-analysis", "format_structural_anomaly_medium", "medium", 20, "format_structural"),
            _ev("yara", "yara_generic_heuristic", "weak", 25, "yara"),
            _ev("heuristic", "packed_binary", "weak", 12, "heuristic"),
            _ev("heuristic", "high_entropy_section", "weak", 8, "heuristic"),
        ]
    )

    assert decision.risk_score == 59
    assert decision.risk_level == "medium"
    assert decision.breakdown.high_gate_open is False


def test_confirmed_signal_opens_malicious_gate():
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("clamav", "confirmed_malware_signature", "confirmed", 95, "signature"),
        ]
    )

    assert decision.risk_score == 95
    assert decision.risk_level == "malicious"
    assert decision.breakdown.malicious_gate_open is True


def test_two_strong_independent_sources_open_high_and_malicious_path():
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("yara", "yara_exploit_rule", "strong", 75, "yara"),
            _ev("format-analysis", "format_execution_or_exploit_high", "strong", 50, "format_structural"),
        ]
    )

    assert decision.risk_score == 100
    assert decision.risk_level == "malicious"
    assert decision.breakdown.synergy_bonus == 10


def test_pure_deobfuscation_is_capped_even_when_points_sum_higher():
    decision = score_direct_evidence(
        direct_evidence=[
            _ev("deobfuscation", "deobfuscation_technique_found", "weak", 4, "deob"),
            _ev("deobfuscation", "deobfuscation_technique_found", "weak", 4, "deob"),
            _ev("deobfuscation", "deobfuscated_payload_execution", "medium", 12, "deob"),
            _ev("deobfuscation", "hidden_content_revealed_bonus", "medium", 5, "deob"),
        ]
    )

    assert decision.risk_score == 20
    assert decision.risk_level == "low"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && poetry run pytest tests/test_scoring_engine.py -v`

Expected: ImportError because `score_direct_evidence` does not exist yet.

- [ ] **Step 3: Implement the local scoring engine**

Create `backend/src/malscan/scoring/engine.py`:

```python
"""Local direct-evidence scoring engine for the multi-signal framework."""

from __future__ import annotations

from collections import defaultdict

from malscan.scoring.models import EvidenceRecord, RiskDecision, ScoreBreakdown
from malscan.scoring.policy import (
    LEGACY_VERDICT_MAP,
    LEVEL_THRESHOLDS,
    NO_HIGH_GATE_CAP,
    NO_MALICIOUS_GATE_CAP,
    POLICY_VERSION,
    PURE_DEOB_CAP,
    RAW_IOC_CAP,
    SYNERGY_CAP,
    WEAK_ONLY_CAP,
)


def _resolve_risk_level(score: int) -> str:
    for level, (low, high) in LEVEL_THRESHOLDS.items():
        if low <= score <= high:
            return level
    return "malicious"


def score_direct_evidence(*, direct_evidence: list[EvidenceRecord]) -> RiskDecision:
    ordered = sorted(direct_evidence, key=lambda ev: ev.points, reverse=True)

    local_score = 0
    synergy_bonus = 0
    dampener = 0
    weak_only = True
    strong_sources: set[str] = set()
    medium_sources: set[str] = set()
    non_benign_sources: set[str] = set()
    confirmed_present = False
    cap_totals: dict[str, int] = defaultdict(int)

    for ev in ordered:
        if ev.tier == "benign_context":
            continue
        non_benign_sources.add(ev.source)
        if ev.tier != "weak":
            weak_only = False
        if ev.tier == "confirmed":
            confirmed_present = True
        if ev.tier in {"confirmed", "strong"}:
            strong_sources.add(ev.source)
        if ev.tier == "medium":
            medium_sources.add(ev.source)
        cap_totals[ev.cap_group] += ev.points

    raw_ioc_total = 0
    deob_total = 0
    for ev in ordered:
        effective = ev.points
        if ev.cap_group == "ioc_raw":
            remaining = max(0, RAW_IOC_CAP - raw_ioc_total)
            effective = min(effective, remaining)
            raw_ioc_total += effective
        if ev.cap_group == "deob":
            remaining = max(0, PURE_DEOB_CAP - deob_total)
            effective = min(effective, remaining)
            deob_total += effective
        if ev.tier != "benign_context":
            local_score += effective

    if len(strong_sources) >= 2:
        synergy_bonus += 10
    elif confirmed_present and (strong_sources or medium_sources):
        synergy_bonus += 5

    if any(ev.kind.startswith("deobfuscated_payload") for ev in ordered) and any(ev.source in {"yara", "ioc", "sandbox"} for ev in ordered):
        synergy_bonus += 8

    score = max(0, min(100, local_score + min(synergy_bonus, SYNERGY_CAP) - dampener))

    high_gate_open = bool(confirmed_present or strong_sources or len(medium_sources) >= 2)
    malicious_gate_open = False
    if confirmed_present:
        malicious_gate_open = True
    elif len(strong_sources) >= 2 and score >= 85:
        malicious_gate_open = True
    elif len(strong_sources) >= 1 and len(medium_sources) >= 2 and score >= 85:
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
        synergy_bonus=min(synergy_bonus, SYNERGY_CAP),
        dampener=dampener,
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && poetry run pytest tests/test_scoring_engine.py -v`

Expected: `5 passed`

- [ ] **Step 5: Commit**

```bash
git add backend/src/malscan/scoring/engine.py backend/tests/test_scoring_engine.py
git commit -m "feat(scoring): add local risk engine with policy gates"
```

---

## Task 4: Implement tree aggregation in shared backend scoring core

**Files:**
- Create: `backend/src/malscan/scoring/tree.py`
- Create: `backend/tests/test_scoring_tree.py`

- [ ] **Step 1: Write failing tests for descendant inheritance and promotion floors**

Create `backend/tests/test_scoring_tree.py`:

```python
"""Tests for artifact tree scoring rollup."""

from malscan.scoring.models import RiskDecision, ScoreBreakdown
from malscan.scoring.tree import merge_with_descendants


def _decision(score: int, level: str) -> RiskDecision:
    return RiskDecision(
        risk_score=score,
        risk_level=level,
        legacy_verdict="malicious" if level == "malicious" else ("clean" if level == "clean" else "suspicious"),
        evidence=[],
        top_evidence=[],
        breakdown=ScoreBreakdown(local_score=score, final_score=score),
    )


def test_direct_malicious_child_promotes_parent_to_high_floor():
    merged = merge_with_descendants(
        local=_decision(5, "clean"),
        descendants=[
            {
                "artifact_id": "child-1",
                "sha256": "a" * 64,
                "relative_depth": 1,
                "risk_level": "malicious",
                "risk_score": 95,
                "origin_path": "archive/payload.exe",
            }
        ],
    )

    assert merged.risk_score == 60
    assert merged.risk_level == "high"


def test_deep_single_malicious_descendant_stays_low_without_local_support():
    merged = merge_with_descendants(
        local=_decision(0, "clean"),
        descendants=[
            {
                "artifact_id": "leaf-1",
                "sha256": "b" * 64,
                "relative_depth": 3,
                "risk_level": "malicious",
                "risk_score": 95,
                "origin_path": "a/b/c/leaf.ps1",
            }
        ],
    )

    assert merged.risk_score == 17
    assert merged.risk_level == "low"


def test_two_malicious_descendants_open_tree_malicious_gate():
    merged = merge_with_descendants(
        local=_decision(25, "low"),
        descendants=[
            {"artifact_id": "c1", "sha256": "1" * 64, "relative_depth": 1, "risk_level": "malicious", "risk_score": 95, "origin_path": "one.exe"},
            {"artifact_id": "c2", "sha256": "2" * 64, "relative_depth": 2, "risk_level": "malicious", "risk_score": 91, "origin_path": "two.dll"},
        ],
    )

    assert merged.risk_level == "malicious"
    assert merged.breakdown.malicious_gate_open is True


def test_duplicate_descendant_hash_contributes_once():
    merged = merge_with_descendants(
        local=_decision(15, "low"),
        descendants=[
            {"artifact_id": "d1", "sha256": "3" * 64, "relative_depth": 1, "risk_level": "high", "risk_score": 70, "origin_path": "a.exe"},
            {"artifact_id": "d2", "sha256": "3" * 64, "relative_depth": 1, "risk_level": "high", "risk_score": 70, "origin_path": "b.exe"},
        ],
    )

    assert merged.breakdown.inherited_score == 25
    assert merged.risk_score == 40
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && poetry run pytest tests/test_scoring_tree.py -v`

Expected: ImportError because `merge_with_descendants` does not exist.

- [ ] **Step 3: Implement tree aggregation helper**

Create `backend/src/malscan/scoring/tree.py`:

```python
"""Tree-aware aggregation helpers for artifact rollup scoring."""

from __future__ import annotations

from math import floor
from typing import Any

from malscan.scoring.models import RiskDecision, ScoreBreakdown
from malscan.scoring.policy import DEPTH_DECAY, INHERITANCE_BASE, INHERITED_SCORE_CAP, LEGACY_VERDICT_MAP


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


def merge_with_descendants(*, local: RiskDecision, descendants: list[dict[str, Any]]) -> RiskDecision:
    seen_hashes: set[str] = set()
    branch_scores: list[tuple[int, dict[str, Any]]] = []
    malicious_descendants = 0
    high_descendants = 0

    for desc in descendants:
        sha256 = str(desc["sha256"])
        if sha256 in seen_hashes:
            continue
        seen_hashes.add(sha256)

        level = str(desc["risk_level"])
        base = INHERITANCE_BASE.get(level, 0)
        relative_depth = int(desc["relative_depth"])
        multiplier = DEPTH_DECAY.get(relative_depth, 0.35)
        inherited_points = floor(base * multiplier)
        if level == "malicious":
            malicious_descendants += 1
        if level == "high":
            high_descendants += 1
        desc = dict(desc)
        desc["inherited_points"] = inherited_points
        branch_scores.append((inherited_points, desc))

    branch_scores.sort(key=lambda item: item[0], reverse=True)
    inherited_score = min(INHERITED_SCORE_CAP, sum(score for score, _desc in branch_scores[:3]))

    final_score = min(100, local.risk_score + inherited_score)
    malicious_gate_open = local.breakdown.malicious_gate_open
    high_gate_open = local.breakdown.high_gate_open

    direct_child_malicious = any(str(item[1]["risk_level"]) == "malicious" and int(item[1]["relative_depth"]) == 1 for item in branch_scores)
    any_nearby_high_or_malicious = any(str(item[1]["risk_level"]) in {"high", "malicious"} and int(item[1]["relative_depth"]) <= 2 for item in branch_scores)

    if direct_child_malicious:
        final_score = max(final_score, 60)
        high_gate_open = True

    if any_nearby_high_or_malicious:
        high_gate_open = True

    if malicious_descendants >= 2:
        malicious_gate_open = True
    elif direct_child_malicious and local.breakdown.local_score >= 20:
        malicious_gate_open = True

    if not malicious_gate_open:
        final_score = min(final_score, 84)

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
            "total_descendants": len(branch_scores),
            "malicious_descendants": malicious_descendants,
            "high_descendants": high_descendants,
            "top_descendants": [desc for _score, desc in branch_scores[:3]],
        },
        policy_version=local.policy_version,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && poetry run pytest tests/test_scoring_tree.py -v`

Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
git add backend/src/malscan/scoring/tree.py backend/tests/test_scoring_tree.py
git commit -m "feat(scoring): add tree-aware artifact rollup logic"
```

---

## Task 5: Extend artifact schema and persistence for risk metadata

**Files:**
- Create: `backend/alembic/versions/005_add_artifact_risk_fields.py`
- Modify: `backend/src/malscan/models/artifact.py`
- Modify: `backend/src/malscan/main.py`
- Modify: `worker/src/malscan_worker/db.py`
- Modify: `worker/tests/test_db_artifact_insert.py`
- Modify: `backend/tests/test_models.py`

- [ ] **Step 1: Write failing tests for new artifact fields**

Append to `backend/tests/test_models.py`:

```python
from malscan.models.artifact import Artifact


def test_artifact_model_includes_risk_level_and_policy_version_columns():
    assert "risk_level" in Artifact.__table__.c
    assert "policy_version" in Artifact.__table__.c
```

Append to `worker/tests/test_db_artifact_insert.py`:

```python
@pytest.mark.asyncio
async def test_update_artifact_risk_includes_risk_level_and_policy_version(monkeypatch):
    captured: dict = {}

    class DummySession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def execute(self, stmt, params):
            captured["params"] = params

        async def commit(self):
            return None

        async def rollback(self):
            return None

    monkeypatch.setattr(worker_db, "AsyncSession", DummySession)

    await worker_db.update_artifact_risk(
        artifact_id=str(uuid.uuid4()),
        verdict="suspicious",
        score=59,
        risk_level="medium",
        policy_version="msrs-v1",
    )

    assert captured["params"]["risk_level"] == "medium"
    assert captured["params"]["policy_version"] == "msrs-v1"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && poetry run pytest tests/test_models.py::test_artifact_model_includes_risk_level_and_policy_version_columns -v && cd ../worker && poetry run pytest tests/test_db_artifact_insert.py::test_update_artifact_risk_includes_risk_level_and_policy_version -v`

Expected: both tests fail because the columns and helper do not exist yet.

- [ ] **Step 3: Add Alembic migration**

Create `backend/alembic/versions/005_add_artifact_risk_fields.py`:

```python
"""Add artifact risk_level and policy_version fields.

Revision ID: 005_add_artifact_risk_fields
Revises: 004_add_artifacts_table
"""

from typing import Union

import sqlalchemy as sa

from alembic import op

revision: str = "005_add_artifact_risk_fields"
down_revision: Union[str, None] = "004_add_artifacts_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("artifacts", sa.Column("risk_level", sa.String(20), nullable=True))
    op.add_column("artifacts", sa.Column("policy_version", sa.String(20), nullable=True))


def downgrade() -> None:
    op.drop_column("artifacts", "policy_version")
    op.drop_column("artifacts", "risk_level")
```

- [ ] **Step 4: Update artifact model and startup schema repair**

Modify `backend/src/malscan/models/artifact.py` to add:

```python
    risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
```

Modify `backend/src/malscan/main.py` inside `_ensure_schema_compatibility()` to create missing columns if an environment starts without the new migration applied:

```python
    has_risk_level = (
        await conn.execute(
            text(
                """
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'artifacts'
                  AND column_name = 'risk_level'
                """
            )
        )
    ).scalar_one_or_none()
    if not has_risk_level:
        await conn.execute(text("ALTER TABLE artifacts ADD COLUMN risk_level VARCHAR(20)"))

    has_policy_version = (
        await conn.execute(
            text(
                """
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'artifacts'
                  AND column_name = 'policy_version'
                """
            )
        )
    ).scalar_one_or_none()
    if not has_policy_version:
        await conn.execute(text("ALTER TABLE artifacts ADD COLUMN policy_version VARCHAR(20)"))
```

- [ ] **Step 5: Replace artifact update helper with risk-aware version**

Modify `worker/src/malscan_worker/db.py`:

1. Update `create_artifact()` signature to accept `risk_level: str | None = None` and `policy_version: str | None = None`
2. Include both columns in the raw INSERT
3. Replace `update_artifact_verdict()` with:

```python
async def update_artifact_risk(
    artifact_id: str,
    verdict: str,
    score: int,
    risk_level: str,
    policy_version: str,
) -> None:
    """Update denormalized artifact risk fields."""
    from uuid import UUID as _UUID
    from sqlalchemy import text

    async with AsyncSession(_engine) as session:
        try:
            stmt = text(
                """
                UPDATE artifacts
                SET verdict = :verdict,
                    score = :score,
                    risk_level = :risk_level,
                    policy_version = :policy_version
                WHERE id = :id
                """
            )
            await session.execute(
                stmt,
                {
                    "id": _UUID(artifact_id),
                    "verdict": verdict,
                    "score": score,
                    "risk_level": risk_level,
                    "policy_version": policy_version,
                },
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd backend && poetry run pytest tests/test_models.py::test_artifact_model_includes_risk_level_and_policy_version_columns -v && cd ../worker && poetry run pytest tests/test_db_artifact_insert.py -v`

Expected: model field test passes and worker DB tests pass.

- [ ] **Step 7: Commit**

```bash
git add backend/alembic/versions/005_add_artifact_risk_fields.py backend/src/malscan/models/artifact.py backend/src/malscan/main.py backend/tests/test_models.py worker/src/malscan_worker/db.py worker/tests/test_db_artifact_insert.py
git commit -m "feat(scoring): persist artifact risk metadata"
```

---

## Task 6: Link artifact rows to created sub-jobs

**Files:**
- Modify: `worker/src/malscan_worker/utils/submission.py`
- Modify: `worker/tests/test_internal_job_submission.py`

- [ ] **Step 1: Write failing test for artifact-to-subjob linkage**

Append to `worker/tests/test_internal_job_submission.py`:

```python
@pytest.mark.asyncio
async def test_submit_subjob_updates_artifact_job_id_when_artifact_id_provided(monkeypatch):
    existing_file = None
    captured_updates: list[dict] = []

    class DummyScalarResult:
        def scalar_one_or_none(self):
            return existing_file

    class DummySession:
        def __init__(self, *args, **kwargs):
            self._adds = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def execute(self, stmt, *args, **kwargs):
            if kwargs:
                captured_updates.append(kwargs)
                return None
            return DummyScalarResult()

        def add(self, obj):
            self._adds.append(obj)

        async def flush(self):
            for obj in self._adds:
                if getattr(obj, "id", None) is None:
                    obj.id = uuid.uuid4()

        async def commit(self):
            return None

    monkeypatch.setattr("malscan_worker.utils.submission.AsyncSession", DummySession)
    monkeypatch.setattr("malscan_worker.utils.submission.upload_to_minio", AsyncMock())

    submitter = InternalJobSubmitter()
    submitter._ensure_connection = AsyncMock()
    submitter._exchange = SimpleNamespace(publish=AsyncMock())

    artifact_id = str(uuid.uuid4())
    sub_job_id = await submitter.submit_subjob(
        file_path="/tmp/sub.bin",
        filename="sub.bin",
        content_type="application/octet-stream",
        sha256_hash="d" * 64,
        file_size=12,
        parent_job_id=str(uuid.uuid4()),
        parent_job_depth=0,
        artifact_id=artifact_id,
    )

    assert sub_job_id is not None
    assert captured_updates
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worker && poetry run pytest tests/test_internal_job_submission.py::test_submit_subjob_updates_artifact_job_id_when_artifact_id_provided -v`

Expected: FAIL because no artifact update occurs.

- [ ] **Step 3: Update submitter to link artifact to created sub-job**

Modify `worker/src/malscan_worker/utils/submission.py` after `await db.commit()` for the sub-job creation path:

```python
            if artifact_id:
                await db.execute(
                    update(Job.__table__.metadata.tables["artifacts"])
                    .where(Job.__table__.metadata.tables["artifacts"].c.id == UUID(artifact_id))
                    .values(job_id=UUID(sub_job_id))
                )
                await db.commit()
```

Use a direct `artifacts` table update with SQLAlchemy `table()` / reflected table or a text statement if simpler; the important behavior is that the artifact row gains the created `job_id`.

Prefer a clear raw SQL statement in this file to avoid importing backend models into the worker submitter.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd worker && poetry run pytest tests/test_internal_job_submission.py -v`

Expected: all submitter tests pass.

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/utils/submission.py worker/tests/test_internal_job_submission.py
git commit -m "fix(artifacts): link artifact rows to created sub-jobs"
```

---

## Task 7: Integrate shared local scorer into worker pipeline result building

**Files:**
- Modify: `worker/src/malscan_worker/pipeline.py`
- Create: `worker/tests/test_pipeline_risk_scoring.py`
- Modify: `worker/tests/test_pipeline.py`
- Modify: `worker/tests/test_deobfuscation_pipeline_integration.py`

- [ ] **Step 1: Write failing worker pipeline risk tests**

Create `worker/tests/test_pipeline_risk_scoring.py`:

```python
"""Tests for worker-side local risk scoring integration in _build_analysis_result."""

from datetime import datetime, timezone

from malscan_worker.pipeline import _build_analysis_result
from malscan_worker.stages.base import StageResult


def _stage(stage_name: str, findings: dict) -> StageResult:
    now = datetime.now(timezone.utc)
    return StageResult(
        stage_name=stage_name,
        status="ok",
        started_at=now,
        ended_at=now,
        duration_ms=1,
        findings=findings,
        artifacts=[],
    )


def test_pipeline_builds_risk_block_and_legacy_fields_from_local_scorer():
    ctx = type("Ctx", (), {"sha256": "a" * 64, "original_filename": "sample.docm"})()
    report = _build_analysis_result(
        "job-1",
        "file-1",
        ctx,
        [
            _stage("file-type", {"mime_type": "application/vnd.ms-word", "file_size": 100}),
            _stage("clamav", {"infected": False, "threat_name": None}),
            _stage("yara", {"matches": []}),
            _stage("ioc-extract", {"urls": [], "domains": [], "ips": []}),
            _stage(
                "format-analysis",
                {
                    "analyzer": "office",
                    "format_type": "OOXML",
                    "risk_score": 45,
                    "risk_factors": ["macro_auto_exec"],
                    "indicators": [
                        {"type": "macro_auto_exec", "severity": "high", "detail": "AutoOpen + Shell"}
                    ],
                    "features": {},
                },
            ),
            _stage("deobfuscation", {"techniques_found": []}),
            _stage("sandbox", {"executed": False, "behaviors": [], "network_connections": [], "is_mock": True}),
        ],
        123,
    )

    assert report["score"] == report["risk"]["risk_score"]
    assert report["risk_level"] == "medium"
    assert report["verdict"] == "suspicious"
    assert report["risk"]["legacy_verdict"] == "suspicious"
    assert report["risk"]["policy_version"] == "msrs-v1"
    assert report["risk"]["evidence"]


def test_confirmed_clamav_hit_produces_malicious_local_risk():
    ctx = type("Ctx", (), {"sha256": "b" * 64, "original_filename": "payload.exe"})()
    report = _build_analysis_result(
        "job-2",
        "file-2",
        ctx,
        [
            _stage("file-type", {"mime_type": "application/octet-stream", "file_size": 100}),
            _stage("clamav", {"infected": True, "threat_name": "Win.Test.EICAR"}),
            _stage("yara", {"matches": []}),
            _stage("ioc-extract", {"urls": [], "domains": [], "ips": []}),
            _stage("format-analysis", {"indicators": [], "risk_score": 0, "risk_factors": [], "features": {}}),
            _stage("deobfuscation", {"techniques_found": []}),
            _stage("sandbox", {"executed": False, "behaviors": [], "network_connections": [], "is_mock": True}),
        ],
        123,
    )

    assert report["score"] == 95
    assert report["risk_level"] == "malicious"
    assert report["verdict"] == "malicious"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd worker && poetry run pytest tests/test_pipeline_risk_scoring.py -v`

Expected: FAIL because `_build_analysis_result()` does not expose the new `risk` block or `risk_level`.

- [ ] **Step 3: Replace inline scoring in `_build_analysis_result()` with shared local scorer**

Modify `worker/src/malscan_worker/pipeline.py`:

1. Import shared scoring adapters and engine:

```python
from malscan.scoring.adapters import build_direct_evidence
from malscan.scoring.engine import score_direct_evidence
```

2. Remove the current hand-written scoring branches for ClamAV/YARA/document-analysis/format-analysis/deobfuscation.

3. After `stage_findings` and IOC merge logic are built, compute local risk like this:

```python
    artifact_id = getattr(ctx, "artifact_id", None)
    direct_evidence = build_direct_evidence(artifact_id=artifact_id, stage_findings=stage_findings)
    decision = score_direct_evidence(direct_evidence=direct_evidence)
```

4. Update the returned report shape to include:

```python
        "verdict": decision.legacy_verdict,
        "score": decision.risk_score,
        "risk_level": decision.risk_level,
        "risk": {
            "policy_version": decision.policy_version,
            "risk_score": decision.risk_score,
            "risk_level": decision.risk_level,
            "legacy_verdict": decision.legacy_verdict,
            "malicious_gate_open": decision.breakdown.malicious_gate_open,
            "high_gate_open": decision.breakdown.high_gate_open,
            "independent_source_count": decision.breakdown.independent_source_count,
            "breakdown": {
                "local_score": decision.breakdown.local_score,
                "inherited_score": decision.breakdown.inherited_score,
                "synergy_bonus": decision.breakdown.synergy_bonus,
                "dampener": decision.breakdown.dampener,
                "final_score": decision.breakdown.final_score,
            },
            "evidence": [
                {
                    "source": ev.source,
                    "kind": ev.kind,
                    "tier": ev.tier,
                    "severity": ev.severity,
                    "points": ev.points,
                    "scope": ev.scope,
                    "depth": ev.depth,
                    "reason": ev.reason,
                    "raw": ev.raw,
                }
                for ev in decision.evidence
            ],
            "top_evidence": [
                {
                    "source": ev.source,
                    "kind": ev.kind,
                    "tier": ev.tier,
                    "severity": ev.severity,
                    "points": ev.points,
                    "scope": ev.scope,
                    "depth": ev.depth,
                    "reason": ev.reason,
                    "raw": ev.raw,
                }
                for ev in decision.top_evidence
            ],
            "descendant_summary": {},
        },
```

5. Keep the existing raw `results` sections intact.

6. Do **not** add descendant inheritance inside worker `_build_analysis_result()`.

- [ ] **Step 4: Update artifact risk persistence call in worker pipeline**

Replace the artifact update block in `worker/src/malscan_worker/pipeline.py`:

```python
                from malscan_worker.db import update_artifact_risk

                await update_artifact_risk(
                    artifact_id=job_data["artifact_id"],
                    verdict=analysis_result["verdict"],
                    score=analysis_result["score"],
                    risk_level=analysis_result["risk_level"],
                    policy_version=analysis_result["risk"]["policy_version"],
                )
```

- [ ] **Step 5: Update existing pipeline tests to the new report shape**

Modify `worker/tests/test_pipeline.py` assertions in `test_build_analysis_result_applies_format_scoring_and_reporting()`:

```python
    assert report["verdict"] == "suspicious"
    assert report["risk_level"] == "medium"
    assert report["score"] == 59
    assert report["risk"]["policy_version"] == "msrs-v1"
    assert report["risk"]["breakdown"]["local_score"] >= 0
```

Modify `worker/tests/test_deobfuscation_pipeline_integration.py` to replace old additive deobfuscation boost expectations with local-scoring expectations:

1. pure deob + raw IOC should stay `low`
2. deob + confirmed YARA should be `malicious`
3. no deob evidence should remain `clean`

Use exact expectations from the spec examples, not the old `+25 cap` behavior.

- [ ] **Step 6: Run worker scoring tests**

Run: `cd worker && poetry run pytest tests/test_pipeline_risk_scoring.py tests/test_pipeline.py tests/test_deobfuscation_pipeline_integration.py -v`

Expected: all selected tests pass.

- [ ] **Step 7: Commit**

```bash
git add worker/src/malscan_worker/pipeline.py worker/tests/test_pipeline_risk_scoring.py worker/tests/test_pipeline.py worker/tests/test_deobfuscation_pipeline_integration.py
git commit -m "feat(worker): integrate shared local risk scoring into pipeline reports"
```

---

## Task 8: Preserve unknown password-exhausted behavior while adding zero-risk block

**Files:**
- Modify: `worker/src/malscan_worker/reporting.py`
- Modify: `worker/tests/test_password_flow.py`

- [ ] **Step 1: Write failing test for zeroed risk block on unknown report**

Append to `worker/tests/test_password_flow.py` inside `test_consumer_wrong_password_exhausted_stores_report_sets_done_and_ack`:

```python
    assert saved_result["risk"]["risk_score"] == 0
    assert saved_result["risk"]["risk_level"] == "clean"
    assert saved_result["risk"]["legacy_verdict"] == "unknown"
    assert saved_result["risk"]["policy_version"] == "msrs-v1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worker && poetry run pytest tests/test_password_flow.py::test_consumer_wrong_password_exhausted_stores_report_sets_done_and_ack -v`

Expected: FAIL because `risk` is missing.

- [ ] **Step 3: Add zeroed `risk` block to exhausted-password report builder**

Modify `worker/src/malscan_worker/reporting.py` so `build_password_attempts_exhausted_report()` returns:

```python
        "risk_level": "clean",
        "risk": {
            "policy_version": "msrs-v1",
            "risk_score": 0,
            "risk_level": "clean",
            "legacy_verdict": "unknown",
            "malicious_gate_open": False,
            "high_gate_open": False,
            "independent_source_count": 0,
            "breakdown": {
                "local_score": 0,
                "inherited_score": 0,
                "synergy_bonus": 0,
                "dampener": 0,
                "final_score": 0,
            },
            "evidence": [],
            "top_evidence": [],
            "descendant_summary": {},
        },
```

Keep top-level `verdict` as `unknown`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd worker && poetry run pytest tests/test_password_flow.py::test_consumer_wrong_password_exhausted_stores_report_sets_done_and_ack -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/reporting.py worker/tests/test_password_flow.py
git commit -m "fix(reporting): add zeroed risk block to unknown password exhaustion report"
```

---

## Task 9: Expose tree-aware risk and artifact metadata in backend report API

**Files:**
- Modify: `backend/src/malscan/api/routes.py`
- Modify: `backend/src/malscan/schemas/requests.py`
- Modify: `backend/tests/test_api.py`

- [ ] **Step 1: Write failing backend API tests for `risk_level` and tree rollup**

Append to `backend/tests/test_api.py`:

```python
def test_get_report_returns_risk_level_and_risk_block(client: TestClient, mock_db_session: AsyncMock):
    job_id = uuid.uuid4()

    mock_job = MagicMock()
    mock_job.id = job_id
    mock_job.parent_job_id = None
    mock_job.status = JobStatus.DONE.value
    mock_job.sub_jobs = []
    mock_job.result = {
        "job_id": str(job_id),
        "file": {
            "file_id": "file-1",
            "sha256": "abc123",
            "mime": "application/octet-stream",
            "size": 10,
            "original_filename": "sample.bin",
        },
        "verdict": "suspicious",
        "score": 59,
        "risk_level": "medium",
        "risk": {
            "policy_version": "msrs-v1",
            "risk_score": 59,
            "risk_level": "medium",
            "legacy_verdict": "suspicious",
            "malicious_gate_open": False,
            "high_gate_open": False,
            "independent_source_count": 1,
            "breakdown": {
                "local_score": 59,
                "inherited_score": 0,
                "synergy_bonus": 0,
                "dampener": 0,
                "final_score": 59,
            },
            "evidence": [],
            "top_evidence": [],
            "descendant_summary": {},
        },
        "results": {
            "av_result": {"engine": "clamav", "infected": False, "threat_name": None},
            "yara_hits": [],
            "iocs": {"urls": [], "domains": [], "ips": [], "hashes": {"md5": "", "sha1": "", "sha256": "abc123"}},
            "sandbox": {"executed": False, "behaviors": [], "network_connections": [], "is_mock": True},
        },
        "timings": {"total_ms": 100, "stages": []},
    }
    mock_job.created_at.isoformat.return_value = "2023-01-01T00:00:00Z"

    mock_result = MagicMock()
    mock_result.unique.return_value.scalar_one_or_none.return_value = mock_job
    mock_pending_result = MagicMock()
    mock_pending_result.scalar.return_value = 0
    mock_tree_result = MagicMock()
    mock_tree_result.scalars.return_value.all.return_value = []
    mock_db_session.execute.side_effect = [mock_result, mock_pending_result, mock_tree_result]

    response = client.get(f"/api/v1/reports/{job_id}")

    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "medium"
    assert data["risk"]["risk_score"] == 59


def test_get_report_recomputes_tree_risk_when_artifact_tree_exists(client: TestClient, mock_db_session: AsyncMock, mocker):
    job_id = uuid.uuid4()

    mock_job = MagicMock()
    mock_job.id = job_id
    mock_job.parent_job_id = None
    mock_job.status = JobStatus.DONE.value
    mock_job.sub_jobs = []
    mock_job.result = {
        "job_id": str(job_id),
        "file": {
            "file_id": "file-1",
            "sha256": "abc123",
            "mime": "application/zip",
            "size": 10,
            "original_filename": "bundle.zip",
        },
        "verdict": "suspicious",
        "score": 5,
        "risk_level": "clean",
        "risk": {
            "policy_version": "msrs-v1",
            "risk_score": 5,
            "risk_level": "clean",
            "legacy_verdict": "clean",
            "malicious_gate_open": False,
            "high_gate_open": False,
            "independent_source_count": 0,
            "breakdown": {"local_score": 5, "inherited_score": 0, "synergy_bonus": 0, "dampener": 0, "final_score": 5},
            "evidence": [],
            "top_evidence": [],
            "descendant_summary": {},
        },
        "results": {
            "av_result": {"engine": "clamav", "infected": False, "threat_name": None},
            "yara_hits": [],
            "iocs": {"urls": [], "domains": [], "ips": [], "hashes": {"md5": "", "sha1": "", "sha256": "abc123"}},
            "sandbox": {"executed": False, "behaviors": [], "network_connections": [], "is_mock": True},
        },
        "timings": {"total_ms": 100, "stages": []},
    }
    mock_job.created_at.isoformat.return_value = "2023-01-01T00:00:00Z"

    mock_result = MagicMock()
    mock_result.unique.return_value.scalar_one_or_none.return_value = mock_job
    mock_pending_result = MagicMock()
    mock_pending_result.scalar.return_value = 0
    mock_tree_result = MagicMock()

    root_artifact = MagicMock()
    root_artifact.id = uuid.uuid4()
    root_artifact.parent_id = None
    root_artifact.original_filename = "bundle.zip"
    root_artifact.sha256 = "root"
    root_artifact.mime = "application/zip"
    root_artifact.size = 10
    root_artifact.depth = 0
    root_artifact.origin_path = None
    root_artifact.extraction_source = "archive-extract"
    root_artifact.archive_type = "zip"
    root_artifact.extraction_note = None
    root_artifact.verdict = "suspicious"
    root_artifact.score = 5
    root_artifact.job_id = job_id
    root_artifact.risk_level = "clean"

    child_artifact = MagicMock()
    child_artifact.id = uuid.uuid4()
    child_artifact.parent_id = root_artifact.id
    child_artifact.original_filename = "payload.exe"
    child_artifact.sha256 = "child"
    child_artifact.mime = "application/octet-stream"
    child_artifact.size = 20
    child_artifact.depth = 1
    child_artifact.origin_path = "payload.exe"
    child_artifact.extraction_source = "archive-extract"
    child_artifact.archive_type = None
    child_artifact.extraction_note = None
    child_artifact.verdict = "malicious"
    child_artifact.score = 95
    child_artifact.job_id = uuid.uuid4()
    child_artifact.risk_level = "malicious"

    mock_tree_result.scalars.return_value.all.return_value = [root_artifact, child_artifact]
    mock_db_session.execute.side_effect = [mock_result, mock_pending_result, mock_tree_result]

    response = client.get(f"/api/v1/reports/{job_id}")

    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "high"
    assert data["risk"]["breakdown"]["inherited_score"] == 35
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && poetry run pytest tests/test_api.py::test_get_report_returns_risk_level_and_risk_block tests/test_api.py::test_get_report_recomputes_tree_risk_when_artifact_tree_exists -v`

Expected: FAIL because `risk_level` is not yet in the response schema or tree rollup is not applied.

- [ ] **Step 3: Extend response schemas**

Modify `backend/src/malscan/schemas/requests.py`:

1. Add `RiskBreakdown`, `RiskEvidence`, `DescendantSummary`, and `RiskSummary` models
2. Add `risk_level: str | None = None` and `risk_level`/`policy_version` to `ArtifactTreeNode`
3. Extend `AnalysisResults` with optional `format_analysis` and `deobfuscation` fields so the existing stored report shape is modeled instead of silently dropped
4. Add `risk_level: str` and `risk: RiskSummary` to `ReportResponse`

Use this minimal schema shape:

```python
class RiskEvidence(BaseModel):
    source: str
    kind: str
    tier: str
    severity: str
    points: int
    scope: str
    depth: int
    reason: str
    raw: dict = {}


class RiskBreakdown(BaseModel):
    local_score: int
    inherited_score: int
    synergy_bonus: int
    dampener: int
    final_score: int


class RiskSummary(BaseModel):
    policy_version: str
    risk_score: int
    risk_level: str
    legacy_verdict: str
    malicious_gate_open: bool
    high_gate_open: bool
    independent_source_count: int
    breakdown: RiskBreakdown
    evidence: list[RiskEvidence]
    top_evidence: list[RiskEvidence]
    descendant_summary: dict = {}
```

- [ ] **Step 4: Recompute tree-aware risk in backend report route**

Modify `backend/src/malscan/api/routes.py`:

1. Import shared tree scorer:

```python
from malscan.scoring.models import RiskDecision, ScoreBreakdown
from malscan.scoring.tree import merge_with_descendants
```

2. Extend `_build_artifact_tree()` to include `risk_level` and `policy_version` on each node.

3. Add a helper `_apply_tree_risk_rollup(report: dict[str, Any], artifact_tree: dict | None) -> dict[str, Any]`:

```python
def _apply_tree_risk_rollup(report: dict[str, Any], artifact_tree: dict | None) -> dict[str, Any]:
    if not artifact_tree or "risk" not in report:
        return report

    local = RiskDecision(
        risk_score=int(report["risk"]["risk_score"]),
        risk_level=str(report["risk"]["risk_level"]),
        legacy_verdict=str(report["risk"]["legacy_verdict"]),
        evidence=[],
        top_evidence=[],
        breakdown=ScoreBreakdown(
            local_score=int(report["risk"]["breakdown"]["local_score"]),
            inherited_score=int(report["risk"]["breakdown"]["inherited_score"]),
            synergy_bonus=int(report["risk"]["breakdown"]["synergy_bonus"]),
            dampener=int(report["risk"]["breakdown"]["dampener"]),
            final_score=int(report["risk"]["breakdown"]["final_score"]),
            malicious_gate_open=bool(report["risk"].get("malicious_gate_open", False)),
            high_gate_open=bool(report["risk"].get("high_gate_open", False)),
            independent_source_count=int(report["risk"].get("independent_source_count", 0)),
        ),
        policy_version=str(report["risk"].get("policy_version", "msrs-v1")),
    )

    descendants: list[dict[str, Any]] = []

    def _collect(node: dict[str, Any], parent_depth: int = 0) -> None:
        for child in node.get("children", []):
            descendants.append(
                {
                    "artifact_id": child["id"],
                    "sha256": child["sha256"],
                    "relative_depth": max(1, int(child["depth"]) - int(node["depth"])),
                    "risk_level": child.get("risk_level") or "clean",
                    "risk_score": int(child.get("score") or 0),
                    "origin_path": child.get("origin_path"),
                }
            )
            _collect(child, parent_depth + 1)

    _collect(artifact_tree)
    final = merge_with_descendants(local=local, descendants=descendants)

    report["score"] = final.risk_score
    report["verdict"] = final.legacy_verdict
    report["risk_level"] = final.risk_level
    report["risk"]["risk_score"] = final.risk_score
    report["risk"]["risk_level"] = final.risk_level
    report["risk"]["legacy_verdict"] = final.legacy_verdict
    report["risk"]["malicious_gate_open"] = final.breakdown.malicious_gate_open
    report["risk"]["high_gate_open"] = final.breakdown.high_gate_open
    report["risk"]["breakdown"]["inherited_score"] = final.breakdown.inherited_score
    report["risk"]["breakdown"]["final_score"] = final.breakdown.final_score
    report["risk"]["descendant_summary"] = final.descendant_summary
    return report
```

4. In `get_report()`, after `report["artifact_tree"] = await _build_artifact_tree(...)`, call `_apply_tree_risk_rollup()` before returning.

Note: this route only runs after `_count_pending_descendants()` returns `0`, so this is the correct place to do canonical tree-aware rollup.

- [ ] **Step 5: Run backend API tests**

Run: `cd backend && poetry run pytest tests/test_api.py::test_get_report_success tests/test_api.py::test_get_report_returns_risk_level_and_risk_block tests/test_api.py::test_get_report_recomputes_tree_risk_when_artifact_tree_exists -v`

Expected: selected report tests pass.

- [ ] **Step 6: Commit**

```bash
git add backend/src/malscan/api/routes.py backend/src/malscan/schemas/requests.py backend/tests/test_api.py
git commit -m "feat(api): expose tree-aware risk scoring in report responses"
```

---

## Task 10: Propagate risk fields into artifact tree nodes and report contract

**Files:**
- Modify: `backend/src/malscan/api/routes.py`
- Modify: `backend/src/malscan/schemas/requests.py`

- [ ] **Step 1: Write failing assertion for artifact tree node risk metadata**

Append to `backend/tests/test_api.py::test_get_report_recomputes_tree_risk_when_artifact_tree_exists`:

```python
    child = data["artifact_tree"]["children"][0]
    assert child["risk_level"] == "malicious"
    assert child["score"] == 95
```

- [ ] **Step 2: Run test to verify it fails if field is missing**

Run: `cd backend && poetry run pytest tests/test_api.py::test_get_report_recomputes_tree_risk_when_artifact_tree_exists -v`

Expected: FAIL if `risk_level` is not included on tree nodes.

- [ ] **Step 3: Include `risk_level` and `policy_version` in artifact tree builder**

Modify `_build_artifact_tree()` node assembly in `backend/src/malscan/api/routes.py`:

```python
            "risk_level": art.risk_level,
            "policy_version": art.policy_version,
```

Modify `ArtifactTreeNode` schema to add:

```python
    risk_level: str | None = None
    policy_version: str | None = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && poetry run pytest tests/test_api.py::test_get_report_recomputes_tree_risk_when_artifact_tree_exists -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/src/malscan/api/routes.py backend/src/malscan/schemas/requests.py backend/tests/test_api.py
git commit -m "feat(api): include risk metadata on artifact tree nodes"
```

---

## Task 11: End-to-end worker and backend verification

**Files:**
- Modify: any files from previous tasks as needed

- [ ] **Step 1: Run worker test subset for scoring, pipeline, password, and artifact linkage**

Run: `cd worker && poetry run pytest tests/test_pipeline.py tests/test_pipeline_risk_scoring.py tests/test_deobfuscation_pipeline_integration.py tests/test_password_flow.py tests/test_db_artifact_insert.py tests/test_internal_job_submission.py -v`

Expected: all selected worker tests pass.

- [ ] **Step 2: Run backend test subset for scoring and report API**

Run: `cd backend && poetry run pytest tests/test_scoring_models.py tests/test_scoring_adapters.py tests/test_scoring_engine.py tests/test_scoring_tree.py tests/test_models.py tests/test_api.py -v`

Expected: all selected backend tests pass.

- [ ] **Step 3: Run Ruff on backend and worker changed files**

Run: `cd backend && poetry run ruff check src/malscan/scoring src/malscan/api/routes.py src/malscan/schemas/requests.py tests/test_scoring_models.py tests/test_scoring_adapters.py tests/test_scoring_engine.py tests/test_scoring_tree.py tests/test_api.py tests/test_models.py && cd ../worker && poetry run ruff check src/malscan_worker/pipeline.py src/malscan_worker/reporting.py src/malscan_worker/db.py src/malscan_worker/utils/submission.py src/malscan_worker/stages/yara_scan.py tests/test_pipeline.py tests/test_pipeline_risk_scoring.py tests/test_deobfuscation_pipeline_integration.py tests/test_password_flow.py tests/test_db_artifact_insert.py tests/test_internal_job_submission.py`

Expected: no lint errors.

- [ ] **Step 4: Run backend and worker formatters if Ruff reports fixable issues**

Run: `cd backend && poetry run ruff check --fix src/malscan/scoring src/malscan/api/routes.py src/malscan/schemas/requests.py tests/test_scoring_models.py tests/test_scoring_adapters.py tests/test_scoring_engine.py tests/test_scoring_tree.py tests/test_api.py tests/test_models.py && poetry run ruff format src/malscan/scoring src/malscan/api/routes.py src/malscan/schemas/requests.py tests/test_scoring_models.py tests/test_scoring_adapters.py tests/test_scoring_engine.py tests/test_scoring_tree.py tests/test_api.py tests/test_models.py && cd ../worker && poetry run ruff check --fix src/malscan_worker/pipeline.py src/malscan_worker/reporting.py src/malscan_worker/db.py src/malscan_worker/utils/submission.py src/malscan_worker/stages/yara_scan.py tests/test_pipeline.py tests/test_pipeline_risk_scoring.py tests/test_deobfuscation_pipeline_integration.py tests/test_password_flow.py tests/test_db_artifact_insert.py tests/test_internal_job_submission.py && poetry run ruff format src/malscan_worker/pipeline.py src/malscan_worker/reporting.py src/malscan_worker/db.py src/malscan_worker/utils/submission.py src/malscan_worker/stages/yara_scan.py tests/test_pipeline.py tests/test_pipeline_risk_scoring.py tests/test_deobfuscation_pipeline_integration.py tests/test_password_flow.py tests/test_db_artifact_insert.py tests/test_internal_job_submission.py`

Expected: formatting completes cleanly.

- [ ] **Step 5: Re-run both test subsets after any formatting changes**

Run: `cd worker && poetry run pytest tests/test_pipeline.py tests/test_pipeline_risk_scoring.py tests/test_deobfuscation_pipeline_integration.py tests/test_password_flow.py tests/test_db_artifact_insert.py tests/test_internal_job_submission.py -v && cd ../backend && poetry run pytest tests/test_scoring_models.py tests/test_scoring_adapters.py tests/test_scoring_engine.py tests/test_scoring_tree.py tests/test_models.py tests/test_api.py -v`

Expected: all selected tests still pass.

- [ ] **Step 6: Commit final integration adjustments**

```bash
git add backend/src/malscan/scoring backend/src/malscan/models/artifact.py backend/src/malscan/api/routes.py backend/src/malscan/schemas/requests.py backend/src/malscan/main.py backend/alembic/versions/005_add_artifact_risk_fields.py backend/tests/test_scoring_models.py backend/tests/test_scoring_adapters.py backend/tests/test_scoring_engine.py backend/tests/test_scoring_tree.py backend/tests/test_models.py backend/tests/test_api.py worker/src/malscan_worker/pipeline.py worker/src/malscan_worker/reporting.py worker/src/malscan_worker/db.py worker/src/malscan_worker/utils/submission.py worker/src/malscan_worker/stages/yara_scan.py worker/tests/test_pipeline.py worker/tests/test_pipeline_risk_scoring.py worker/tests/test_deobfuscation_pipeline_integration.py worker/tests/test_password_flow.py worker/tests/test_db_artifact_insert.py worker/tests/test_internal_job_submission.py
git commit -m "feat: add evidence-driven multi-signal risk scoring"
```

---

## Self-Review Checklist

### Spec coverage

Covered spec areas:

1. scoring schema and evidence model: Tasks 1-3
2. evidence weights, caps, gates, conflict rules: Tasks 2-4
3. parent-child inheritance and aggregation: Tasks 4, 9, 10
4. report output format: Tasks 7, 8, 9, 10
5. single weak-signal protection: Task 3
6. future analyzer extension path: Tasks 2 and 9 via shared adapters and API contract
7. dual-track compatibility with legacy verdict: Tasks 1, 3, 7, 8, 9
8. twelve-case policy alignment: Task 3 engine behavior + Task 4 tree behavior tests

### Placeholder scan

Checked for disallowed placeholders:

1. no placeholder markers remain in task steps
2. no deferred-work wording remains in task steps
4. every code-changing step includes concrete code or a concrete patch target
5. every verification step includes an exact command

### Type consistency

Key names used consistently through the plan:

1. `risk_score`
2. `risk_level`
3. `legacy_verdict`
4. `policy_version`
5. `EvidenceRecord`
6. `RiskDecision`
7. `ScoreBreakdown`
8. `score_direct_evidence`
9. `merge_with_descendants`
10. `update_artifact_risk`

---

Plan complete and saved to `docs/superpowers/plans/2026-04-09-multi-signal-risk-scoring-system.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
