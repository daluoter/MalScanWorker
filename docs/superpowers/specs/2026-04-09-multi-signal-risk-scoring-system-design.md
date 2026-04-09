# Multi-Signal Risk Scoring System Design

**Date:** 2026-04-09
**Status:** Draft
**Approach:** Hybrid Policy Engine (Approach C)

## 1. Problem Statement

The current `worker/src/malscan_worker/pipeline.py` computes a final `verdict` and `score` with stage-specific `if/else` blocks. That logic was adequate for early single-file static scanning, but it is now too thin for the current and planned MalScanWorker pipeline.

The main problems are:

1. **Flat verdict logic** -- the system still collapses many signals into a coarse `clean / suspicious / malicious` outcome with limited explanation.
2. **Uneven signal treatment** -- ClamAV, YARA, document analysis, deobfuscation, IOC extraction, and format analysis all contribute differently, but the scoring logic is not normalized.
3. **Weak support for artifact trees** -- extracted child artifacts already exist, and artifact rows already store `score` and `verdict`, but there is no formal inheritance policy from descendant findings back to parents.
4. **Weak-signal inflation risk** -- several low-confidence heuristics can accumulate without a clear policy for capping their effect or requiring corroboration.
5. **Poor extensibility** -- future analyzers such as sandbox integrations or new format analyzers would require more hand-written scoring branches inside `pipeline.py`.
6. **Limited explainability** -- reports expose raw stage findings, but they do not provide a normalized evidence list that explains exactly why the final score was assigned.

## 2. Goals

1. Produce a final `risk_score` from `0-100` for every scanned artifact.
2. Produce a final `risk_level` with five buckets: `clean / low / medium / high / malicious`.
3. Preserve backward compatibility by keeping the existing top-level `verdict` field as a legacy mapping.
4. Normalize heterogeneous stage outputs into a common evidence model.
5. Support parent-child artifact inheritance with depth-aware weighting.
6. Ensure a single weak signal cannot escalate a sample to `malicious`.
7. Provide a clear, compact, evidence-driven report format for analysts and downstream systems.
8. Allow future analyzers to plug into the framework without modifying the core policy engine.

## 3. Non-Goals

1. This design does **not** introduce machine learning or probabilistic models.
2. This design does **not** replace raw stage findings; those remain in the report under `results`.
3. This design does **not** attempt to perfectly classify file intent from one signal source alone.
4. This design does **not** require a threat-intel platform in v1; IOC reputation enrichment is optional and additive.

## 4. Current-State Constraints

The design must fit the current codebase and data flow:

1. `pipeline.py` already computes a top-level `score` and `verdict` and writes the full report JSON with `update_job_result()`.
2. `format-analysis` already emits `risk_score`, `risk_factors`, `indicators`, and `features`.
3. `create_artifact()` and `update_artifact_verdict()` already denormalize `score` and `verdict` to artifact rows.
4. The artifact tree model already records `parent_id`, `root_id`, `depth`, and extracted provenance.
5. `SandboxStage` is currently a mock, so the framework must define a clean future contract for dynamic evidence without depending on a real sandbox yet.

## 5. Compatibility Strategy

### 5.1 Dual-Track Output

The new framework introduces:

1. `risk_score`: integer `0-100`
2. `risk_level`: `clean | low | medium | high | malicious`
3. `verdict`: legacy compatibility field

Legacy mapping:

| New `risk_level` | Legacy `verdict` |
|---|---|
| `clean` | `clean` |
| `low` | `suspicious` |
| `medium` | `suspicious` |
| `high` | `suspicious` |
| `malicious` | `malicious` |

This preserves the existing external contract while letting the frontend and downstream services adopt the more expressive risk model incrementally.

### 5.2 Database Compatibility

The current `artifacts` table stores only `score` and `verdict` as denormalized fields. To support the new system cleanly, the recommended schema extension is:

```sql
ALTER TABLE artifacts ADD COLUMN risk_level VARCHAR(20);
ALTER TABLE artifacts ADD COLUMN policy_version VARCHAR(20);
```

Recommended interpretation:

1. `score` stores the new `risk_score`
2. `verdict` stores the legacy compatibility verdict
3. `risk_level` stores the five-level classification
4. `policy_version` stores the scoring policy version, for replay and calibration

## 6. Approaches Considered

### Approach A: Rule-Based Bands

Every signal directly sets the final score or verdict through explicit rules.

Example:

1. `ClamAV hit -> 95 / malicious`
2. `YARA hit -> 60+ / suspicious`
3. `packed binary -> 25 / suspicious`

Pros:

1. Highest transparency
2. Easy to debug
3. Minimal code to start

Cons:

1. Does not scale well as signal count grows
2. Hard to model cross-signal corroboration
3. Tends to become a large brittle ladder of conditionals

### Approach B: Pure Weighted Evidence

Every signal contributes weighted points. Final outcome is a score threshold lookup.

Pros:

1. Uniform and extensible
2. Easy to add new analyzers
3. Naturally evidence-driven

Cons:

1. Many weak signals can accidentally sum to a high score
2. Harder to express policy constraints such as “cannot be malicious without confirmation”
3. Requires more careful calibration and caps

### Approach C: Hybrid Policy Engine (Recommended)

Use weighted evidence as the base layer, then apply explicit policy gates, caps, and inheritance rules before resolving the final level.

Pros:

1. Preserves evidence-driven scoring
2. Prevents weak-signal inflation
3. Cleanly supports parent-child inheritance
4. Gives future analyzers a stable adapter contract

Cons:

1. Slightly more complex than pure rules
2. Requires a dedicated normalization layer

## 7. Recommended Architecture

### 7.1 Overview

```
Pipeline stages -> raw stage findings
                -> evidence normalizers/adapters
                -> artifact-local scoring
                -> artifact-tree aggregation
                -> policy resolution
                -> report rendering + artifact/job persistence
```

### 7.2 Components

#### A. Evidence Normalizers

Each stage keeps its native output, but an adapter converts it into normalized evidence records.

Example adapters:

1. `ClamAVEvidenceAdapter`
2. `YaraEvidenceAdapter`
3. `IocEvidenceAdapter`
4. `FormatAnalysisEvidenceAdapter`
5. `DeobfuscationEvidenceAdapter`
6. `SandboxEvidenceAdapter`
7. `ArtifactTreeEvidenceAdapter`

#### B. Local Risk Scorer

Computes the score for the current artifact from direct evidence only.

Outputs:

1. `local_score`
2. `local_level`
3. `score_breakdown`
4. `top_evidence`
5. `policy_flags`

#### C. Tree Aggregator

Applies descendant inheritance with depth decay, branch caps, and malicious-gate rules.

Outputs:

1. `inherited_score`
2. `descendant_summary`
3. `tree_gate_flags`

#### D. Policy Resolver

Combines local and inherited evidence, then applies:

1. malicious eligibility rules
2. weak-signal caps
3. conflict dampening
4. final threshold mapping

#### E. Report Builder

Builds the final dual-track report with:

1. raw stage outputs under `results`
2. normalized evidence under `risk.evidence`
3. score breakdown under `risk.breakdown`
4. compatibility fields at the top level

## 8. Normalized Evidence Schema

### 8.1 Evidence Record

Each normalized signal becomes an `EvidenceRecord`.

```python
@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    source: str                    # clamav, yara, ioc, format-analysis, deobfuscation, sandbox, tree
    kind: str                      # confirmed_malware_signature, malicious_family_yara, packed_binary, etc.
    tier: str                      # confirmed, strong, medium, weak, benign_context
    severity: str                  # info, low, medium, high, critical
    confidence: float              # 0.0 - 1.0
    points: int                    # pre-cap base points
    cap_group: str                 # signature, yara, ioc_raw, ioc_intel, format_structural, deob, dynamic, tree
    scope: str                     # direct, descendant, contextual
    artifact_id: str | None
    related_artifact_id: str | None
    depth: int
    reason: str
    tags: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)
```

### 8.2 Required Design Rules

1. Stages do **not** assign final verdicts.
2. Stages do **not** assign final risk levels.
3. Stages may still emit stage-local `risk_score` or `risk_factors` for debugging, but the policy engine treats them as inputs, not the final answer.
4. New analyzers must emit structured indicators that can be normalized into `EvidenceRecord` objects.

## 9. Evidence Tiers

Signals are grouped by how much trust the scorer should place in them.

### 9.1 Tier Definitions

| Tier | Meaning | Typical examples |
|---|---|---|
| `confirmed` | High-confidence malicious confirmation | ClamAV malware signature, sandbox process injection + C2, curated YARA malware-family rule |
| `strong` | Strong suspicious evidence with clear malicious intent | exploit indicators, downloader execution chains, threat-intel IOC hit |
| `medium` | Suspicious but not fully dispositive | auto-exec macros, suspicious PE imports, malicious script patterns |
| `weak` | Heuristic or noisy support signal | packed file, entropy anomaly, raw IOC extraction, deobfuscation technique found |
| `benign_context` | Context that reduces confidence in weak heuristics | trusted signer, internal-only IOC, allowlisted hash |

### 9.2 Tier Principles

1. A single `weak` signal cannot raise a file above `low`.
2. Multiple `weak` signals from the same source family cannot raise a file above `medium`.
3. `malicious` requires at least one `confirmed` signal or multi-source corroboration defined by policy gates.
4. `benign_context` does not directly produce negative risk points. It dampens or caps weaker evidence.

## 10. Concrete Scoring Policy

### 10.1 Final Level Thresholds

| Score range | `risk_level` | Legacy `verdict` |
|---|---|---|
| `0-9` | `clean` | `clean` |
| `10-29` | `low` | `suspicious` |
| `30-59` | `medium` | `suspicious` |
| `60-84` | `high` | `suspicious` |
| `85-100` | `malicious` | `malicious` |

### 10.2 Base Signal Weights

#### ClamAV

| Evidence kind | Points | Tier | Notes |
|---|---:|---|---|
| `confirmed_malware_signature` | 95 | confirmed | Opens malicious gate immediately |
| `suspicious_signature` | 70 | strong | For generic or non-family detections if such metadata exists later |

Rationale: ClamAV signature hits are usually the highest-precision signal in the current pipeline.

#### YARA

YARA rules must eventually carry metadata so the scorer can classify them reliably.

Recommended metadata:

```text
classification = malicious_family | exploit | suspicious | generic
confidence = high | medium | low
```

| Evidence kind | Points | Tier | Notes |
|---|---:|---|---|
| `yara_malicious_family` | 85 | confirmed | Curated malware family / payload rules |
| `yara_exploit_rule` | 75 | strong | Exploit chain or shellcode rule |
| `yara_suspicious_behavior` | 55 | strong | Downloader, credential theft, stager pattern |
| `yara_generic_heuristic` | 25 | weak | Generic strings or noisy indicators |

Additional YARA policy:

1. Additional distinct `yara_malicious_family` matches add `+5` each, capped at `+10`.
2. Multiple `generic_heuristic` rules cap at `35` total from the generic YARA family.
3. YARA evidence from deobfuscated content carries normal points; no separate discount is applied.

#### IOC Extraction

Raw IOC extraction is intentionally weak without enrichment.

| Evidence kind | Points | Tier | Cap |
|---|---:|---|---:|
| `raw_url_ioc` | 3 | weak | 12 |
| `raw_domain_ioc` | 3 | weak | 12 |
| `raw_ip_ioc` | 4 | weak | 12 |
| `ioc_multiple_types_bonus` | 5 | weak | 5 |
| `intel_malicious_ioc` | 35 | strong | 45 |
| `intel_suspicious_ioc` | 20 | medium | 30 |

IOC policy:

1. Raw IOC extraction without reputation cannot exceed `15` total.
2. Reputation or blocklist matches are treated as separate enriched evidence, not as raw IOC inflation.
3. If all IOCs are internal/private/allowlisted, raw IOC evidence is capped at `5`.

#### Format-Specific Analyzer

The new scorer uses structured analyzer indicators as the primary signal. Existing analyzer `risk_score` becomes supporting context only.

| Evidence kind | Points | Tier | Notes |
|---|---:|---|---|
| `format_execution_or_exploit_critical` | 70 | strong | Equation Editor exploit, direct execution primitive |
| `format_execution_or_exploit_high` | 50 | strong | launch action, dangerous external template, shellcode indicator |
| `format_loader_or_dropper_pattern` | 35 | medium | auto-exec macro + suspicious APIs, embedded executable, suspicious script launcher |
| `format_structural_anomaly_medium` | 20 | medium | suspicious resource, malicious PDF object graph, malformed object chain |
| `format_structural_anomaly_low` | 8 | weak | packer, high entropy section, extension mismatch |
| `format_risk_score_support` | 0-15 | weak | Fallback support only, derived from analyzer `risk_score` if structured indicators are sparse |

Analyzer support score mapping:

```text
support_points = min(15, floor(risk_score / 4))
```

Use the support score only when the analyzer emitted fewer than two explicit indicators. This avoids double-counting.

#### Deobfuscation

Deobfuscation is suspicious, but not dispositive.

| Evidence kind | Points | Tier | Cap |
|---|---:|---|---:|
| `deobfuscation_technique_found` | 4 each | weak | 12 |
| `deobfuscated_payload_networking` | 10 | medium | 20 |
| `deobfuscated_payload_execution` | 12 | medium | 20 |
| `hidden_content_revealed_bonus` | 5 | medium | 5 |

Deobfuscation policy:

1. Pure obfuscation evidence alone cannot exceed `20`.
2. The real risk impact should come from what downstream stages find in the decoded content.
3. If deobfuscation reveals content that later triggers YARA or IOC enrichment, those downstream hits carry the real weight.

#### Dynamic Analysis

Dynamic analysis is not fully implemented yet, but the policy contract should be stable now.

| Evidence kind | Points | Tier | Notes |
|---|---:|---|---|
| `sandbox_confirmed_malicious_behavior` | 95 | confirmed | process injection, ransomware behavior, credential theft, confirmed C2 |
| `sandbox_strong_malicious_chain` | 80 | confirmed | download-execute-persist, defense evasion, multi-step malware chain |
| `sandbox_suspicious_behavior_combo` | 65 | strong | child process + network beacon + autorun/persistence |
| `sandbox_single_suspicious_behavior` | 20 | weak | one noisy behavior alone |

#### Artifact Ancestry / Tree Inheritance

Descendant findings are not treated as direct evidence. They use a separate inheritance policy.

Base inherited points by descendant level:

| Descendant level | Base inherited points |
|---|---:|
| `malicious` | 35 |
| `high` | 25 |
| `medium` | 15 |
| `low` | 6 |

Depth decay:

| Relative depth | Multiplier |
|---|---:|
| `1` | `1.00` |
| `2` | `0.70` |
| `3` | `0.50` |
| `4+` | `0.35` |

Inherited score per descendant:

```text
inherited_points = floor(base_points * depth_multiplier)
```

Tree aggregation rules:

1. Sum only the top `3` descendant branch contributions.
2. Cap total inherited score at `40`.
3. Multiple descendants with the same `sha256` only contribute once.
4. Descendant evidence should carry its own explanation, including depth and origin path.

#### Structural Heuristics

These signals are intentionally weak unless corroborated.

| Evidence kind | Points | Tier | Cap |
|---|---:|---|---:|
| `packed_binary` | 12 | weak | 15 |
| `high_entropy_section` | 8 | weak | 12 |
| `suspicious_extension_mismatch` | 8 | weak | 10 |
| `malformed_container_structure` | 10 | weak | 15 |
| `polyglot_or_overlay_anomaly` | 15 | weak | 20 |

### 10.3 Synergy Bonuses

Weighted evidence alone is not enough. Certain combinations should raise confidence because they represent malicious intent from independent sources.

| Combination | Bonus |
|---|---:|
| `deobfuscated_payload_execution` + `yara_*` or `intel_malicious_ioc` | 8 |
| `macro_auto_exec` + `network_ioc` | 8 |
| `format_execution_or_exploit_*` + `descendant malicious/high` | 10 |
| `two independent strong sources` | 10 |
| `one confirmed source` + `one additional medium/strong source` | 5 |

Synergy rules:

1. A synergy bonus can only be added when the contributing signals come from different source families.
2. Total synergy is capped at `15`.

### 10.4 Dampeners and Conflict Resolution

Normal-looking context should not generate negative scores, but it should limit heuristic overreaction.

Supported benign-context evidence kinds:

1. `allowlisted_hash`
2. `trusted_signer`
3. `internal_only_iocs`
4. `known_benign_packer`
5. `expected_embedded_content`

Conflict-resolution rules:

1. `confirmed` malicious evidence beats all benign-context evidence unless the sample is explicitly allowlisted by exact hash.
2. `allowlisted_hash` suppresses all weak and medium heuristic evidence, but does **not** suppress confirmed malware signatures or confirmed sandbox behavior.
3. `trusted_signer` reduces weak structural evidence by `50%` and caps heuristic-only files at `medium`.
4. `internal_only_iocs` caps raw IOC evidence at `5`.
5. `expected_embedded_content` can suppress inherited `low` contributions from benign child files, but never suppresses malicious descendant evidence.

Priority order when evidence conflicts:

```text
confirmed dynamic/signature evidence
> curated malicious-family YARA
> strong exploit/execution evidence
> threat-intel IOC evidence
> structural heuristics and raw IOC extraction
```

### 10.5 Hard Caps to Prevent Weak-Signal Inflation

The following caps are mandatory:

1. **Weak-only cap:** if all evidence is `weak`, final score is capped at `29`.
2. **Single-source weak/medium cap:** if all evidence comes from one source family and there is no confirmed evidence, final score is capped at `59`.
3. **No-malicious-gate cap:** if malicious-gate conditions are not met, final score is capped at `84`.
4. **Raw IOC cap:** raw IOC extraction without enrichment is capped at `15`.
5. **Pure deobfuscation cap:** deobfuscation without corroborating downstream evidence is capped at `20`.

### 10.6 Malicious Gate Rules

A sample is eligible for `risk_level = malicious` only if **at least one** of these conditions is true:

1. At least one `confirmed` evidence record exists.
2. Two independent `strong` evidence sources exist and the total score is at least `85`.
3. One `strong` source and at least two additional independent `medium` or higher sources exist, and the total score is at least `85`.
4. Tree gate opens because:
   - there is at least one `malicious` descendant at depth `1-2` **and** local score is at least `20`, or
   - there are at least two `malicious` descendants on separate branches.

If none of these conditions are met, the sample cannot exceed `high` even if the raw weighted score crosses `85`.

### 10.7 Minimum High-Risk Gate

To reach `high`, at least one of the following must be true:

1. One `strong` or `confirmed` signal exists.
2. Two independent `medium` sources exist.
3. One `malicious` or `high` descendant exists at depth `1-2`.

Without one of these conditions, the final score is capped at `59`.

## 11. Artifact Tree Aggregation Policy

### 11.1 Why Tree Aggregation Is Separate

Parents such as archives, OOXML documents, PDFs with embedded files, and containers are often dangerous because of what they carry, not because their own bytes alone are overtly malicious. The scoring system therefore needs a formal descendant inheritance rule.

### 11.2 Per-Artifact Flow

For each artifact node:

1. Score direct evidence only.
2. Score all children recursively.
3. Compute descendant contributions with depth decay.
4. Apply tree gate rules.
5. Resolve final `risk_score` and `risk_level`.

### 11.3 Branch-Aware Rollup

Use branch-aware aggregation instead of simple `max(child_score)`:

```text
inherited_score = min(40, sum(top_three_branch_contributions))
combined_score = min(100, local_score + inherited_score + synergy - dampeners)
```

Why not simple max?

1. It loses the fact that two dangerous descendants are worse than one.
2. It overreacts to a single deep descendant when the parent context is otherwise weak.

### 11.4 Parent Promotion Rules

1. A direct child with `malicious` level sets the parent minimum to `high`.
2. A direct child with `malicious` level can escalate the parent to `malicious` only when the parent also has at least `20` local score or there are multiple malicious descendants.
3. A single malicious descendant at depth `3+` without local corroboration can raise the parent to at most `high`.
4. Multiple `medium` descendants can raise a parent to `high`, but not `malicious`, unless the malicious gate opens.

### 11.5 Duplicate and Loop Handling

1. Duplicate descendants with the same `sha256` contribute once per root tree.
2. Cycles already prevented by `ancestor_hashes` should produce no inherited contribution.
3. Descendants marked `skipped` or `duplicate_within_extraction` do not contribute risk.

## 12. Report Format

### 12.1 Top-Level JSON

Recommended top-level shape:

```python
{
    "job_id": "...",
    "file": {...},
    "verdict": "suspicious",            # legacy
    "score": 78,                         # legacy-compatible alias of risk_score
    "risk_level": "high",
    "risk": {
        "policy_version": "msrs-v1",
        "risk_score": 78,
        "risk_level": "high",
        "legacy_verdict": "suspicious",
        "malicious_gate_open": False,
        "high_gate_open": True,
        "independent_source_count": 3,
        "breakdown": {
            "local_score": 56,
            "inherited_score": 15,
            "synergy_bonus": 8,
            "dampener": 1,
            "final_score": 78,
        },
        "evidence": [...],
        "top_evidence": [...],
        "descendant_summary": {...},
    },
    "results": {...},                    # raw stage outputs preserved
    "timings": {...},
}
```

### 12.2 Evidence Rendering

Each report should expose the evidence list in priority order, with the most decision-relevant items first.

Recommended evidence item shape:

```python
{
    "source": "format-analysis",
    "kind": "format_loader_or_dropper_pattern",
    "tier": "medium",
    "severity": "high",
    "points": 35,
    "scope": "direct",
    "depth": 0,
    "reason": "OOXML macro auto-exec with suspicious API keywords",
    "raw": {
        "keywords": ["AutoOpen", "Shell", "URLDownloadToFileA"],
    },
}
```

### 12.3 Descendant Summary

Recommended summary block:

```python
{
    "descendant_summary": {
        "total_descendants": 7,
        "malicious_descendants": 1,
        "high_descendants": 2,
        "max_descendant_depth": 3,
        "top_descendants": [
            {
                "artifact_id": "...",
                "risk_level": "malicious",
                "risk_score": 96,
                "relative_depth": 1,
                "origin_path": "archive/loader.exe",
                "inherited_points": 35,
            }
        ],
    }
}
```

## 13. Integration Plan for Current Pipeline

### 13.1 Replace Final Verdict Logic in `pipeline.py`

Current `_build_analysis_result()` contains hard-coded verdict logic. Replace that logic with:

1. Collect `stage_findings`
2. Build evidence via adapter functions
3. Call the scorer
4. Attach `risk_level`, `risk`, and compatibility `verdict`
5. Preserve existing `results` payloads

### 13.2 Artifact Persistence Changes

Recommended DB layer changes:

1. Rename `update_artifact_verdict()` to `update_artifact_risk()`
2. Persist:
   - `score` = new `risk_score`
   - `verdict` = legacy verdict
   - `risk_level`
   - `policy_version`

### 13.3 Stage Contracts

No stage should call the scorer directly. The scorer belongs to the pipeline/reporting layer.

Benefits:

1. Stages remain focused on extraction and analysis
2. Policy stays centralized
3. Future recalibration does not require analyzer rewrites

## 14. Future Analyzer Extension Contract

### 14.1 Rules for New Analyzers

Any new analyzer must follow these rules:

1. Emit raw findings in its native format for debugging.
2. Emit structured indicators that can be normalized into `EvidenceRecord` objects.
3. Never assign final `verdict`, `risk_level`, or top-level `score`.
4. Include enough metadata for calibration:
   - `kind`
   - `severity`
   - `detail`
   - optional `confidence`

### 14.2 Unknown Evidence Safety Valve

If a new analyzer emits an unknown evidence kind before the policy is updated:

1. Normalize it to `tier = weak`
2. Assign conservative default points such as `5`
3. Mark the report with `policy_note = "unknown_evidence_kind_defaulted"`

This prevents new analyzers from silently over-inflating risk.

### 14.3 Policy Versioning

The report must carry `policy_version`, such as `msrs-v1`. This enables:

1. replay and backtesting
2. A/B comparison during calibration
3. safe migration when weights change

## 15. Python Skeleton

Recommended new package:

```text
worker/src/malscan_worker/scoring/
  __init__.py
  models.py
  policy.py
  engine.py
  adapters.py
  tree.py
```

The code below is intentionally a **policy skeleton**, not a production-complete implementation. It shows the main control flow and data model, but omits some details for brevity, including:

1. per-`cap_group` enforcement
2. allowlist suppression precedence
3. direct-child promotion floors
4. duplicate-descendant collapse by `sha256`
5. report rendering helpers and adapter registration

### 15.1 Models

```python
from __future__ import annotations

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

### 15.2 Policy

```python
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
```

### 15.3 Engine

```python
from collections import defaultdict
from math import floor


def resolve_risk_level(score: int) -> str:
    for level, (low, high) in LEVEL_THRESHOLDS.items():
        if low <= score <= high:
            return level
    return "malicious"


def apply_depth_decay(points: int, depth: int) -> int:
    multiplier = DEPTH_DECAY.get(depth, 0.35)
    return floor(points * multiplier)


def score_artifact(
    direct_evidence: list[EvidenceRecord],
    descendant_levels: list[tuple[str, int, str]],
    benign_context: list[EvidenceRecord],
) -> RiskDecision:
    cap_totals: dict[str, int] = defaultdict(int)
    local_score = 0
    inherited_score = 0
    synergy_bonus = 0
    dampener = 0

    strong_sources: set[str] = set()
    medium_sources: set[str] = set()
    confirmed_present = False
    weak_only = True

    ordered = sorted(direct_evidence, key=lambda ev: ev.points, reverse=True)

    for ev in ordered:
        effective_points = ev.points
        if ev.tier == "benign_context":
            continue
        if ev.tier != "weak":
            weak_only = False
        if ev.tier == "confirmed":
            confirmed_present = True
        if ev.tier in {"confirmed", "strong"}:
            strong_sources.add(ev.source)
        elif ev.tier == "medium":
            medium_sources.add(ev.source)

        cap_totals[ev.cap_group] += effective_points
        local_score += effective_points

    branch_scores: list[int] = []
    malicious_descendants = 0
    for level, relative_depth, _origin_path in descendant_levels:
        base = INHERITANCE_BASE[level]
        if level == "malicious":
            malicious_descendants += 1
        if base <= 0:
            continue
        branch_scores.append(apply_depth_decay(base, relative_depth))

    inherited_score = min(40, sum(sorted(branch_scores, reverse=True)[:3]))

    if len(strong_sources) >= 2:
        synergy_bonus += 10
    elif confirmed_present and (strong_sources or medium_sources):
        synergy_bonus += 5

    if any(ev.kind.startswith("deobfuscated_payload") for ev in direct_evidence) and any(
        ev.source in {"yara", "ioc", "sandbox"} for ev in direct_evidence
    ):
        synergy_bonus += 8

    if any(ev.kind == "trusted_signer" for ev in benign_context):
        dampener += 5
    if any(ev.kind == "internal_only_iocs" for ev in benign_context):
        dampener += 3

    score = max(0, min(100, local_score + inherited_score + min(synergy_bonus, 15) - dampener))

    malicious_gate_open = False
    if confirmed_present:
        malicious_gate_open = True
    elif len(strong_sources) >= 2 and score >= 85:
        malicious_gate_open = True
    elif len(strong_sources) >= 1 and len(medium_sources) >= 2 and score >= 85:
        malicious_gate_open = True
    elif malicious_descendants >= 2:
        malicious_gate_open = True

    high_gate_open = bool(strong_sources or confirmed_present or len(medium_sources) >= 2 or inherited_score >= 25)

    if weak_only:
        score = min(score, 29)
    if not high_gate_open:
        score = min(score, 59)
    if not malicious_gate_open:
        score = min(score, 84)

    level = resolve_risk_level(score)
    legacy_verdict = LEGACY_VERDICT_MAP[level]

    breakdown = ScoreBreakdown(
        local_score=local_score,
        inherited_score=inherited_score,
        synergy_bonus=min(synergy_bonus, 15),
        dampener=dampener,
        final_score=score,
        malicious_gate_open=malicious_gate_open,
        high_gate_open=high_gate_open,
    )

    return RiskDecision(
        risk_score=score,
        risk_level=level,
        legacy_verdict=legacy_verdict,
        evidence=ordered,
        top_evidence=ordered[:10],
        breakdown=breakdown,
    )
```

## 16. Twelve Worked Examples

These examples show how the framework should behave on realistic inputs.

### Case 1: Clean PDF brochure

Signals:

1. No ClamAV hit
2. No YARA hit
3. No suspicious PDF indicators
4. No IOCs

Scoring:

1. direct = `0`
2. inherited = `0`
3. final = `0`

Result:

1. `risk_score = 0`
2. `risk_level = clean`
3. `verdict = clean`

### Case 2: Invoice DOCM with auto-exec macro and suspicious APIs

Signals:

1. `macro_auto_exec + suspicious keywords` -> `format_loader_or_dropper_pattern = 35`
2. `format_risk_score_support = 10`

Scoring:

1. local = `45`
2. inherited = `0`
3. no malicious gate
4. final = `45`

Result:

1. `risk_score = 45`
2. `risk_level = medium`
3. `verdict = suspicious`

### Case 3: Obfuscated JavaScript downloader

Signals:

1. two deobfuscation techniques -> `8`
2. deobfuscated payload contains downloader execution string -> `12`
3. raw URL IOC -> `3`
4. script analyzer suspicious downloader pattern -> `35`
5. synergy `deobfuscated payload + IOC/script evidence` -> `8`

Scoring:

1. local = `58`
2. synergy = `8`
3. final = `66`

Result:

1. `risk_score = 66`
2. `risk_level = high`
3. `verdict = suspicious`

### Case 4: Packed PE with suspicious imports but no signature hits

Signals:

1. suspicious imports -> `20`
2. packed binary -> `12`
3. high entropy section -> `8`
4. generic YARA heuristic -> `25`

Scoring:

1. local = `65`
2. no malicious gate
3. high gate does not open because only one medium source exists
4. final capped at `59`

Result:

1. `risk_score = 59`
2. `risk_level = medium`
3. `verdict = suspicious`

### Case 5: ZIP containing a direct child EXE with ClamAV hit

Root ZIP signals:

1. local archive heuristics -> `5`
2. one malicious descendant at depth 1 -> inherited `35`
3. tree gate not enough for malicious because local score < `20`

Scoring:

1. local = `5`
2. inherited = `35`
3. final = `40`
4. parent minimum promoted to `high` by policy
5. final adjusted to `60`

Result:

1. `risk_score = 60`
2. `risk_level = high`
3. `verdict = suspicious`

Child EXE result:

1. ClamAV hit -> `95`
2. `risk_level = malicious`

### Case 6: OOXML external template injection

Signals:

1. external template exploit indicator -> `50`
2. remote domain IOC -> `3`
3. multi-type IOC bonus -> `0`

Scoring:

1. local = `53`
2. no malicious gate
3. final = `53`

Result:

1. `risk_score = 53`
2. `risk_level = medium`
3. `verdict = suspicious`

### Case 7: Encoded PowerShell with YARA family hit on deobfuscated content

Signals:

1. PowerShell encoded command -> `4`
2. deobfuscated payload execution -> `12`
3. malicious-family YARA on sidecar -> `85`
4. hidden content revealed bonus -> `5`
5. confirmed + medium corroboration synergy -> `5`

Scoring:

1. local raw = `106`
2. final = `100`
3. malicious gate open via confirmed YARA

Result:

1. `risk_score = 100`
2. `risk_level = malicious`
3. `verdict = malicious`

### Case 8: PDF with embedded JavaScript but otherwise weak context

Signals:

1. suspicious PDF action -> `20`
2. one raw URL IOC -> `3`
3. no YARA, no ClamAV, no child payload

Scoring:

1. local = `23`
2. final = `23`

Result:

1. `risk_score = 23`
2. `risk_level = low`
3. `verdict = suspicious`

### Case 9: Nested archive depth 3 with malicious PowerShell leaf

Root archive signals:

1. no local evidence
2. one malicious descendant at depth 3 -> inherited `floor(35 * 0.5) = 17`
3. no corroborating local evidence

Scoring:

1. final = `17`
2. no parent-promotion floor applies because the malicious descendant is deep and local score is `0`

Result:

1. `risk_score = 17`
2. `risk_level = low`
3. `verdict = suspicious`

Intermediate child archive with local oddities:

1. local packed/structure anomalies -> `15`
2. inherited malicious descendant depth 1 -> `35`
3. final = `50`
4. promoted to `high` minimum if direct child malicious
5. final adjusted to `60`

Result:

1. `risk_score = 60`
2. `risk_level = high`

### Case 10: Text file with many URLs but no other signals

Signals:

1. four URLs -> `12`
2. one domain -> capped within raw IOC family
3. multi-type bonus -> `5`
4. total raw IOC cap applies -> `15`

Result:

1. `risk_score = 15`
2. `risk_level = low`
3. `verdict = suspicious`

### Case 11: Sandbox confirms beaconing and process injection

Signals:

1. confirmed malicious dynamic behavior -> `95`
2. suspicious network IOC -> `3`
3. confirmed + additional corroboration synergy -> `5`

Scoring:

1. final = `100`
2. malicious gate open immediately

Result:

1. `risk_score = 100`
2. `risk_level = malicious`
3. `verdict = malicious`

### Case 12: Signed installer with high entropy and suspicious imports

Signals:

1. suspicious imports -> `20`
2. high entropy section -> `8`
3. packed binary -> `12`
4. trusted signer benign context -> dampener `5` and heuristic cap

Scoring:

1. raw = `40`
2. dampened = `35`
3. heuristic-only + trusted signer cap keeps it at `medium`

Result:

1. `risk_score = 35`
2. `risk_level = medium`
3. `verdict = suspicious`

## 17. Calibration Plan

### 17.1 Dataset Requirements

Build a calibration corpus with labeled examples by file type:

1. clean Office documents
2. clean archives with nested benign files
3. clean installers and signed binaries
4. benign scripts from admin tooling
5. malicious Office droppers
6. malicious archives containing payloads
7. commodity malware PE samples
8. obfuscated scripts and PowerShell droppers
9. malicious PDFs
10. future sandbox-confirmed malware

Do not calibrate on malware only. Clean corpora are essential for false-positive control.

### 17.2 Metrics

Track at least:

1. precision / recall for `malicious`
2. precision / recall for `high_or_above`
3. false-positive rate for clean corpora
4. parent-level false positives in artifact trees
5. top contributing evidence kinds in false positives

### 17.3 Calibration Procedure

1. Run the scorer in shadow mode beside the current logic.
2. Store `policy_version`, evidence list, and final score for every sample.
3. Review the highest-scoring false positives first.
4. Reduce weak evidence weights before lowering strong signal weights.
5. Prefer caps and gates over large negative penalties.
6. Tune per-format only when a global policy is clearly insufficient.

### 17.4 Recommended Tuning Order

When false positives are too high:

1. tighten malicious gate rules
2. lower weak structural caps
3. lower raw IOC cap
4. increase benign-context dampening for trusted contexts
5. tune tree inheritance depth multipliers

When recall is too low:

1. improve evidence normalization quality first
2. raise synergy bonuses for truly independent sources
3. promote specific recurring indicators from `medium` to `strong`
4. enrich raw IOCs with reputation instead of raising raw IOC points

## 18. False-Positive Reduction Strategy

### 18.1 Core Principle

Do not try to “subtract risk away” aggressively. Instead:

1. keep weak signals weak
2. require corroboration for severe outcomes
3. use benign context to dampen heuristics
4. separate descendant inheritance from direct evidence

### 18.2 Specific Protections

1. single weak signal cannot exceed `low`
2. raw IOC extraction cannot exceed `15`
3. pure deobfuscation cannot exceed `20`
4. single deep malicious descendant cannot make a clean root `malicious`
5. trusted signer reduces heuristic-only elevation
6. unknown analyzer evidence defaults to conservative weights

### 18.3 Human Review Hooks

When the top evidence list consists mostly of `weak` signals, the UI should surface a review note such as:

```text
High score driven mainly by heuristic evidence. Review raw findings before escalation.
```

This is especially important during policy tuning.

## 19. Recommended Implementation Notes

1. Keep raw stage outputs unchanged under `results`.
2. Add a new scoring module instead of growing `_build_analysis_result()` further.
3. Normalize stage outputs in one place only.
4. Version the policy from the first rollout.
5. Add tests that lock down score composition, not just final labels.

## 20. Recommendation Summary

Use the **Hybrid Policy Engine**.

Why this is the recommended design for MalScanWorker:

1. It fits the current pipeline and artifact tree model.
2. It converts stage outputs into explainable evidence instead of more hard-coded branches.
3. It prevents weak-signal over-escalation.
4. It provides a clean bridge from current `verdict` semantics to richer `risk_level` semantics.
5. It gives future analyzers, especially sandbox and threat-intel enrichment, a stable integration path without rewriting the scoring framework.
