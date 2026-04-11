# Static Heuristics Enhancement Design

**Date:** 2026-04-10
**Status:** Approved
**Approach:** Heuristic Evidence Overlay (v1 minimal)

## 1. Problem Statement

MalScanWorker already has several static-analysis sources:

1. ClamAV signatures
2. YARA rules
3. IOC extraction
4. format-specific analyzers for PE, PDF, Script, LNK, and Office-derived content
5. archive extraction with recursion and safety limits

The current weak point is recall when a sample has **no signature hit** and no strong single indicator. The existing format analyzers mainly emit:

1. `indicators`
2. `features`
3. `risk_score`
4. `risk_factors`

That is enough for coarse scoring, but it is not yet a dedicated, normalized heuristic layer. The consequences are:

1. heuristic logic is fragmented inside analyzers
2. entropy, packer, LOLBins, token-level script clues, and archive-shape anomalies are not expressed with one stable contract
3. the backend scorer cannot distinguish low-confidence support evidence from stronger corroborating structural evidence
4. `format-analysis` and `archive-extract` do not expose a first-class heuristic payload that can be calibrated independently from signatures
5. false-positive controls are weaker than they should be because weak heuristics are not grouped into explicit cap families

This design adds a dedicated **static heuristic evidence layer** that improves suspicious-sample detection even when ClamAV and YARA are silent, while preserving the current analyzer and scoring architecture.

## 2. Goals

1. Add a generic heuristic layer that works with the current `AnalyzerResult -> FormatAnalysisStage -> malscan.scoring` flow.
2. Cover at least:
   - entropy analysis
   - packer indicators
   - suspicious imports / API patterns
   - file structure anomalies
   - embedded resource anomalies
   - script suspicious token patterns
   - LOLBins / living-off-the-land clues
   - archive structure anomalies
3. Distinguish:
   - generic heuristics
   - format-specific heuristics
4. Mark which heuristics are only supporting evidence and must not directly classify a sample as malicious.
5. Integrate heuristics into the existing risk scorer without replacing signature or sandbox evidence.
6. Preserve backward compatibility for existing analyzer outputs and reports.
7. Provide explicit fields, implementation boundaries, and tests.

## 3. Non-Goals

1. This design does not introduce ML-based classification.
2. This design does not remove existing `indicators`, `risk_score`, or `risk_factors` in v1.
3. This design does not make heuristic signals equivalent to confirmed malware signatures.
4. This design does not require a new database schema.
5. This design does not rewrite analyzers into a new framework from scratch.

## 4. Current-State Constraints

The design must fit the code that exists today:

1. worker analyzers return `AnalyzerResult` from `worker/src/malscan_worker/analyzers/base.py`
2. `worker/src/malscan_worker/stages/format_analysis.py` serializes analyzer output into the stage findings
3. `worker/src/malscan_worker/stages/archive_extract.py` emits archive extraction findings separately from format analysis
4. `backend/src/malscan/scoring/adapters.py` currently converts raw stage findings into `EvidenceRecord` objects
5. `backend/src/malscan/scoring/engine.py` already enforces weak-only, no-high-gate, and no-malicious-gate limits

The key design choice is therefore:

**keep the current analyzer contract, but add a first-class `heuristics` payload that the backend scorer treats as the primary generic-static-evidence input.**

## 5. Recommended Architecture

### 5.1 Summary

Use a **Heuristic Evidence Overlay**:

1. analyzers continue to emit `indicators`, `features`, `risk_score`, and `risk_factors`
2. analyzers additionally emit normalized `heuristics`
3. `FormatAnalysisStage` passes the new `heuristics` list through unchanged
4. `ArchiveExtractStage` also emits `heuristics` for archive-only structural anomalies
5. the backend scoring adapter consumes `heuristics` first
6. existing `indicators` and `risk_score` become fallback compatibility inputs

### 5.2 Why this is the right v1

This is the smallest correct change because it:

1. avoids rewriting all analyzers to emit backend `EvidenceRecord` objects directly
2. keeps worker-side logic focused on extraction and static inspection
3. preserves current test coverage around `AnalyzerResult`, `FormatAnalysisStage`, and pipeline report shaping
4. allows progressive calibration by comparing:
   - legacy `indicators`
   - new `heuristics`
   - final normalized evidence in the report

### 5.3 Flow

```text
file -> file-type
     -> deobfuscation
     -> format-analysis
          -> analyzer features
          -> analyzer indicators
          -> analyzer heuristics (NEW)
     -> archive-extract
          -> archive summary
          -> archive heuristics (NEW)
     -> pipeline report
          -> backend scoring adapter
               -> heuristic evidence normalization (NEW primary path)
               -> legacy indicator fallback (compatibility)
               -> score_direct_evidence()
```

## 6. Generic vs Format-Specific Heuristics

### 6.1 Generic Heuristics

Generic heuristics are reusable across multiple formats or stages. They are defined by **category**, not by one file format.

The generic categories for v1 are:

1. `entropy`
2. `packer`
3. `api_pattern`
4. `structure`
5. `resource`
6. `script_token`
7. `lolbin`
8. `archive`

Generic heuristics may still be emitted from a format-specific analyzer, but they use a shared schema and shared scoring policy.

Examples:

1. `entropy.high_region_cluster`
2. `packer.sparse_imports_high_entropy`
3. `api.process_injection_cluster`
4. `structure.overlay_anomaly`
5. `resource.embedded_executable`
6. `script.long_line_high_entropy`
7. `lolbin.reference_only`
8. `archive.executable_concentration`

### 6.2 Format-Specific Heuristics

Format-specific heuristics depend on one parser or file model.

Examples:

1. PE:
   - entry point outside `.text`
   - writable+executable section
   - sparse import table with packer section names
2. PDF:
   - `/Launch` action
   - obfuscated `/J#61vaScript` names
   - stacked decode filters with low object count
3. Office:
   - macro auto-exec with suspicious launcher APIs
   - external relationship/template references
4. LNK:
   - encoded PowerShell command in shortcut target
   - icon mismatch disguising executable target
5. Script:
   - encoded command + execution primitives
   - AMSI bypass tokens
   - scheduled task / service creation
6. Archive:
   - nested archives with executable leaves
   - path traversal entries
   - extreme member-count / member-type mix

### 6.3 Boundary Rule

Use this rule to decide ownership:

1. if the signal depends only on normalized feature fragments such as entropy, token density, command text, embedded-file type, or archive member stats, it belongs to the generic heuristic layer
2. if the signal depends on parser-specific semantics such as PE section flags, PDF action objects, or OOXML relationships, it belongs to a format-specific rule that still emits a generic `HeuristicHit`

## 7. Worker-Side Heuristic Schema

### 7.1 New Worker Contract

Add a new typed payload to worker analyzer and archive outputs.

Recommended worker schema:

```python
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class HeuristicHit:
    key: str                     # stable mapping key, e.g. "packer.sparse_imports_high_entropy"
    category: str                # entropy, packer, api_pattern, structure, resource, script_token, lolbin, archive
    scope: str                   # generic, pe, pdf, office, lnk, script, archive
    role: str                    # evidence_only, corroborating, gate_signal
    severity: str                # low, medium, high
    confidence: float            # 0.0 - 1.0
    summary: str                 # analyst-facing short explanation
    evidence: dict[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()
```

### 7.2 Field Semantics

| Field | Meaning | Used by scorer? |
|---|---|---|
| `key` | Stable mapping identifier | Yes |
| `category` | Group for UI/debugging and cap family routing | Yes |
| `scope` | Origin analyzer family | Yes |
| `role` | Whether this is weak evidence, corroboration, or a stronger gate signal | Yes |
| `severity` | Local analyzer severity label | Yes |
| `confidence` | Analyzer confidence in this heuristic hit | Yes |
| `summary` | Human-readable explanation | Yes |
| `evidence` | Structured raw details used in report rendering | Yes |
| `tags` | Optional extra labels such as `packed`, `download-exec`, `lolbin` | Optional |

### 7.3 Required Rules for `HeuristicHit`

1. `key` must be stable and version-independent
2. worker-side heuristics must never emit `final verdict`, `risk_level`, or `malicious`
3. worker-side heuristics must never emit a `confirmed` concept
4. all heuristics in this layer are **heuristic evidence only**; even `gate_signal` only means "strong heuristic signal", not "malware confirmed"
5. `evidence` must contain enough context for explainability and tests

### 7.4 `AnalyzerResult` and Stage Changes

Recommended changes:

#### `worker/src/malscan_worker/analyzers/base.py`

Extend `AnalyzerResult`:

```python
@dataclass
class AnalyzerResult:
    analyzer_name: str
    format_type: str
    indicators: list[AnalyzerIndicator] = field(default_factory=list)
    heuristics: list[HeuristicHit] = field(default_factory=list)
    features: dict[str, JsonValue] = field(default_factory=dict)
    extracted_strings: list[str] = field(default_factory=list)
    risk_score: int = 0
    risk_factors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    extracted_artifacts: list[AnalyzerArtifact] = field(default_factory=list)
```

#### `worker/src/malscan_worker/stages/format_analysis.py`

Pass through:

```python
findings = {
    "analyzer": analysis.analyzer_name or analyzer.name,
    "format_type": analysis.format_type,
    "risk_score": analysis.risk_score,
    "risk_factors": analysis.risk_factors,
    "indicators": analysis.indicators,
    "heuristics": [asdict(item) for item in analysis.heuristics],
    "features": analysis.features,
    ...
}
```

#### `worker/src/malscan_worker/stages/archive_extract.py`

Add:

1. `archive_summary`
2. `heuristics`

Example output:

```python
{
    "archive_type": "zip",
    "extracted_count": 12,
    "sub_jobs_created": 11,
    "warnings": ["Path traversal skipped: ../run.exe"],
    "archive_summary": {
        "entry_count": 13,
        "executable_member_count": 4,
        "nested_archive_count": 2,
        "duplicate_basename_count": 3,
        "max_member_depth": 4,
        "password_protected": False,
        "total_extracted_bytes": 284392,
        "suspicious_member_extensions": [".exe", ".ps1", ".lnk"],
    },
    "heuristics": [
        {
            "key": "archive.executable_concentration",
            "category": "archive",
            "scope": "archive",
            "role": "corroborating",
            "severity": "medium",
            "confidence": 0.75,
            "summary": "Archive contains multiple executable/script members",
            "evidence": {"count": 4, "extensions": [".exe", ".ps1", ".lnk"]},
            "tags": ["archive", "embedded-executable"],
        }
    ],
}
```

## 8. Normalized Evidence Mapping

### 8.1 Backend Design

Extend `backend/src/malscan/scoring/adapters.py` with two new paths:

1. `_append_format_heuristics()` for `format-analysis.heuristics`
2. `_append_archive_heuristics()` for `archive-extract.heuristics`

Existing `indicators` handling stays as fallback compatibility logic.

### 8.2 Role Mapping Policy

Worker-side `role` maps into backend evidence tiers like this:

| Worker `role` | Backend default tier | Meaning |
|---|---|---|
| `evidence_only` | `weak` or `medium` | support only, never intended to open malicious gate |
| `corroborating` | `medium` | meaningful suspicious evidence that needs company |
| `gate_signal` | `strong` | clear suspicious execution or exploit primitive, still not confirmed malware |

### 8.3 Hard Rule: No Heuristic Produces `confirmed`

This is the main false-positive protection.

Only these sources may produce `tier = confirmed`:

1. ClamAV signatures
2. curated high-confidence YARA family/exploit rules
3. future threat-intel enrichment
4. future sandbox-confirmed behavior

The static heuristic layer may produce at most `strong` evidence.

## 9. Heuristic Scoring Policy

### 9.1 New Cap Groups

Extend `backend/src/malscan/scoring/policy.py` with generic cap groups:

```python
CAP_GROUP_LIMITS = {
    "ioc_raw": 15,
    "deob": 20,
    "heuristic_entropy": 12,
    "heuristic_packer": 18,
    "heuristic_api": 35,
    "heuristic_structure": 20,
    "heuristic_resource": 30,
    "heuristic_script": 30,
    "heuristic_lolbin": 25,
    "heuristic_archive": 25,
}
```

Update `score_direct_evidence()` so caps are data-driven rather than hard-coded only for `ioc_raw` and `deob`.

### 9.2 Default Mapping Table

| Heuristic key | Tier | Points | Cap group | Notes |
|---|---:|---:|---|---|
| `entropy.high_region_cluster` | weak | 8 | `heuristic_entropy` | one or more high-entropy sections/regions |
| `entropy.full_file_entropy_high` | weak | 6 | `heuristic_entropy` | whole-file compression/encryption hint |
| `packer.known_section_name` | weak | 10 | `heuristic_packer` | UPX/Themida/etc |
| `packer.sparse_imports_high_entropy` | medium | 18 | `heuristic_packer` | stronger packer cluster |
| `packer.entrypoint_non_text` | medium | 15 | `heuristic_packer` | suspicious runtime loader pattern |
| `api.suspicious_cluster` | medium | 18 | `heuristic_api` | grouped suspicious APIs |
| `api.process_injection_cluster` | strong | 40 | `heuristic_api` | `VirtualAllocEx + WriteProcessMemory + CreateRemoteThread` |
| `api.crypto_extortion_combo` | medium | 20 | `heuristic_api` | ransomware-like API combination |
| `structure.overlay_anomaly` | weak | 10 | `heuristic_structure` | unexpected overlay/trailing data |
| `structure.malformed_container` | weak | 10 | `heuristic_structure` | parse survives, structure abnormal |
| `structure.polyglot_signature_overlap` | medium | 15 | `heuristic_structure` | suspicious multi-format signature overlap |
| `resource.embedded_executable` | medium | 22 | `heuristic_resource` | PE/script inside resource or attachment |
| `resource.large_high_entropy_blob` | medium | 16 | `heuristic_resource` | embedded encrypted payload candidate |
| `resource.unusual_resource_density` | weak | 8 | `heuristic_resource` | many unexpected resource objects |
| `script.encoded_command_execution` | strong | 45 | `heuristic_script` | encoded payload plus execution primitive |
| `script.amsi_bypass` | medium | 18 | `heuristic_script` | evasion token cluster |
| `script.long_line_entropy_cluster` | weak | 8 | `heuristic_script` | obfuscation support signal |
| `lolbin.reference_only` | weak | 6 | `heuristic_lolbin` | suspicious tool mention only |
| `lolbin.execution_chain` | medium | 18 | `heuristic_lolbin` | LOLBin used with remote/encoded/launch behavior |
| `archive.executable_concentration` | medium | 18 | `heuristic_archive` | multiple executable-like members |
| `archive.password_protected` | weak | 6 | `heuristic_archive` | evidence only |
| `archive.path_traversal_member` | weak | 10 | `heuristic_archive` | suspicious archive member path |
| `archive.deep_nesting` | weak | 8 | `heuristic_archive` | recursion/staging clue |

### 9.3 Evidence-Only Heuristics

The following heuristics are **evidence_only** and must not independently justify `high` or `malicious`:

1. `entropy.high_region_cluster`
2. `entropy.full_file_entropy_high`
3. `packer.known_section_name`
4. `structure.overlay_anomaly`
5. `structure.malformed_container`
6. `resource.unusual_resource_density`
7. `script.long_line_entropy_cluster`
8. `lolbin.reference_only`
9. `archive.password_protected`
10. `archive.deep_nesting`
11. `archive.duplicate_basenames`
12. `archive.path_traversal_member`

These are intentionally weak because they are common in benign installers, admin scripts, archives, and compressed software.

### 9.4 Corroborating Heuristics

These may contribute materially, but still require corroboration:

1. `packer.sparse_imports_high_entropy`
2. `packer.entrypoint_non_text`
3. `api.suspicious_cluster`
4. `resource.embedded_executable`
5. `resource.large_high_entropy_blob`
6. `archive.executable_concentration`
7. `lolbin.execution_chain`
8. `script.amsi_bypass`

### 9.5 Strong Gate Signals

These are still heuristic, but deserve `strong` treatment because they imply an execution or exploit chain:

1. `api.process_injection_cluster`
2. `script.encoded_command_execution`
3. `pdf.launch_action_executable`
4. `office.external_template_execution`
5. `lnk.encoded_lolbin_launcher`

Even these are not `confirmed`; they only help open `high_gate` and can reach `malicious` only when combined under existing policy gates.

## 10. Rule Catalogue

### 10.1 Generic Rules

#### A. Entropy Analysis

1. `entropy.high_region_cluster`
   - Trigger: two or more sections/regions with entropy >= `7.2`, or one executable section/resource >= `7.4`
   - Role: `evidence_only`
   - Evidence:
     - names of regions
     - entropy values
     - executable/resource flags

2. `entropy.full_file_entropy_high`
   - Trigger: full-file entropy >= `7.0` and file type is not known compressed media
   - Role: `evidence_only`
   - Evidence:
     - file entropy
     - mime
     - extension

#### B. Packer Indicators

1. `packer.known_section_name`
   - Trigger: known section name such as `UPX0`, `UPX1`, `.aspack`, `.themida`
   - Role: `evidence_only`

2. `packer.sparse_imports_high_entropy`
   - Trigger: import DLL count <= `1` or imported function count < `10` plus at least one high-entropy executable section
   - Role: `corroborating`

3. `packer.entrypoint_non_text`
   - Trigger: PE entry point not in `.text` or in a suspicious non-standard section
   - Role: `corroborating`

#### C. Suspicious Imports / API Patterns

1. `api.suspicious_cluster`
   - Trigger: 2 or more API hits in one cluster family:
     - download/network
     - injection
     - persistence
     - anti-analysis
   - Role: `corroborating`

2. `api.process_injection_cluster`
   - Trigger: any 3 of:
     - `VirtualAllocEx`
     - `WriteProcessMemory`
     - `CreateRemoteThread`
     - `NtQueueApcThread`
     - `SetThreadContext`
   - Role: `gate_signal`

3. `api.crypto_extortion_combo`
   - Trigger: encryption APIs plus file-enumeration / file-rewrite APIs
   - Role: `corroborating`

#### D. File Structure Anomalies

1. `structure.overlay_anomaly`
   - Trigger: overlay data present and size > threshold, especially in PE/LNK/script wrappers
   - Role: `evidence_only`

2. `structure.malformed_container`
   - Trigger: parse succeeds partially but reports broken xref/object count mismatch/truncated trailing blocks or invalid offsets
   - Role: `evidence_only`

3. `structure.polyglot_signature_overlap`
   - Trigger: conflicting magic/footer/header relationships that suggest polyglot or appended payload
   - Role: `corroborating`

#### E. Embedded Resource Anomalies

1. `resource.embedded_executable`
   - Trigger: PE/script/archive/executable attachment embedded in a container, resource, or object
   - Role: `corroborating`

2. `resource.large_high_entropy_blob`
   - Trigger: embedded object/resource > size threshold and entropy >= `7.2`
   - Role: `corroborating`

3. `resource.unusual_resource_density`
   - Trigger: excessive resource count or many unexpected resource object types for that format
   - Role: `evidence_only`

#### F. Script Suspicious Token Patterns

1. `script.encoded_command_execution`
   - Trigger: encoded payload markers plus execution primitive in same script/LNK command chain
   - Role: `gate_signal`

2. `script.amsi_bypass`
   - Trigger: AMSI bypass strings or reflection-based bypass tokens
   - Role: `corroborating`

3. `script.long_line_entropy_cluster`
   - Trigger: very long lines plus high symbol density and encoded blob hits
   - Role: `evidence_only`

#### G. LOLBins / Living-off-the-Land

1. `lolbin.reference_only`
   - Trigger: `powershell`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `wscript`, `cscript`, `cmd /c` referenced without stronger context
   - Role: `evidence_only`

2. `lolbin.execution_chain`
   - Trigger: LOLBin plus one of:
     - remote URL
     - encoded payload
     - launch/exec primitive
     - user-writable staging path
   - Role: `corroborating`

#### H. Archive Structure Anomalies

1. `archive.password_protected`
   - Trigger: archive requires password or member encryption detected
   - Role: `evidence_only`

2. `archive.executable_concentration`
   - Trigger: multiple extracted members are executable/script/shortcut/archive droppers
   - Role: `corroborating`

3. `archive.path_traversal_member`
   - Trigger: extraction skipped members due to `../`, absolute path, or unsafe path normalization
   - Role: `evidence_only`

4. `archive.deep_nesting`
   - Trigger: nested archive depth above normal threshold or multiple nested archive layers before payloads
   - Role: `evidence_only`

### 10.2 Format-Specific Rule Examples

#### PE

1. `packer.sparse_imports_high_entropy`
2. `packer.entrypoint_non_text`
3. `api.process_injection_cluster`
4. `resource.embedded_executable`
5. `structure.overlay_anomaly`

#### PDF

1. `pdf.launch_action_executable`
2. `pdf.javascript_openaction_chain`
3. `structure.malformed_container`
4. `resource.embedded_executable`
5. `structure.polyglot_signature_overlap`

#### Office

1. `office.external_template_execution`
2. `office.macro_autoexec_launcher`
3. `resource.embedded_executable`
4. `lolbin.execution_chain` from macro preview text

#### Script

1. `script.encoded_command_execution`
2. `script.amsi_bypass`
3. `lolbin.execution_chain`
4. `archive.deep_nesting` only if decoded payload reveals nested archive staging

#### LNK

1. `lnk.encoded_lolbin_launcher`
2. `lolbin.execution_chain`
3. `structure.overlay_anomaly`
4. `script.encoded_command_execution` if decoded command contains encoded launcher chain

## 11. Concrete Worker Features Needed

### 11.1 PE Analyzer

Existing PE feature extraction is already close. The heuristic layer should consume or add:

1. `features["sections"]`
2. `features["imports"]`
3. `features["resources"]`
4. `features["headers"]`
5. `features["overlay"]`
6. `features["packer_clues"]`
7. `features["entry_point_section"]` (NEW)
8. `features["import_count"]` (NEW)

### 11.2 PDF Analyzer

Needed feature fragments:

1. `features["js_code"]`
2. `features["launch_actions"]`
3. `features["open_actions"]`
4. `features["embedded_files"]`
5. `features["suspicious_names"]`
6. `features["stream_info"]`
7. `features["parse_errors"]` or parser-derived anomaly count (NEW)

### 11.3 Script Analyzer

Needed feature fragments:

1. `download_operations`
2. `exec_operations`
3. `process_operations`
4. `registry_operations`
5. `network_indicators`
6. `encoded_strings`
7. `obfuscation_score`
8. `max_line_length` (NEW)
9. `lolbin_references` (NEW)

### 11.4 LNK Analyzer

Needed feature fragments:

1. `command_chain`
2. `decoded_command`
3. `target_path`
4. `icon_location`
5. `working_dir`
6. `network_path`

### 11.5 Office Adapter

Needed feature fragments:

1. `macros`
2. `embedded_objects`
3. `parser_findings`
4. `suspicious_keywords`
5. `external_relationships` or equivalent extracted targets if available (NEW)

### 11.6 Archive Extract Stage

Add a lightweight archive summary model:

```python
archive_summary = {
    "entry_count": int,
    "executable_member_count": int,
    "script_member_count": int,
    "shortcut_member_count": int,
    "nested_archive_count": int,
    "duplicate_basename_count": int,
    "max_member_depth": int,
    "password_protected": bool,
    "path_traversal_skipped": int,
    "suspicious_member_extensions": list[str],
    "member_extension_histogram": dict[str, int],
    "total_extracted_bytes": int,
}
```

This is enough for v1 archive heuristics without redesigning extractor internals.

## 12. Pseudocode / Python Skeleton

### 12.1 Heuristic Models

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class HeuristicHit:
    key: str
    category: str
    scope: str
    role: str
    severity: str
    confidence: float
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()


def make_hit(
    *,
    key: str,
    category: str,
    scope: str,
    role: str,
    severity: str,
    confidence: float,
    summary: str,
    evidence: dict[str, Any] | None = None,
    tags: tuple[str, ...] = (),
) -> HeuristicHit:
    return HeuristicHit(
        key=key,
        category=category,
        scope=scope,
        role=role,
        severity=severity,
        confidence=confidence,
        summary=summary,
        evidence=evidence or {},
        tags=tags,
    )
```

### 12.2 Generic Evaluators

```python
def evaluate_entropy_regions(*, scope: str, regions: list[dict[str, Any]]) -> list[HeuristicHit]:
    suspicious = [
        region for region in regions
        if float(region.get("entropy", 0.0)) >= 7.2
    ]
    if len(suspicious) >= 2:
        return [
            make_hit(
                key="entropy.high_region_cluster",
                category="entropy",
                scope=scope,
                role="evidence_only",
                severity="medium",
                confidence=0.65,
                summary="Multiple high-entropy regions detected",
                evidence={
                    "region_count": len(suspicious),
                    "regions": suspicious[:5],
                },
                tags=("entropy", "packed"),
            )
        ]
    return []


def evaluate_lolbin_chain(*, scope: str, text: str) -> list[HeuristicHit]:
    text_l = text.lower()
    referenced = [
        name for name in (
            "powershell", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin",
            "wscript", "cscript", "cmd /c",
        )
        if name in text_l
    ]
    if not referenced:
        return []

    has_remote = any(token in text_l for token in ("http://", "https://", "downloadstring", "downloadfile"))
    has_encoded = any(token in text_l for token in ("-enc", "encodedcommand", "frombase64string"))
    has_exec = any(token in text_l for token in ("start-process", "invoke-expression", "shell", "createprocess"))

    if has_remote or has_encoded or has_exec:
        return [
            make_hit(
                key="lolbin.execution_chain",
                category="lolbin",
                scope=scope,
                role="corroborating",
                severity="medium",
                confidence=0.8,
                summary="LOLBins appear in an execution-oriented chain",
                evidence={
                    "referenced": referenced,
                    "has_remote": has_remote,
                    "has_encoded": has_encoded,
                    "has_exec": has_exec,
                },
                tags=("lolbin",),
            )
        ]

    return [
        make_hit(
            key="lolbin.reference_only",
            category="lolbin",
            scope=scope,
            role="evidence_only",
            severity="low",
            confidence=0.55,
            summary="LOLBins referenced without a stronger chain",
            evidence={"referenced": referenced},
            tags=("lolbin",),
        )
    ]
```

### 12.3 PE Integration Example

```python
def build_pe_heuristics(features: dict[str, Any]) -> list[HeuristicHit]:
    hits: list[HeuristicHit] = []

    sections = list(features.get("sections", []))
    imports = list(features.get("imports", []))
    overlay = features.get("overlay") or {}
    packer_clues = list(features.get("packer_clues", []))

    hits.extend(evaluate_entropy_regions(scope="pe", regions=sections))

    if packer_clues:
        hits.append(
            make_hit(
                key="packer.known_section_name",
                category="packer",
                scope="pe",
                role="evidence_only",
                severity="medium",
                confidence=0.75,
                summary="Known packer section names detected",
                evidence={"packer_clues": packer_clues},
                tags=("packed",),
            )
        )

    if len(imports) <= 1 and any(float(item.get("entropy", 0)) >= 7.2 for item in sections):
        hits.append(
            make_hit(
                key="packer.sparse_imports_high_entropy",
                category="packer",
                scope="pe",
                role="corroborating",
                severity="medium",
                confidence=0.8,
                summary="Sparse imports with high-entropy sections suggest packing",
                evidence={"import_dll_count": len(imports), "sections": sections[:5]},
                tags=("packed",),
            )
        )

    suspicious_imports = {
        fn.lower()
        for item in imports
        if isinstance(item, dict)
        for fn in item.get("functions", [])
        if isinstance(fn, str)
    }
    inj_cluster = {"virtualallocex", "writeprocessmemory", "createremotethread"}
    if len(inj_cluster & suspicious_imports) >= 3:
        hits.append(
            make_hit(
                key="api.process_injection_cluster",
                category="api_pattern",
                scope="pe",
                role="gate_signal",
                severity="high",
                confidence=0.9,
                summary="Process injection API cluster detected",
                evidence={"matched": sorted(inj_cluster & suspicious_imports)},
                tags=("injection",),
            )
        )

    if overlay.get("present") and int(overlay.get("size", 0) or 0) >= 1024:
        hits.append(
            make_hit(
                key="structure.overlay_anomaly",
                category="structure",
                scope="pe",
                role="evidence_only",
                severity="low",
                confidence=0.6,
                summary="Unexpected PE overlay data present",
                evidence=dict(overlay),
                tags=("overlay",),
            )
        )

    return hits
```

### 12.4 Backend Adapter Example

```python
HEURISTIC_MAP = {
    "entropy.high_region_cluster": ("weak", 8, "heuristic_entropy"),
    "packer.known_section_name": ("weak", 10, "heuristic_packer"),
    "packer.sparse_imports_high_entropy": ("medium", 18, "heuristic_packer"),
    "api.process_injection_cluster": ("strong", 40, "heuristic_api"),
    "structure.overlay_anomaly": ("weak", 10, "heuristic_structure"),
    "resource.embedded_executable": ("medium", 22, "heuristic_resource"),
    "script.encoded_command_execution": ("strong", 45, "heuristic_script"),
    "lolbin.execution_chain": ("medium", 18, "heuristic_lolbin"),
    "archive.executable_concentration": ("medium", 18, "heuristic_archive"),
}


def _append_format_heuristics(
    records: list[EvidenceRecord],
    artifact_id: str | None,
    finding: dict[str, Any],
) -> None:
    for hit in finding.get("heuristics", []):
        if not isinstance(hit, dict):
            continue
        key = str(hit.get("key", "")).strip()
        if not key:
            continue

        tier, points, cap_group = HEURISTIC_MAP.get(key, ("weak", 5, "heuristic_structure"))
        severity = {
            "strong": "high",
            "medium": "medium",
            "weak": "low",
        }[tier]

        _append(
            records,
            source="format-analysis",
            kind=key,
            tier=tier,
            severity=severity,
            confidence=float(hit.get("confidence", 0.5) or 0.5),
            points=points,
            cap_group=cap_group,
            artifact_id=artifact_id,
            reason=str(hit.get("summary", key)),
            raw=dict(hit),
        )
```

## 13. Twenty Heuristic Case Examples

### 1. Packed PE with UPX sections

Input:
`UPX0`, `UPX1`, sparse imports, high-entropy executable section

Heuristics:

1. `packer.known_section_name`
2. `packer.sparse_imports_high_entropy`
3. `entropy.high_region_cluster`

Expected outcome:
Medium or high suspicious, not malicious by itself.

### 2. Clean signed installer with one compressed resource

Input:
large installer, one high-entropy resource, normal imports, no suspicious chain

Heuristics:

1. `resource.large_high_entropy_blob`

Expected outcome:
Low or medium only after caps; should not escalate alone.

### 3. PE with injection API trio

Input:
`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`

Heuristics:

1. `api.process_injection_cluster`

Expected outcome:
High suspicious, still not malicious without corroboration.

### 4. PE with overlay dropper tail

Input:
small PE plus 300 KB overlay blob

Heuristics:

1. `structure.overlay_anomaly`

Expected outcome:
Support evidence only.

### 5. PDF with `/Launch` to executable attachment

Input:
`/OpenAction`, `/Launch`, embedded `setup.exe`

Heuristics:

1. `pdf.launch_action_executable`
2. `resource.embedded_executable`

Expected outcome:
High suspicious; can help open malicious path only with other strong evidence.

### 6. PDF with obfuscated JavaScript names

Input:
`/J#61vaScript`, `/OpenAction`, suspicious JS body

Heuristics:

1. `pdf.javascript_openaction_chain`
2. `structure.malformed_container` if parse anomalies also present

Expected outcome:
Medium or high.

### 7. Benign PDF with attachment form

Input:
one non-executable attachment, normal form fields

Heuristics:

1. none or only weak resource support

Expected outcome:
Stay low/clean.

### 8. PowerShell with `-EncodedCommand` and `IEX`

Input:
encoded command plus `Invoke-Expression`

Heuristics:

1. `script.encoded_command_execution`
2. `lolbin.execution_chain`

Expected outcome:
High suspicious.

### 9. PowerShell admin script with `certutil` only

Input:
`certutil` used for certificate export, no remote URL, no exec chain

Heuristics:

1. `lolbin.reference_only`

Expected outcome:
Evidence-only, low.

### 10. JavaScript with long obfuscated line and base64 blobs

Input:
single 8 KB line, `fromCharCode`, base64 strings

Heuristics:

1. `script.long_line_entropy_cluster`

Expected outcome:
Weak support unless combined with downloader or exec indicators.

### 11. JavaScript downloader

Input:
`XMLHttpRequest`, `ActiveXObject`, `WScript.Shell.Run`

Heuristics:

1. `script.download_execute_chain`
2. `lolbin.execution_chain` if script launches `powershell` or `cmd`

Expected outcome:
High suspicious.

### 12. Office DOCM with `AutoOpen` and `Shell`

Input:
macro auto-exec with suspicious launcher keywords

Heuristics:

1. `office.macro_autoexec_launcher`

Expected outcome:
Medium to high suspicious.

### 13. Office document with external template

Input:
external template relationship pointing to remote URL

Heuristics:

1. `office.external_template_execution`
2. `lolbin.execution_chain` only if macro/script preview text also includes LOLBin chain

Expected outcome:
High suspicious.

### 14. LNK to PowerShell hidden encoded command

Input:
target `powershell.exe -w hidden -enc ...`

Heuristics:

1. `lnk.encoded_lolbin_launcher`
2. `script.encoded_command_execution`
3. `lolbin.execution_chain`

Expected outcome:
High suspicious.

### 15. LNK with PDF icon disguising EXE

Input:
target EXE, icon `.pdf`

Heuristics:

1. `lnk.icon_disguise`

Expected outcome:
Medium support, not malicious alone.

### 16. ZIP with several executables and scripts

Input:
archive containing `.exe`, `.ps1`, `.lnk`, `.dll`

Heuristics:

1. `archive.executable_concentration`

Expected outcome:
Medium suspicious parent artifact.

### 17. ZIP with path traversal entry

Input:
entry `../Startup/run.vbs`

Heuristics:

1. `archive.path_traversal_member`

Expected outcome:
Evidence-only unless child artifacts add more.

### 18. Password-protected archive with no other clues

Input:
encrypted ZIP, no inspected contents yet

Heuristics:

1. `archive.password_protected`

Expected outcome:
Low only; never high by itself.

### 19. Nested archives ending in a malicious script leaf

Input:
three nested archives, inner script emits `script.encoded_command_execution`

Heuristics:

1. root: `archive.deep_nesting`
2. leaf: `script.encoded_command_execution`

Expected outcome:
Root gets elevated through descendant logic, but deep nesting alone stays weak.

### 20. Archive with many duplicate bait filenames

Input:
`invoice.pdf.exe`, `invoice(1).pdf.exe`, `invoice-final.pdf.exe`

Heuristics:

1. `archive.duplicate_basenames`
2. `archive.executable_concentration`

Expected outcome:
Medium suspicious if executable concentration is also present.

## 14. False-Positive Reduction Strategy

### 14.1 Core Principles

1. all heuristic signals remain below `confirmed`
2. noisy categories are capped by family
3. a single heuristic should rarely exceed `low`
4. only gate-signal heuristics may help open `high_gate`
5. `malicious` still requires existing multi-source or confirmed-evidence policy

### 14.2 Specific FP Controls

1. entropy-only files remain weak-capped
2. packer-only files cap at `medium`
3. LOLBin reference without remote/encoded/exec chain stays weak
4. password-protected archive stays weak without child evidence
5. large resources do not escalate alone unless executable or highly corroborated
6. parser anomalies count as structural noise, not malware confirmation
7. script token rules require clustered behavior, not single-token hits
8. archive rules look at **composition**, not just one member extension

### 14.3 Recommended Threshold Discipline

Use these defaults:

1. entropy thresholds should be conservative:
   - section/resource >= `7.2`
   - whole-file >= `7.0`
2. API cluster rules should require at least `2` related APIs, or `3` for injection cluster
3. LOLBin chain rules should require one contextual amplifier:
   - remote URL
   - encoded payload
   - execution primitive
   - user-writable staging path
4. archive concentration rules should require more than one executable-like member or a suspicious ratio, not a single installer file

### 14.4 Allowlisted / Benign Context Hooks

The scorer already supports dampening concepts. This design should preserve room for:

1. trusted signer dampening for PE heuristics
2. expected installer/archive templates
3. internal-only IOC context
4. expected embedded content in enterprise documents

## 15. Testing Strategy

### 15.1 Worker Unit Tests

Add tests for heuristic builders, not only analyzers.

Recommended test files:

1. `worker/tests/heuristics/test_common.py`
2. `worker/tests/heuristics/test_pe_heuristics.py`
3. `worker/tests/heuristics/test_pdf_heuristics.py`
4. `worker/tests/heuristics/test_script_heuristics.py`
5. `worker/tests/heuristics/test_archive_heuristics.py`

Test focus:

1. exact heuristic keys
2. expected `role`
3. expected evidence payload structure
4. suppression of weak heuristics on benign fixtures

### 15.2 Analyzer Tests

Extend existing analyzer tests so they assert `heuristics` as well as `indicators`.

Examples:

1. PE high entropy fixture emits `entropy.high_region_cluster`
2. PE injection import fixture emits `api.process_injection_cluster`
3. PDF launch fixture emits `pdf.launch_action_executable`
4. Script encoded PowerShell emits `script.encoded_command_execution`
5. LNK encoded launcher emits `lnk.encoded_lolbin_launcher`

### 15.3 Archive Tests

Extend archive handler/stage tests for:

1. password-protected archive -> `archive.password_protected`
2. path traversal member skipped -> `archive.path_traversal_member`
3. multiple executable members -> `archive.executable_concentration`
4. nested archive summary -> `archive.deep_nesting`

### 15.4 Backend Adapter Tests

Add explicit tests in `backend/tests/test_scoring_adapters.py` for:

1. format-analysis heuristics map to expected evidence kinds and cap groups
2. archive heuristics map to expected evidence kinds and cap groups
3. legacy indicator fallback still works when heuristics are absent
4. unknown heuristic keys default conservatively to weak 5-point evidence

### 15.5 Engine Tests

Add tests for cap-group enforcement:

1. multiple entropy hits cap at `heuristic_entropy`
2. multiple archive hits cap at `heuristic_archive`
3. process injection cluster plus weak signals can reach `high`
4. heuristic-only samples cannot reach `malicious` without gate conditions

### 15.6 Integration Tests

Add pipeline-level tests for:

1. `results.format_analysis.heuristics`
2. `results.archive_extract.heuristics`
3. `risk.evidence` containing heuristic-derived records
4. compatibility when heuristics are absent

## 16. File-Level Implementation Plan

### New worker files

1. `worker/src/malscan_worker/heuristics/__init__.py`
2. `worker/src/malscan_worker/heuristics/models.py`
3. `worker/src/malscan_worker/heuristics/common.py`
4. `worker/src/malscan_worker/heuristics/pe.py`
5. `worker/src/malscan_worker/heuristics/pdf.py`
6. `worker/src/malscan_worker/heuristics/script.py`
7. `worker/src/malscan_worker/heuristics/archive.py`

### Modified worker files

1. `worker/src/malscan_worker/analyzers/base.py`
2. `worker/src/malscan_worker/analyzers/pe_analyzer.py`
3. `worker/src/malscan_worker/analyzers/pdf_analyzer.py`
4. `worker/src/malscan_worker/analyzers/script_analyzer.py`
5. `worker/src/malscan_worker/analyzers/lnk_analyzer.py`
6. `worker/src/malscan_worker/analyzers/office_adapter.py`
7. `worker/src/malscan_worker/stages/format_analysis.py`
8. `worker/src/malscan_worker/stages/archive_extract.py`
9. `worker/src/malscan_worker/extractors/base.py`

### Modified backend files

1. `backend/src/malscan/scoring/adapters.py`
2. `backend/src/malscan/scoring/policy.py`
3. `backend/src/malscan/scoring/engine.py`

## 17. Rollout Strategy

1. introduce `heuristics` payloads first without removing any existing fields
2. update backend adapter to prefer heuristics, but keep `indicators` fallback
3. add tests that compare old and new report shapes
4. calibrate caps before increasing any heuristic point value
5. only after stable tuning consider reducing reliance on `risk_score` support points

## 18. Recommendation Summary

Implement the static-feature enhancement as a **Heuristic Evidence Overlay**.

This is the right design for MalScanWorker because it:

1. fits the code already in the repo
2. gives generic static evidence a first-class schema
3. separates weak evidence from stronger corroborating signals
4. improves recall when signatures are absent
5. keeps false-positive control in the backend scoring policy instead of spreading scoring logic across analyzers
