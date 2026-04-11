# Report Explainability Redesign Design

**Date:** 2026-04-11
**Status:** Proposed
**Approach:** Additive Explainability Contract (v2)

## 1. Problem Statement

MalScanWorker can already tell a user whether a sample is `clean`, `suspicious`, or `malicious`, and it now exposes tree-aware risk scoring, heuristics, deobfuscation output, and an artifact tree. That is enough for machine processing, but not enough for an analyst or end user to answer the practical questions that matter during triage:

1. Which artifact was actually judged suspicious or malicious?
2. Where is that artifact in the nested archive structure?
3. Which evidence hit?
4. Which analyzer or stage found it?
5. Which IOC or decoded string was extracted?
6. How was the final score formed?
7. Which parts are uncertain?
8. If this was a miss, where could the miss have happened?

The current report payload spreads relevant facts across several places:

1. `risk.evidence` contains scoring facts, but lacks complete artifact/stage/analyzer provenance.
2. `results.format_analysis`, `results.deobfuscation`, `results.archive_extract`, and `results.document_analysis` preserve raw stage outputs, but are not normalized into a user-facing explanation model.
3. `artifact_tree` shows lineage, but not which evidence, analyzer, IOC, or score component belongs to each node.
4. `risk.breakdown` explains local vs inherited score at a high level, but not the contribution of each evidence record or tree rollup decision.
5. Failure and uncertainty signals exist implicitly in skipped stages, parser errors, truncation flags, password exhaustion, and unsupported formats, but they are not elevated into a first-class diagnostics section.

The redesign should make the report answer those questions directly without breaking the current endpoint or current consumers.

## 2. Goals

1. Preserve the current `GET /api/v1/reports/{job_id}` endpoint and current compatibility fields.
2. Add a canonical explainability layer that answers all eight questions above.
3. Make every scored artifact addressable, even when the current job never created a persistent root artifact row.
4. Make evidence, analyzer, IOC, decoded string, and score contribution traceable to a specific artifact.
5. Provide an artifact-tree view and an evidence-timeline view without forcing the UI to reconstruct them from raw stage payloads.
6. Add a top-findings summary that is useful for both API clients and human readers.
7. Add explicit uncertainty and failure-diagnostics sections that explain partial coverage, blocked analysis, or likely miss locations.
8. Keep the current `results.*` stage outputs as the raw compatibility path.

## 3. Non-Goals

1. This design does not replace the current risk scoring policy.
2. This design does not remove top-level `verdict`, `score`, `risk_level`, `risk`, `results`, `timings`, `child_jobs`, or `artifact_tree`.
3. This design does not require a new public endpoint in v1 of the redesign.
4. This design does not require ML-based attribution or natural-language generation in the backend.
5. This design does not attempt to guarantee byte-perfect provenance for old stored reports that never persisted the required raw signals.

## 4. Current-State Constraints

The redesign has to fit the code that exists now:

1. The worker stores a local report in `worker/src/malscan_worker/pipeline.py`.
2. The backend backfills the `risk` block for legacy reports and recomputes tree-aware rollup inside `backend/src/malscan/api/routes.py`.
3. The current scoring engine already produces normalized `EvidenceRecord` instances, but the serialized report drops several important fields such as `artifact_id`, `related_artifact_id`, `confidence`, and cap application details.
4. The current `artifact_tree` is built from persisted artifact rows and then used for descendant rollup, but it does not carry finding references or stage coverage.
5. The frontend `ReportPage` still mainly renders legacy sections and currently ignores most of the richer `risk` and `artifact_tree` data.

That leads to the central design rule for this change:

**keep current raw stage outputs and current compatibility fields intact, then add one canonical explainability contract that is derived from them.**

## 5. Approaches Considered

### Approach A: Expand `risk.evidence.raw` only

Add more provenance into `risk.evidence.raw` and make the UI reconstruct everything from there.

Pros:

1. Smallest storage and schema change.
2. Minimal work in the worker.

Cons:

1. Pushes complex grouping logic into every client.
2. Does not naturally express artifact tree, top findings, timeline, or diagnostics.
3. Keeps the report hard to read for humans and hard to consume for UI.

### Approach B: Add a dedicated additive `explainability` block while preserving current fields

Keep `results.*` as raw stage outputs and add a canonical `explainability` block, plus richer `risk.score_trace` and richer `artifact_tree` nodes.

Pros:

1. Best fit for existing endpoint compatibility.
2. Lets backend own grouping, provenance stitching, and rollup explanation once.
3. Gives UI a stable, ready-to-render contract.
4. Keeps old clients working because all changes are additive.

Cons:

1. Some data is intentionally duplicated between raw stage outputs and the canonical explainability layer.
2. Requires new assembly code in backend.

### Approach C: Create a separate `/reports/{job_id}/explainability` endpoint

Keep the current report untouched and introduce a second endpoint for explainability.

Pros:

1. Cleaner separation between legacy and new clients.
2. Easier to size-control if explainability gets large.

Cons:

1. Splits one report across two contracts.
2. Risks drift between the main report and the explainability report.
3. Adds frontend round trips and more endpoint surface area.

### Recommendation

Use **Approach B**.

It is the smallest correct design that still gives the user a true explainability contract instead of another pile of raw stage payloads. It also fits the current codebase: worker keeps producing raw findings, backend keeps owning canonical report shaping, and the endpoint remains backward-compatible.

## 6. Recommended Architecture

### 6.1 Design Principles

1. One endpoint, additive contract.
2. Raw stage outputs stay under `results`.
3. Canonical explainability lives under `explainability`.
4. Score reasoning lives under `risk.score_trace`.
5. Artifact lineage stays under the existing top-level `artifact_tree`, but each node gains explainability metadata.
6. Every reference is report-scoped and stable within the returned payload.
7. Every explainability entity must point back to an `artifact_id`.
8. Every meaningful uncertainty or coverage gap must be explicit.

### 6.2 Top-Level Report Shape

Recommended additive top-level contract:

```json
{
  "report_schema_version": "mswr-report-v2",
  "job_id": "job-root-1",
  "parent_job_id": null,
  "file": {
    "file_id": "file-1",
    "sha256": "1111",
    "mime": "application/zip",
    "size": 23104,
    "original_filename": "invoice.zip"
  },
  "verdict": "suspicious",
  "score": 73,
  "risk_level": "high",
  "risk": {
    "policy_version": "msrs-v1",
    "risk_score": 73,
    "risk_level": "high",
    "legacy_verdict": "suspicious",
    "malicious_gate_open": false,
    "high_gate_open": true,
    "independent_source_count": 3,
    "breakdown": {
      "local_score": 38,
      "inherited_score": 35,
      "synergy_bonus": 0,
      "dampener": 0,
      "final_score": 73
    },
    "evidence": [],
    "top_evidence": [],
    "descendant_summary": {},
    "score_trace": {
      "formula": "final = local + inherited + synergy - dampener, then apply gate caps and bounds",
      "components": [],
      "gates": {},
      "breakdown": {}
    }
  },
  "results": {
    "av_result": {"engine": "ClamAV", "infected": false, "threat_name": null},
    "yara_hits": [],
    "iocs": {
      "urls": [],
      "domains": [],
      "ips": [],
      "hashes": {"md5": "", "sha1": "", "sha256": "1111"}
    },
    "sandbox": {
      "executed": false,
      "behaviors": [],
      "network_connections": [],
      "is_mock": true
    }
  },
  "timings": {"total_ms": 781, "stages": []},
  "child_jobs": [],
  "artifact_tree": {
    "id": "art-1",
    "filename": "invoice.zip",
    "sha256": "1111",
    "size": 23104,
    "depth": 0,
    "children": []
  },
  "explainability": {
    "summary": {
      "headline": "One nested artifact drove the final suspicious verdict.",
      "primary_artifact_id": "art-2",
      "primary_artifact_path": "invoice.zip!/payload.js",
      "top_findings": [],
      "final_verdict_explainer": "The root archive is suspicious because a nested child artifact scored high and the tree rollup inherited that risk."
    },
    "artifacts": [],
    "findings": [],
    "evidence": [],
    "iocs": [],
    "decoded_strings": [],
    "uncertainties": [],
    "timeline": [],
    "failure_diagnostics": {
      "status": "none",
      "headline": "No blocking coverage gaps were detected.",
      "diagnostics": [],
      "suspected_miss_stages": []
    }
  },
  "created_at": "2026-04-11T12:00:00Z"
}
```

### 6.3 Canonical Entity Rules

The redesigned report uses seven canonical entity families:

1. artifact
2. finding
3. evidence
4. IOC
5. decoded string
6. uncertainty
7. diagnostic event

Every entity is report-scoped and referenced by a string ID:

1. `artifact_id`: persistent UUID when available; synthetic `root::<job_id>` for legacy or non-persisted roots
2. `finding_id`: `finding::<artifact_id>::<ordinal>`
3. `evidence_id`: keep current scoring IDs or promote them to stable report-scoped IDs
4. `ioc_id`: `ioc::<artifact_id>::<type>::<ordinal>`
5. `decoded_id`: `decoded::<artifact_id>::<ordinal>`
6. `uncertainty_id`: `uncertainty::<artifact_id>::<ordinal>`
7. `timeline_event_id`: `timeline::<ordinal>`
8. `diagnostic_id`: `diag::<artifact_id>::<stage>::<ordinal>`

### 6.4 Root Artifact Rule

This redesign requires a canonical root artifact for every report.

Rules:

1. New reports should persist a root artifact row for every job as early as possible in the pipeline.
2. If a stored report predates that behavior and no artifact row exists, backend synthesizes a virtual root artifact using `file`, `job_id`, and top-level verdict data.
3. `artifact_tree` must therefore never be `null` in explainability-aware responses. Legacy callers can still ignore it.

This is necessary because the first question in the target user experience is always: **which artifact was judged?**

### 6.5 Artifact Model

Recommended `explainability.artifacts[]` object:

```json
{
  "artifact_id": "art-2",
  "parent_artifact_id": "art-1",
  "root_artifact_id": "art-1",
  "job_id": "job-child-2",
  "filename": "payload.js",
  "sha256": "2222",
  "mime": "text/plain",
  "size": 8042,
  "verdict": "suspicious",
  "score": 73,
  "risk_level": "high",
  "lineage": {
    "depth": 1,
    "archive_layer": 1,
    "display_path": "invoice.zip!/payload.js",
    "origin_path": "payload.js",
    "container_chain": [
      {"artifact_id": "art-1", "filename": "invoice.zip", "relation": "root"},
      {"artifact_id": "art-2", "filename": "payload.js", "relation": "archive_member"}
    ]
  },
  "analysis": {
    "status": "complete",
    "primary_analyzer": "script",
    "stage_coverage": [
      {"stage": "file-type", "status": "ok"},
      {"stage": "deobfuscation", "status": "ok"},
      {"stage": "ioc-extract", "status": "ok"},
      {"stage": "format-analysis", "status": "ok"}
    ]
  },
  "finding_ids": ["finding::art-2::1"],
  "uncertainty_ids": ["uncertainty::art-2::1"]
}
```

Important behavior:

1. `archive_layer` counts archive containers only; it answers "which compression layer" directly.
2. `depth` keeps the generic lineage depth for non-archive artifacts too.
3. `display_path` is the main UI string for lineage rendering.

### 6.6 Finding Model

The UI should not force the user to read raw evidence lists. It needs grouped findings.

Recommended `explainability.findings[]` object:

```json
{
  "finding_id": "finding::art-2::1",
  "artifact_id": "art-2",
  "title": "Encoded PowerShell download-execute chain",
  "summary": "A nested script contains an encoded command, decoded execution payload, and outbound URL IOC.",
  "severity": "high",
  "confidence": "high",
  "kind": "script_execution_chain",
  "primary": true,
  "score_impact": 57,
  "found_by": [
    {"stage": "format-analysis", "analyzer": "script"},
    {"stage": "deobfuscation", "analyzer": null},
    {"stage": "ioc-extract", "analyzer": null}
  ],
  "evidence_ids": ["ev-4", "ev-5", "ev-6"],
  "ioc_ids": ["ioc::art-2::url::1"],
  "decoded_ids": ["decoded::art-2::1"],
  "uncertainty_ids": ["uncertainty::art-2::1"],
  "timeline_event_ids": ["timeline::7", "timeline::8", "timeline::9"]
}
```

Grouping rules:

1. A finding is centered on one artifact.
2. A finding groups evidence that points to the same behavioral theme.
3. Signature hits, exploit hits, and descendant inheritance should usually each create their own top-level finding.
4. Corroborating IOC and decoded string records attach to the nearest finding on the same artifact.

### 6.7 Evidence Model

The current `risk.evidence` contract should remain, but each entry should gain optional provenance and contribution fields.

Recommended additive serialized evidence shape:

```json
{
  "id": "ev-4",
  "source": "format-analysis",
  "stage": "format-analysis",
  "analyzer": "script",
  "kind": "script.encoded_command_execution",
  "tier": "strong",
  "severity": "high",
  "confidence": 0.91,
  "points": 45,
  "scope": "direct",
  "depth": 0,
  "artifact_id": "art-2",
  "related_artifact_id": null,
  "reason": "Encoded payload and execution primitives appear together",
  "raw": {
    "key": "script.encoded_command_execution",
    "summary": "Encoded payload and execution primitives appear together",
    "evidence": {
      "encoded_strings": ["JABXAGUAYgBDAGwAaQBlAG4AdAA="],
      "exec_operations": ["powershell", "iex"]
    }
  },
  "finding_ids": ["finding::art-2::1"],
  "ioc_ids": [],
  "decoded_ids": ["decoded::art-2::1"],
  "score_contribution": {
    "base_points": 45,
    "applied_points": 30,
    "cap_group": "heuristic_script",
    "cap_applied": true,
    "cap_reason": "heuristic_script family limit",
    "gate_effect": null
  }
}
```

Recommended rules:

1. `risk.evidence` and `risk.top_evidence` keep the current ordering semantics.
2. The richer canonical copy also appears under `explainability.evidence`.
3. Old reports can leave the additive fields empty.

### 6.8 IOC Model

IOC data should stop being only three top-level string arrays if the UI is expected to explain where each IOC came from.

Keep current compatibility field:

```json
"results": {
  "iocs": {
    "urls": [],
    "domains": [],
    "ips": [],
    "hashes": {"md5": "", "sha1": "", "sha256": ""}
  }
}
```

Add canonical IOC records:

```json
{
  "ioc_id": "ioc::art-2::url::1",
  "artifact_id": "art-2",
  "type": "url",
  "value": "https://cdn.bad.test/update",
  "source_stage": "deobfuscation",
  "source_kind": "decoded_candidate",
  "decoder": "powershell",
  "decoded_id": "decoded::art-2::1",
  "first_seen_in": "timeline::8",
  "finding_ids": ["finding::art-2::1"]
}
```

### 6.9 Decoded String Model

Recommended `explainability.decoded_strings[]` object:

```json
{
  "decoded_id": "decoded::art-2::1",
  "artifact_id": "art-2",
  "source_stage": "deobfuscation",
  "decoder": "powershell",
  "technique": "powershell_base64",
  "confidence": 0.93,
  "content_preview": "powershell -w hidden -enc SQBtAG0AYQBsAGkAYwBpAG8AdQBzAA==",
  "content_encoding": "utf-8",
  "content_truncated": true,
  "provenance": {
    "offset": 144,
    "length": 218,
    "key": null,
    "meta": {"command_style": "-enc"}
  },
  "ioc_ids": ["ioc::art-2::url::1"],
  "finding_ids": ["finding::art-2::1"]
}
```

### 6.10 Score Formation Model

The current `risk.breakdown` is necessary but insufficient. It explains totals, not why each total happened.

Recommended additive `risk.score_trace` shape:

```json
{
  "formula": "final = local + inherited + synergy - dampener, then apply gate caps and bounds",
  "components": [
    {
      "type": "evidence",
      "artifact_id": "art-2",
      "evidence_id": "ev-4",
      "label": "script.encoded_command_execution",
      "base_points": 45,
      "applied_points": 30,
      "reason": "heuristic_script cap limited the direct contribution"
    },
    {
      "type": "evidence",
      "artifact_id": "art-2",
      "evidence_id": "ev-5",
      "label": "deobfuscated_payload_execution",
      "base_points": 12,
      "applied_points": 12,
      "reason": "decoded execution payload remained within deob cap"
    },
    {
      "type": "synergy_bonus",
      "value": 10,
      "reason": "multiple independent strong or medium sources corroborated each other"
    }
  ],
  "gates": {
    "high_gate_open": true,
    "malicious_gate_open": false,
    "capped_by": "no_malicious_gate"
  },
  "breakdown": {
    "local_score": 63,
    "inherited_score": 0,
    "synergy_bonus": 10,
    "dampener": 0,
    "final_score": 73
  }
}
```

Tree-aware reports should also include descendant contribution components when relevant:

```json
{
  "type": "descendant_inheritance",
  "artifact_id": "art-1",
  "related_artifact_id": "art-3",
  "relative_depth": 1,
  "source_score": 95,
  "applied_points": 35,
  "reason": "direct malicious child artifact inherited into root report"
}
```

### 6.11 Uncertainty Model

Uncertainty is not the same as failure. The report needs both.

Recommended `explainability.uncertainties[]` object:

```json
{
  "uncertainty_id": "uncertainty::art-2::1",
  "artifact_id": "art-2",
  "kind": "heuristic_only_verdict",
  "severity": "medium",
  "direction": "possible_false_positive",
  "message": "This verdict is driven by heuristic and decoded-content evidence without a confirming signature or sandbox event.",
  "finding_ids": ["finding::art-2::1"]
}
```

Recommended uncertainty kinds:

1. `heuristic_only_verdict`
2. `decoded_content_truncated`
3. `parser_fallback_used`
4. `unsupported_inner_format`
5. `duplicate_descendant_skipped`
6. `partial_ioc_provenance`
7. `tree_inheritance_elevated_root`

### 6.12 Failure Diagnostics Model

Failure diagnostics answer: **if this report missed something, where likely failed or degraded?**

Recommended `explainability.failure_diagnostics` shape:

```json
{
  "status": "degraded",
  "headline": "One or more stages had partial coverage; the report may understate risk.",
  "diagnostics": [
    {
      "diagnostic_id": "diag::art-1::deobfuscation::1",
      "artifact_id": "art-1",
      "stage": "deobfuscation",
      "code": "candidate_cap_reached",
      "category": "coverage_gap",
      "severity": "medium",
      "likely_effect": "possible_false_negative",
      "confidence": "medium",
      "message": "Deobfuscation truncated additional candidates after reaching the configured cap.",
      "recommended_action": "re-run with a higher candidate cap or targeted decoder"
    }
  ],
  "suspected_miss_stages": [
    {
      "artifact_id": "art-1",
      "stage": "deobfuscation",
      "reason": "candidate cap reached before all decoded content was analyzed",
      "confidence": "medium"
    }
  ]
}
```

Recommended diagnostic codes for v1:

1. `password_attempts_exhausted`
2. `no_matching_analyzer`
3. `parser_error`
4. `stage_timeout`
5. `candidate_cap_reached`
6. `wall_time_reached`
7. `max_depth_reached`
8. `unsupported_format`
9. `extraction_failed`
10. `descendant_rollup_without_local_confirmation`

### 6.13 Timeline Model

The timeline is the second UI view the user asked for.

Recommended `explainability.timeline[]` object:

```json
{
  "timeline_event_id": "timeline::8",
  "seq": 8,
  "artifact_id": "art-2",
  "kind": "evidence_emitted",
  "stage": "deobfuscation",
  "analyzer": null,
  "status": "ok",
  "summary": "Deobfuscation decoded a PowerShell execution chain and extracted a URL IOC.",
  "refs": {
    "finding_ids": ["finding::art-2::1"],
    "evidence_ids": ["ev-5"],
    "ioc_ids": ["ioc::art-2::url::1"],
    "decoded_ids": ["decoded::art-2::1"]
  }
}
```

Recommended timeline event kinds:

1. `artifact_registered`
2. `stage_completed`
3. `artifact_extracted`
4. `evidence_emitted`
5. `ioc_extracted`
6. `decoded_string_extracted`
7. `score_adjusted`
8. `diagnostic_recorded`
9. `verdict_finalized`

For current data availability, `seq` is required. Wall-clock timestamps are optional and can be added for new reports.

### 6.14 Artifact Tree View

Keep the current top-level `artifact_tree`, but extend each node with:

1. `display_path`
2. `archive_layer`
3. `analysis_status`
4. `primary_analyzer`
5. `finding_ids`
6. `uncertainty_ids`
7. `diagnostic_ids`
8. `top_finding_titles`

Recommended node excerpt:

```json
{
  "id": "art-2",
  "filename": "payload.js",
  "sha256": "2222",
  "depth": 1,
  "origin_path": "payload.js",
  "verdict": "suspicious",
  "score": 73,
  "risk_level": "high",
  "display_path": "invoice.zip!/payload.js",
  "archive_layer": 1,
  "analysis_status": "complete",
  "primary_analyzer": "script",
  "finding_ids": ["finding::art-2::1"],
  "top_finding_titles": ["Encoded PowerShell download-execute chain"],
  "children": []
}
```

### 6.15 Top Findings Summary

Recommended `explainability.summary` shape:

```json
{
  "headline": "1 nested artifact drove the final suspicious verdict.",
  "primary_artifact_id": "art-2",
  "primary_artifact_path": "invoice.zip!/payload.js",
  "top_findings": [
    {
      "finding_id": "finding::art-2::1",
      "artifact_id": "art-2",
      "artifact_path": "invoice.zip!/payload.js",
      "archive_layer": 1,
      "title": "Encoded PowerShell download-execute chain",
      "score_impact": 57,
      "why_flagged": "script heuristic, decoded execution payload, and URL IOC converged on the same nested script"
    }
  ],
  "final_verdict_explainer": "The root archive is suspicious because a nested child artifact scored high and the tree rollup inherited that risk."
}
```

This is the main UI card group above the detailed sections.

## 7. Example JSON

The following is a valid condensed example for a nested archive case:

```json
{
  "report_schema_version": "mswr-report-v2",
  "job_id": "job-root-1",
  "parent_job_id": null,
  "file": {
    "file_id": "file-1",
    "sha256": "1111",
    "mime": "application/zip",
    "size": 23104,
    "original_filename": "invoice.zip"
  },
  "verdict": "suspicious",
  "score": 73,
  "risk_level": "high",
  "risk": {
    "policy_version": "msrs-v1",
    "risk_score": 73,
    "risk_level": "high",
    "legacy_verdict": "suspicious",
    "malicious_gate_open": false,
    "high_gate_open": true,
    "independent_source_count": 3,
    "breakdown": {
      "local_score": 38,
      "inherited_score": 35,
      "synergy_bonus": 0,
      "dampener": 0,
      "final_score": 73
    },
    "evidence": [
      {
        "id": "ev-1",
        "source": "format-analysis",
        "stage": "format-analysis",
        "analyzer": "script",
        "kind": "script.encoded_command_execution",
        "tier": "strong",
        "severity": "high",
        "confidence": 0.91,
        "points": 45,
        "scope": "direct",
        "depth": 0,
        "artifact_id": "art-2",
        "related_artifact_id": null,
        "reason": "Encoded payload and execution primitives appear together",
        "raw": {
          "key": "script.encoded_command_execution",
          "evidence": {
            "exec_operations": ["powershell", "iex"]
          }
        },
        "finding_ids": ["finding::art-2::1"],
        "ioc_ids": [],
        "decoded_ids": ["decoded::art-2::1"],
        "score_contribution": {
          "base_points": 45,
          "applied_points": 30,
          "cap_group": "heuristic_script",
          "cap_applied": true,
          "cap_reason": "heuristic_script family limit",
          "gate_effect": null
        }
      }
    ],
    "top_evidence": [],
    "descendant_summary": {
      "total_descendants": 1,
      "malicious_descendants": 1,
      "high_descendants": 0,
      "top_descendants": [
        {
          "artifact_id": "art-2",
          "sha256": "2222",
          "relative_depth": 1,
          "risk_level": "malicious",
          "risk_score": 95,
          "origin_path": "payload.js",
          "verdict": "malicious",
          "extraction_note": null,
          "inherited_points": 35
        }
      ]
    },
    "score_trace": {
      "formula": "final = local + inherited + synergy - dampener, then apply gate caps and bounds",
      "components": [
        {
          "type": "evidence",
          "artifact_id": "art-2",
          "evidence_id": "ev-1",
          "label": "script.encoded_command_execution",
          "base_points": 45,
          "applied_points": 30,
          "reason": "heuristic_script cap limited the direct contribution"
        },
        {
          "type": "descendant_inheritance",
          "artifact_id": "art-1",
          "related_artifact_id": "art-2",
          "relative_depth": 1,
          "source_score": 95,
          "applied_points": 35,
          "reason": "direct malicious child artifact inherited into root report"
        }
      ],
      "gates": {
        "high_gate_open": true,
        "malicious_gate_open": false,
        "capped_by": "no_malicious_gate"
      },
      "breakdown": {
        "local_score": 38,
        "inherited_score": 35,
        "synergy_bonus": 0,
        "dampener": 0,
        "final_score": 73
      }
    }
  },
  "results": {
    "av_result": {"engine": "ClamAV", "infected": false, "threat_name": null},
    "yara_hits": [],
    "iocs": {
      "urls": ["https://cdn.bad.test/update"],
      "domains": ["cdn.bad.test"],
      "ips": [],
      "hashes": {"md5": "", "sha1": "", "sha256": "1111"}
    },
    "format_analysis": {"analyzer": "script"},
    "deobfuscation": {"techniques_found": ["powershell_base64"]},
    "sandbox": {"executed": false, "behaviors": [], "network_connections": [], "is_mock": true},
    "archive_extract": {"archive_type": "zip", "extracted_count": 1, "sub_jobs_created": 1, "total_extracted_bytes": 8042, "malicious": false, "reason": null, "extraction_failed": false}
  },
  "timings": {
    "total_ms": 781,
    "stages": [
      {"name": "file-type", "status": "ok", "duration_ms": 3},
      {"name": "archive-extract", "status": "ok", "duration_ms": 21}
    ]
  },
  "child_jobs": [],
  "artifact_tree": {
    "id": "art-1",
    "filename": "invoice.zip",
    "sha256": "1111",
    "mime": "application/zip",
    "size": 23104,
    "depth": 0,
    "origin_path": null,
    "extraction_source": "upload",
    "archive_type": "zip",
    "extraction_note": null,
    "verdict": "suspicious",
    "score": 73,
    "risk_level": "high",
    "policy_version": "msrs-v1",
    "job_id": "job-root-1",
    "display_path": "invoice.zip",
    "archive_layer": 0,
    "analysis_status": "complete",
    "primary_analyzer": null,
    "finding_ids": [],
    "top_finding_titles": [],
    "children": [
      {
        "id": "art-2",
        "filename": "payload.js",
        "sha256": "2222",
        "mime": "text/plain",
        "size": 8042,
        "depth": 1,
        "origin_path": "payload.js",
        "extraction_source": "archive-extract",
        "archive_type": null,
        "extraction_note": null,
        "verdict": "malicious",
        "score": 95,
        "risk_level": "malicious",
        "policy_version": "msrs-v1",
        "job_id": "job-child-2",
        "display_path": "invoice.zip!/payload.js",
        "archive_layer": 1,
        "analysis_status": "complete",
        "primary_analyzer": "script",
        "finding_ids": ["finding::art-2::1"],
        "top_finding_titles": ["Encoded PowerShell download-execute chain"],
        "children": []
      }
    ]
  },
  "explainability": {
    "summary": {
      "headline": "One nested artifact drove the final suspicious verdict.",
      "primary_artifact_id": "art-2",
      "primary_artifact_path": "invoice.zip!/payload.js",
      "top_findings": [
        {
          "finding_id": "finding::art-2::1",
          "artifact_id": "art-2",
          "artifact_path": "invoice.zip!/payload.js",
          "archive_layer": 1,
          "title": "Encoded PowerShell download-execute chain",
          "score_impact": 57,
          "why_flagged": "script heuristic, decoded execution payload, and URL IOC converged on the same nested script"
        }
      ],
      "final_verdict_explainer": "The root archive is suspicious because a malicious child artifact was inherited into the final score."
    },
    "artifacts": [
      {
        "artifact_id": "art-1",
        "parent_artifact_id": null,
        "root_artifact_id": "art-1",
        "job_id": "job-root-1",
        "filename": "invoice.zip",
        "sha256": "1111",
        "mime": "application/zip",
        "size": 23104,
        "verdict": "suspicious",
        "score": 73,
        "risk_level": "high",
        "lineage": {"depth": 0, "archive_layer": 0, "display_path": "invoice.zip", "origin_path": null, "container_chain": [{"artifact_id": "art-1", "filename": "invoice.zip", "relation": "root"}]},
        "analysis": {"status": "complete", "primary_analyzer": null, "stage_coverage": [{"stage": "archive-extract", "status": "ok"}]},
        "finding_ids": [],
        "uncertainty_ids": ["uncertainty::art-1::1"]
      },
      {
        "artifact_id": "art-2",
        "parent_artifact_id": "art-1",
        "root_artifact_id": "art-1",
        "job_id": "job-child-2",
        "filename": "payload.js",
        "sha256": "2222",
        "mime": "text/plain",
        "size": 8042,
        "verdict": "malicious",
        "score": 95,
        "risk_level": "malicious",
        "lineage": {"depth": 1, "archive_layer": 1, "display_path": "invoice.zip!/payload.js", "origin_path": "payload.js", "container_chain": [{"artifact_id": "art-1", "filename": "invoice.zip", "relation": "root"}, {"artifact_id": "art-2", "filename": "payload.js", "relation": "archive_member"}]},
        "analysis": {"status": "complete", "primary_analyzer": "script", "stage_coverage": [{"stage": "deobfuscation", "status": "ok"}, {"stage": "ioc-extract", "status": "ok"}, {"stage": "format-analysis", "status": "ok"}]},
        "finding_ids": ["finding::art-2::1"],
        "uncertainty_ids": []
      }
    ],
    "findings": [
      {
        "finding_id": "finding::art-2::1",
        "artifact_id": "art-2",
        "title": "Encoded PowerShell download-execute chain",
        "summary": "A nested script contains an encoded command, decoded execution payload, and outbound URL IOC.",
        "severity": "high",
        "confidence": "high",
        "kind": "script_execution_chain",
        "primary": true,
        "score_impact": 57,
        "found_by": [{"stage": "format-analysis", "analyzer": "script"}, {"stage": "deobfuscation", "analyzer": null}, {"stage": "ioc-extract", "analyzer": null}],
        "evidence_ids": ["ev-1"],
        "ioc_ids": ["ioc::art-2::url::1"],
        "decoded_ids": ["decoded::art-2::1"],
        "uncertainty_ids": [],
        "timeline_event_ids": ["timeline::3", "timeline::4"]
      }
    ],
    "evidence": [],
    "iocs": [
      {
        "ioc_id": "ioc::art-2::url::1",
        "artifact_id": "art-2",
        "type": "url",
        "value": "https://cdn.bad.test/update",
        "source_stage": "deobfuscation",
        "source_kind": "decoded_candidate",
        "decoder": "powershell",
        "decoded_id": "decoded::art-2::1",
        "first_seen_in": "timeline::4",
        "finding_ids": ["finding::art-2::1"]
      }
    ],
    "decoded_strings": [
      {
        "decoded_id": "decoded::art-2::1",
        "artifact_id": "art-2",
        "source_stage": "deobfuscation",
        "decoder": "powershell",
        "technique": "powershell_base64",
        "confidence": 0.93,
        "content_preview": "powershell -w hidden -enc SQBtAG0AYQBsAGkAYwBpAG8AdQBzAA==",
        "content_encoding": "utf-8",
        "content_truncated": true,
        "provenance": {"offset": 144, "length": 218, "key": null, "meta": {"command_style": "-enc"}},
        "ioc_ids": ["ioc::art-2::url::1"],
        "finding_ids": ["finding::art-2::1"]
      }
    ],
    "uncertainties": [
      {
        "uncertainty_id": "uncertainty::art-1::1",
        "artifact_id": "art-1",
        "kind": "tree_inheritance_elevated_root",
        "severity": "low",
        "direction": "context_only",
        "message": "The root archive verdict is elevated by a child artifact; the outer archive itself may not be directly malicious.",
        "finding_ids": []
      }
    ],
    "timeline": [
      {
        "timeline_event_id": "timeline::1",
        "seq": 1,
        "artifact_id": "art-1",
        "kind": "artifact_registered",
        "stage": "upload",
        "analyzer": null,
        "status": "ok",
        "summary": "Root archive artifact registered.",
        "refs": {"finding_ids": [], "evidence_ids": [], "ioc_ids": [], "decoded_ids": []}
      },
      {
        "timeline_event_id": "timeline::3",
        "seq": 3,
        "artifact_id": "art-2",
        "kind": "evidence_emitted",
        "stage": "format-analysis",
        "analyzer": "script",
        "status": "ok",
        "summary": "Script analyzer emitted encoded command execution evidence.",
        "refs": {"finding_ids": ["finding::art-2::1"], "evidence_ids": ["ev-1"], "ioc_ids": [], "decoded_ids": ["decoded::art-2::1"]}
      },
      {
        "timeline_event_id": "timeline::4",
        "seq": 4,
        "artifact_id": "art-2",
        "kind": "ioc_extracted",
        "stage": "deobfuscation",
        "analyzer": null,
        "status": "ok",
        "summary": "Decoded candidate revealed a URL IOC.",
        "refs": {"finding_ids": ["finding::art-2::1"], "evidence_ids": [], "ioc_ids": ["ioc::art-2::url::1"], "decoded_ids": ["decoded::art-2::1"]}
      }
    ],
    "failure_diagnostics": {
      "status": "none",
      "headline": "No blocking coverage gaps were detected for the scored artifacts.",
      "diagnostics": [],
      "suspected_miss_stages": []
    }
  },
  "created_at": "2026-04-11T12:00:00Z"
}
```

## 8. Example Human-Readable Report

```text
Final verdict: suspicious (73/100, high)

Primary suspicious artifact
- payload.js
- Path: invoice.zip!/payload.js
- Compression layer: 1
- Artifact verdict: malicious (95/100)

Why it was flagged
1. The script analyzer found an encoded command execution pattern.
2. The deobfuscation stage decoded a PowerShell payload.
3. The decoded payload exposed an outbound URL IOC.

Which analyzer and stage found it
- format-analysis / script analyzer
- deobfuscation
- ioc-extract

Key extracted evidence
- Decoded string: "powershell -w hidden -enc SQBtAG0AYQBsAGkAYwBpAG8AdQBzAA=="
- IOC: https://cdn.bad.test/update

How the final score was formed
- +30 applied points from script.encoded_command_execution after heuristic_script cap
- +35 inherited points from direct malicious child artifact payload.js
- Final score: 73

Uncertainty
- The root archive itself is elevated by descendant inheritance; the outer archive is not necessarily directly malicious.

Failure diagnostics
- None. No stage timeout, parser failure, password block, or unsupported-format gap affected the scored path.
```

## 9. Five Case Examples

### Case 1: Root script file with decoded execution chain

Expected result:

1. `artifact_tree` has only the root artifact.
2. `summary.primary_artifact_id` points to the root.
3. `findings[0]` references a script analyzer finding plus decoded string and IOC.
4. `failure_diagnostics.status = "none"`.

Compact example:

```json
{
  "verdict": "suspicious",
  "score": 58,
  "explainability": {
    "summary": {
      "primary_artifact_path": "invoice.js",
      "top_findings": [
        {
          "title": "Encoded command with download URL",
          "artifact_path": "invoice.js",
          "archive_layer": 0
        }
      ]
    },
    "failure_diagnostics": {"status": "none"}
  }
}
```

### Case 2: Archive root elevated by malicious child payload

Expected result:

1. Root artifact remains the report root.
2. `summary.primary_artifact_id` points to the nested child, not the root archive.
3. `risk.score_trace.components` includes a `descendant_inheritance` component.
4. `uncertainties` includes `tree_inheritance_elevated_root` on the root artifact.

Compact example:

```json
{
  "verdict": "suspicious",
  "score": 73,
  "artifact_tree": {
    "filename": "bundle.zip",
    "children": [
      {
        "filename": "payload.exe",
        "risk_level": "malicious",
        "display_path": "bundle.zip!/payload.exe"
      }
    ]
  },
  "risk": {
    "score_trace": {
      "components": [
        {
          "type": "descendant_inheritance",
          "related_artifact_id": "art-payload",
          "applied_points": 35
        }
      ]
    }
  }
}
```

### Case 3: PDF with `/Launch` action and embedded executable

Expected result:

1. `findings` includes a PDF behavior finding and an embedded-resource finding.
2. `found_by` points to the PDF analyzer.
3. `artifact_tree` shows the extracted embedded executable as a child artifact.
4. `top_findings` shows both the structural PDF finding and the extracted child finding.

Compact example:

```json
{
  "verdict": "malicious",
  "score": 91,
  "explainability": {
    "summary": {
      "top_findings": [
        {"title": "PDF launch action targets executable", "artifact_path": "invoice.pdf"},
        {"title": "Embedded executable extracted from PDF", "artifact_path": "invoice.pdf!/embedded/payload.exe"}
      ]
    }
  }
}
```

### Case 4: Password-protected archive exhausted after three wrong attempts

Expected result:

1. Top-level compatibility fields remain `verdict = "unknown"`, `score = 0`, and `risk_level = "clean"`.
2. `failure_diagnostics.status = "blocked"`.
3. `diagnostics[0].code = "password_attempts_exhausted"`.
4. `suspected_miss_stages` points to `archive-extract`.
5. `summary.final_verdict_explainer` says the report only applies to outer-layer coverage.

Compact example:

```json
{
  "verdict": "unknown",
  "score": 0,
  "risk_level": "clean",
  "explainability": {
    "failure_diagnostics": {
      "status": "blocked",
      "diagnostics": [
        {
          "stage": "archive-extract",
          "code": "password_attempts_exhausted",
          "likely_effect": "possible_false_negative"
        }
      ],
      "suspected_miss_stages": [
        {"stage": "archive-extract", "confidence": "high"}
      ]
    }
  }
}
```

### Case 5: Apparent miss caused by unsupported inner format and deobfuscation truncation

Expected result:

1. The final verdict may still be `clean` or `low`.
2. `failure_diagnostics.status = "degraded"`.
3. Diagnostics explicitly say `no_matching_analyzer` for the inner artifact and `candidate_cap_reached` for deobfuscation.
4. `uncertainties` indicate the report may be a false negative because unsupported content was not fully analyzed.

Compact example:

```json
{
  "verdict": "clean",
  "score": 8,
  "explainability": {
    "uncertainties": [
      {
        "kind": "unsupported_inner_format",
        "direction": "possible_false_negative",
        "message": "An extracted child artifact had no matching analyzer."
      }
    ],
    "failure_diagnostics": {
      "status": "degraded",
      "diagnostics": [
        {"stage": "format-analysis", "code": "no_matching_analyzer"},
        {"stage": "deobfuscation", "code": "candidate_cap_reached"}
      ],
      "suspected_miss_stages": [
        {"stage": "format-analysis", "confidence": "high"},
        {"stage": "deobfuscation", "confidence": "medium"}
      ]
    }
  }
}
```

## 10. Backward Compatibility Strategy

### 10.1 Endpoint Compatibility

Keep `GET /api/v1/reports/{job_id}` unchanged.

Rules:

1. Do not remove or rename current top-level fields.
2. Do not change the existing 409 behavior while descendants are still running.
3. Do not remove or rename `results.archive_extract` keys currently used by the UI.

### 10.2 Field Compatibility

Preserve:

1. top-level `verdict`
2. top-level `score`
3. top-level `risk_level`
4. `risk.policy_version`
5. `risk.breakdown`
6. `risk.evidence` and `risk.top_evidence`
7. `results.*` raw stage outputs
8. `artifact_tree` current fields

Add only optional fields in v2:

1. top-level `report_schema_version`
2. `risk.score_trace`
3. additive provenance fields in `risk.evidence[]`
4. additive node metadata in `artifact_tree`
5. top-level `explainability`

### 10.3 Legacy Report Backfill

For old stored reports:

1. Reuse the existing `_ensure_report_risk_shape()` backfill path.
2. Add a second backfill step that creates an empty-but-valid `explainability` block.
3. If no persisted root artifact exists, synthesize a virtual root artifact from `file` metadata and top-level risk fields.
4. Leave unavailable provenance fields empty instead of inventing false precision.

### 10.4 Size Control

The explainability layer will be larger than the current report, so the contract should define caps and truncation flags.

Recommended caps:

1. top findings: 10
2. evidence list in summary contexts: 50, while canonical `risk.evidence` remains complete
3. timeline: 200 events by default
4. decoded strings: 20 previews
5. IOC records: 100 by default

If truncation occurs, set explicit flags inside `explainability` sections.

## 11. Recommended Implementation Boundaries

1. Worker remains responsible for raw stage outputs, artifact registration, and provenance seeds.
2. Scoring remains responsible for normalized evidence and score math.
3. Backend report shaping becomes responsible for:
   - artifact catalog assembly
   - finding grouping
   - score trace rendering
   - uncertainty synthesis
   - failure diagnostics synthesis
   - timeline assembly
4. Frontend remains responsible only for presentation, not provenance reconstruction.

## 12. Why This Design Fits MalScanWorker

This design matches the codebase that exists today:

1. It respects the current worker -> stored report -> backend rollup pipeline.
2. It keeps `results` as the raw compatibility contract.
3. It builds on the existing artifact tree instead of replacing it.
4. It uses the existing scoring engine and evidence model, then serializes them more completely.
5. It gives the frontend exactly the four UI views the user asked for:
   - top findings summary
   - artifact tree
   - evidence timeline
   - failure diagnostics

This is the smallest redesign that actually makes the report explainable.
