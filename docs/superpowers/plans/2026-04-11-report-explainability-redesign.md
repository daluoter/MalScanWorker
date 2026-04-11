# Report Explainability Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an additive explainability contract to `GET /api/v1/reports/{job_id}` so the report can identify the suspicious artifact, its archive layer, supporting evidence, analyzer, extracted IOC or decoded string, score formation, uncertainty, and likely miss stages without breaking existing consumers.

**Architecture:** Keep `results.*` as raw worker stage output and preserve the current compatibility fields, then add canonical explainability assembly in the backend. Persist or synthesize a canonical root artifact for every report, enrich scoring evidence with provenance and score-contribution details, extend `artifact_tree` nodes, and add frontend sections that render top findings, artifact tree, score trace, timeline, and failure diagnostics.

**Tech Stack:** Python 3.11, FastAPI, SQLAlchemy, existing worker pipeline/scoring code, React 18, TypeScript, Vite

**Spec:** `docs/superpowers/specs/2026-04-11-report-explainability-design.md`

---

## File Structure

### New files

| File | Responsibility |
|---|---|
| `backend/src/malscan/report_explainability.py` | Assemble canonical explainability block from stored report, artifact tree, and scoring data |
| `backend/tests/test_report_explainability.py` | Verify finding grouping, score trace, diagnostics, synthetic root behavior |
| `frontend/src/components/report/TopFindingsSummary.tsx` | Render top findings summary cards |
| `frontend/src/components/report/ArtifactTreePanel.tsx` | Render explainable artifact tree with layer/path badges |
| `frontend/src/components/report/ScoreTracePanel.tsx` | Render score-formation breakdown |
| `frontend/src/components/report/EvidenceTimelinePanel.tsx` | Render timeline view |
| `frontend/src/components/report/FailureDiagnosticsPanel.tsx` | Render uncertainty and diagnostics section |

### Modified files

| File | Change |
|---|---|
| `worker/src/malscan_worker/pipeline.py` | Ensure canonical root artifact context and serialize richer risk/timing explainability seeds |
| `worker/src/malscan_worker/reporting.py` | Add empty explainability block for password-exhausted reports |
| `worker/src/malscan_worker/db.py` | Add helper to ensure or create root artifact rows for all jobs |
| `worker/src/malscan_worker/stages/ioc_extract.py` | Emit structured IOC items with first-seen offsets and stable IDs |
| `worker/src/malscan_worker/stages/deobfuscation.py` | Emit stable decoded-candidate IDs and richer provenance for explainability |
| `worker/src/malscan_worker/stages/format_analysis.py` | Preserve analyzer name and extracted artifact refs needed by findings |
| `backend/src/malscan/scoring/models.py` | Add provenance and contribution fields for serialized evidence and score trace helpers |
| `backend/src/malscan/scoring/adapters.py` | Attach artifact/stage/analyzer/confidence metadata to evidence records |
| `backend/src/malscan/scoring/engine.py` | Return score-contribution and gate-cap details for explainability |
| `backend/src/malscan/scoring/tree.py` | Emit descendant-inheritance contribution details |
| `backend/src/malscan/schemas/requests.py` | Add explainability response models and additive evidence fields |
| `backend/src/malscan/api/routes.py` | Backfill explainability block, guarantee synthetic root, and route report assembly through explainability helper |
| `backend/tests/test_api.py` | Verify endpoint compatibility and explainability backfill |
| `backend/tests/test_scoring_adapters.py` | Verify evidence provenance serialization |
| `backend/tests/test_scoring_engine.py` | Verify score trace and gate-cap rendering |
| `worker/tests/test_pipeline.py` | Verify worker report contains explainability seeds without breaking current fields |
| `worker/tests/test_password_flow.py` | Verify password-exhausted reports expose blocked diagnostics |
| `worker/tests/test_artifact_tree.py` | Verify canonical root artifact behavior and lineage expectations |
| `frontend/src/api/types.ts` | Add explainability-aware response types |
| `frontend/src/pages/ReportPage.tsx` | Render new explainability sections while preserving legacy sections |
| `README.en.md` | Document explainability report contract and compatibility behavior |

---

## Task 1: Add canonical response schema and compatibility defaults

**Files:**
- Create: `backend/tests/test_report_explainability.py`
- Modify: `backend/src/malscan/schemas/requests.py`
- Modify: `backend/src/malscan/api/routes.py`
- Modify: `frontend/src/api/types.ts`
- Test: `backend/tests/test_api.py`

- [ ] **Step 1: Write failing schema/backfill tests**

Add tests that assert:

```python
def test_get_report_adds_report_schema_version_and_empty_explainability(
    client: TestClient, mock_db_session: AsyncMock
):
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
            "iocs": {
                "urls": [],
                "domains": [],
                "ips": [],
                "hashes": {"md5": "", "sha1": "", "sha256": "abc123"},
            },
            "sandbox": {
                "executed": False,
                "behaviors": [],
                "network_connections": [],
                "is_mock": True,
            },
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
    data = response.json()

    assert response.status_code == 200
    assert data["report_schema_version"] == "mswr-report-v2"
    assert data["explainability"]["summary"]["top_findings"] == []
    assert data["explainability"]["failure_diagnostics"]["status"] in {"none", "degraded", "blocked"}


def test_get_report_legacy_report_without_artifact_tree_gets_synthetic_root(
    client: TestClient, mock_db_session: AsyncMock
):
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
            "original_filename": "legacy.bin",
        },
        "verdict": "clean",
        "score": 0,
        "results": {
            "av_result": {"engine": "clamav", "infected": False, "threat_name": None},
            "yara_hits": [],
            "iocs": {
                "urls": [],
                "domains": [],
                "ips": [],
                "hashes": {"md5": "", "sha1": "", "sha256": "abc123"},
            },
            "sandbox": {
                "executed": False,
                "behaviors": [],
                "network_connections": [],
                "is_mock": True,
            },
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
    data = response.json()

    assert response.status_code == 200
    assert data["artifact_tree"] is not None
    assert data["artifact_tree"]["filename"] == "legacy.bin"
    assert data["artifact_tree"]["display_path"] == "legacy.bin"
```

- [ ] **Step 2: Run tests to verify they fail**

Run in `backend/`:

```bash
poetry run pytest tests/test_api.py -k "explainability or synthetic_root or risk_block" -v
```

Expected: failures because the report schema and backfill logic do not include the new fields yet.

- [ ] **Step 3: Extend backend response models additively**

Add new Pydantic models in `backend/src/malscan/schemas/requests.py` for:

```python
class ScoreContribution(BaseModel):
    type: str
    artifact_id: str | None = None
    related_artifact_id: str | None = None
    evidence_id: str | None = None
    label: str | None = None
    base_points: int | None = None
    applied_points: int | None = None
    relative_depth: int | None = None
    source_score: int | None = None
    reason: str


class ScoreTrace(BaseModel):
    formula: str
    components: list[ScoreContribution] = Field(default_factory=list)
    gates: dict[str, Any] = Field(default_factory=dict)
    breakdown: dict[str, Any] = Field(default_factory=dict)
```

Also add:

```python
class ExplainabilitySummary(BaseModel):
    headline: str = ""
    primary_artifact_id: str | None = None
    primary_artifact_path: str | None = None
    top_findings: list[dict[str, Any]] = Field(default_factory=list)
    final_verdict_explainer: str = ""


class ExplainabilityBlock(BaseModel):
    summary: ExplainabilitySummary = Field(default_factory=ExplainabilitySummary)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    decoded_strings: list[dict[str, Any]] = Field(default_factory=list)
    uncertainties: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    failure_diagnostics: dict[str, Any] = Field(default_factory=dict)
```

Wire them into `RiskSummary` and `ReportResponse`:

```python
class RiskSummary(BaseModel):
    policy_version: str
    risk_score: int
    risk_level: str
    legacy_verdict: str
    malicious_gate_open: bool
    high_gate_open: bool
    independent_source_count: int
    breakdown: RiskBreakdown
    evidence: list[RiskEvidence] = Field(default_factory=list)
    top_evidence: list[RiskEvidence] = Field(default_factory=list)
    descendant_summary: dict[str, Any] = Field(default_factory=dict)
    score_trace: dict[str, Any] = Field(default_factory=dict)


class ReportResponse(BaseModel):
    job_id: str
    parent_job_id: str | None = None
    file: FileMetadata
    verdict: str
    score: int
    risk_level: str
    risk: RiskSummary
    results: AnalysisResults
    timings: Timings
    created_at: datetime
    child_jobs: list[ChildJobSummary] = Field(default_factory=list)
    artifact_tree: ArtifactTreeNode | None = None
    report_schema_version: str = "mswr-report-v2"
    explainability: ExplainabilityBlock = Field(default_factory=ExplainabilityBlock)
```

- [ ] **Step 4: Add compatibility backfill entry points**

In `backend/src/malscan/api/routes.py`, add helpers that guarantee:

```python
def _empty_explainability() -> dict[str, Any]:
    return {
        "summary": {
            "headline": "",
            "primary_artifact_id": None,
            "primary_artifact_path": None,
            "top_findings": [],
            "final_verdict_explainer": "",
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
            "headline": "",
            "diagnostics": [],
            "suspected_miss_stages": [],
        },
    }


def _ensure_report_explainability_shape(report: dict[str, Any]) -> dict[str, Any]:
    report["report_schema_version"] = str(report.get("report_schema_version") or "mswr-report-v2")
    if not isinstance(report.get("explainability"), dict):
        report["explainability"] = _empty_explainability()
    return report
```

- [ ] **Step 5: Update frontend types additively**

Extend `frontend/src/api/types.ts` with optional explainability-aware types first, without changing existing legacy fields. The key change is that `Report` must accept:

```ts
report_schema_version?: string
risk_level?: string
risk?: {
  policy_version: string
  risk_score: number
  risk_level: string
  legacy_verdict: string
  malicious_gate_open: boolean
  high_gate_open: boolean
  independent_source_count: number
  breakdown: {
    local_score: number
    inherited_score: number
    synergy_bonus: number
    dampener: number
    final_score: number
  }
  evidence: Array<Record<string, unknown>>
  top_evidence: Array<Record<string, unknown>>
  descendant_summary: Record<string, unknown>
  score_trace?: Record<string, unknown>
}
artifact_tree?: Record<string, unknown> | null
explainability?: {
  summary: {
    headline: string
    primary_artifact_id?: string | null
    primary_artifact_path?: string | null
    top_findings: Array<Record<string, unknown>>
    final_verdict_explainer: string
  }
  artifacts: Array<Record<string, unknown>>
  findings: Array<Record<string, unknown>>
  evidence: Array<Record<string, unknown>>
  iocs: Array<Record<string, unknown>>
  decoded_strings: Array<Record<string, unknown>>
  uncertainties: Array<Record<string, unknown>>
  timeline: Array<Record<string, unknown>>
  failure_diagnostics: Record<string, unknown>
}
```

- [ ] **Step 6: Run backend tests again**

Run in `backend/`:

```bash
poetry run pytest tests/test_api.py -k "explainability or synthetic_root or risk_block" -v
```

Expected: tests still fail on assembly behavior, but schema parsing and additive backfill errors should be resolved.

---

## Task 2: Guarantee a canonical root artifact for every report

**Files:**
- Modify: `worker/src/malscan_worker/db.py`
- Modify: `worker/src/malscan_worker/pipeline.py`
- Modify: `worker/tests/test_pipeline.py`
- Modify: `worker/tests/test_artifact_tree.py`

- [ ] **Step 1: Write failing worker tests**

Add tests that assert a root artifact context exists even when no archive or extracted child artifact is created:

```python
@pytest.mark.asyncio
async def test_ensure_root_artifact_returns_existing_artifact_id():
    result = await ensure_root_artifact(
        job_id="job-1",
        root_job_id="job-1",
        sha256="a" * 64,
        size=10,
        original_filename="sample.bin",
        existing_artifact_id="artifact-1",
    )
    assert result == {"id": "artifact-1", "root_id": "artifact-1"}


@pytest.mark.asyncio
async def test_run_pipeline_ensures_root_artifact_context_before_stage_execution(
    mocker, tmp_path
):
    from malscan_worker.pipeline import run_pipeline

    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"sample content")
    captured: dict[str, str | None] = {}

    class CaptureStage(MockStage):
        async def execute(self, ctx):
            captured["artifact_id"] = ctx.artifact_id
            captured["root_artifact_id"] = ctx.root_artifact_id
            return await super().execute(ctx)

    mocker.patch(
        "malscan_worker.pipeline.download_file",
        new_callable=AsyncMock,
        return_value=test_file,
    )
    mocker.patch("malscan_worker.pipeline.update_job_status", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.update_job_stage", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.update_job_result", new_callable=AsyncMock)
    mocker.patch(
        "malscan_worker.pipeline.get_job_for_context",
        new_callable=AsyncMock,
        return_value=None,
    )
    mocker.patch(
        "malscan_worker.pipeline.ensure_root_artifact",
        new_callable=AsyncMock,
        return_value={"id": "artifact-root-1", "root_id": "artifact-root-1"},
    )
    mocker.patch("malscan_worker.pipeline.stage_latency")
    mocker.patch("malscan_worker.pipeline.PARALLEL_STAGES", [CaptureStage("stage1")])
    mocker.patch("malscan_worker.pipeline.FORMAT_ANALYSIS_STAGE", MockStage("format-analysis"))
    mocker.patch("malscan_worker.pipeline.SEQUENTIAL_STAGES", [])

    await run_pipeline(
        {
            "job_id": str(uuid.uuid4()),
            "file_id": str(uuid.uuid4()),
            "storage_key": "test-key",
            "sha256": "a" * 64,
            "original_filename": "sample.bin",
        }
    )

    assert captured["artifact_id"] == "artifact-root-1"
    assert captured["root_artifact_id"] == "artifact-root-1"
```

- [ ] **Step 2: Run worker tests to verify they fail**

Run in `worker/`:

```bash
poetry run pytest tests/test_pipeline.py tests/test_artifact_tree.py -v
```

Expected: failure because root artifact context is not guaranteed today.

- [ ] **Step 3: Add root-artifact helper in worker DB layer**

Add a helper in `worker/src/malscan_worker/db.py`:

```python
async def ensure_root_artifact(
    *,
    job_id: str,
    root_job_id: str,
    sha256: str,
    size: int,
    original_filename: str,
    existing_artifact_id: str | None,
) -> dict[str, str]:
    if existing_artifact_id:
        return {"id": existing_artifact_id, "root_id": existing_artifact_id}

    record = await create_artifact(
        parent_id=None,
        root_id=None,
        depth=0,
        sha256=sha256,
        size=size,
        original_filename=original_filename,
        extraction_source="upload",
        archive_type=None,
        job_id=job_id,
        root_job_id=root_job_id,
    )
    return {"id": record["id"], "root_id": record["id"]}
```

- [ ] **Step 4: Call the helper in the pipeline before stages run**

In `worker/src/malscan_worker/pipeline.py`, after file download and context creation, add:

```python
root_art = await ensure_root_artifact(
    job_id=job_id,
    root_job_id=ctx.root_job_id or job_id,
    sha256=ctx.sha256,
    size=file_path.stat().st_size,
    original_filename=ctx.original_filename,
    existing_artifact_id=ctx.root_artifact_id or ctx.artifact_id,
)
ctx.root_artifact_id = root_art["root_id"]
ctx.artifact_id = ctx.artifact_id or root_art["id"]
```

- [ ] **Step 5: Re-run worker tests**

Run in `worker/`:

```bash
poetry run pytest tests/test_pipeline.py tests/test_artifact_tree.py -v
```

Expected: new root-artifact expectations pass.

---

## Task 3: Emit explainability seeds from worker stages

**Files:**
- Modify: `worker/src/malscan_worker/stages/ioc_extract.py`
- Modify: `worker/src/malscan_worker/stages/deobfuscation.py`
- Modify: `worker/src/malscan_worker/stages/format_analysis.py`
- Modify: `worker/src/malscan_worker/pipeline.py`
- Modify: `worker/tests/test_pipeline.py`

- [ ] **Step 1: Write failing tests for structured IOC and decoded candidate IDs**

Add tests like:

```python
def test_extract_raw_ioc_items_returns_offsets_and_stable_ids() -> None:
    items = extract_raw_ioc_items(
        b"curl https://a.test/update and connect to 1.2.3.4",
        artifact_ref="artifact-1",
    )
    assert items[0]["ioc_id"] == "ioc::artifact-1::url::1"
    assert items[0]["offset"] == 5
    assert items[0]["source_stage"] == "ioc-extract"


def test_candidate_to_dict_adds_stable_decoded_id() -> None:
    candidate = DeobfuscationCandidate(
        content=b"powershell -w hidden -enc SQBtAG0AYQBsAGkAYwBpAG8AdQBzAA==",
        provenance=CandidateProvenance(decoder="powershell", offset=12, length=40),
        confidence=0.9,
        technique="powershell_base64",
    )
    result = DeobfuscationStage._candidate_to_dict(
        candidate,
        artifact_ref="artifact-1",
        index=0,
        max_candidate_bytes=4096,
    )
    assert result["decoded_id"] == "decoded::artifact-1::1"
    assert result["source_stage"] == "deobfuscation"
```

- [ ] **Step 2: Run the targeted worker tests**

Run in `worker/`:

```bash
poetry run pytest tests/test_deobfuscation_pipeline_integration.py tests/test_pipeline.py -v
```

Expected: failures because those structured fields do not exist yet.

- [ ] **Step 3: Keep raw compatibility fields, but add structured arrays**

In `ioc_extract.py`, keep `urls`, `domains`, and `ips`, but also add `ioc_items`:

```python
{
    "urls": urls,
    "domains": domains,
    "ips": ips,
    "ioc_items": [
        {
            "ioc_id": f"ioc::{ctx.artifact_id or ctx.job_id}::url::{idx + 1}",
            "type": "url",
            "value": url,
            "offset": match_start,
            "source_stage": "ioc-extract",
            "source_kind": "raw_regex",
        }
        for idx, (url, match_start) in enumerate(url_matches)
    ],
}
```

In `deobfuscation.py`, add stable decoded IDs:

```python
candidate_dict["decoded_id"] = f"decoded::{artifact_ref}::{index + 1}"
candidate_dict["source_stage"] = "deobfuscation"
```

- [ ] **Step 4: Expose stage timing seeds for the future timeline**

In `worker/src/malscan_worker/pipeline.py`, extend `timings.stages` entries with optional started/ended timestamps:

```python
{
    "name": r.stage_name,
    "status": r.status,
    "duration_ms": r.duration_ms,
    "started_at": r.started_at.isoformat(),
    "ended_at": r.ended_at.isoformat(),
}
```

This is additive and will let backend build a better timeline.

- [ ] **Step 5: Re-run worker tests**

Run in `worker/`:

```bash
poetry run pytest tests/test_pipeline.py tests/test_deobfuscation_pipeline_integration.py -v
```

Expected: new structured seed fields are present while old fields remain intact.

---

## Task 4: Enrich scoring evidence and score-trace output

**Files:**
- Modify: `backend/src/malscan/scoring/models.py`
- Modify: `backend/src/malscan/scoring/adapters.py`
- Modify: `backend/src/malscan/scoring/engine.py`
- Modify: `backend/src/malscan/scoring/tree.py`
- Modify: `backend/tests/test_scoring_adapters.py`
- Modify: `backend/tests/test_scoring_engine.py`

- [ ] **Step 1: Write failing scoring tests**

Add targeted tests that assert:

```python
def test_build_direct_evidence_preserves_artifact_and_analyzer_provenance() -> None:
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "format-analysis": {
                "analyzer": "script",
                "heuristics": [
                    {
                        "key": "script.encoded_command_execution",
                        "category": "script_token",
                        "scope": "script",
                        "role": "gate_signal",
                        "severity": "high",
                        "confidence": 0.9,
                        "summary": "Encoded payload and execution primitives appear together",
                        "evidence": {"exec_operations": ["powershell", "iex"]},
                    }
                ],
            }
        },
    )
    record = next(item for item in records if item.kind == "script.encoded_command_execution")
    assert record.artifact_id == "artifact-1"
    assert record.stage == "format-analysis"
    assert record.analyzer == "script"


def test_score_direct_evidence_returns_score_trace_components():
    records = build_direct_evidence(
        artifact_id="artifact-1",
        stage_findings={
            "format-analysis": {
                "analyzer": "script",
                "heuristics": [
                    {
                        "key": "script.encoded_command_execution",
                        "category": "script_token",
                        "scope": "script",
                        "role": "gate_signal",
                        "severity": "high",
                        "confidence": 0.9,
                        "summary": "Encoded payload and execution primitives appear together",
                        "evidence": {"exec_operations": ["powershell", "iex"]},
                    }
                ],
            }
        },
    )
    decision = score_direct_evidence(direct_evidence=records)
    assert decision.score_trace["components"][0]["type"] == "evidence"
    assert decision.score_trace["components"][0]["artifact_id"] == "artifact-1"


def test_merge_with_descendants_returns_descendant_inheritance_components():
    local = RiskDecision(
        risk_score=20,
        risk_level="low",
        legacy_verdict="suspicious",
        evidence=[],
        top_evidence=[],
        breakdown=ScoreBreakdown(local_score=20, inherited_score=0, synergy_bonus=0, dampener=0, final_score=20),
        score_trace={"formula": "", "components": [], "gates": {}, "breakdown": {}},
    )
    final = merge_with_descendants(
        local=local,
        descendants=[
            {
                "artifact_id": "artifact-child-1",
                "sha256": "b" * 64,
                "relative_depth": 1,
                "risk_level": "malicious",
                "risk_score": 95,
                "origin_path": "payload.exe",
                "verdict": "malicious",
                "extraction_note": None,
            }
        ],
    )
    assert final.score_trace["components"][-1]["type"] == "descendant_inheritance"
```

- [ ] **Step 2: Run scoring tests to verify they fail**

Run in `backend/`:

```bash
poetry run pytest tests/test_scoring_adapters.py tests/test_scoring_engine.py -v
```

Expected: failures because current scoring decisions do not expose score-trace structures.

- [ ] **Step 3: Extend scoring dataclasses minimally**

In `backend/src/malscan/scoring/models.py`, extend `EvidenceRecord` and `RiskDecision`:

```python
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
    stage: str | None = None
    analyzer: str | None = None
    score_contribution: dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskDecision:
    risk_score: int
    risk_level: str
    legacy_verdict: str
    evidence: list[EvidenceRecord]
    top_evidence: list[EvidenceRecord]
    breakdown: ScoreBreakdown
    descendant_summary: dict[str, Any] = field(default_factory=dict)
    policy_version: str = POLICY_VERSION
    score_trace: dict[str, Any] = field(default_factory=dict)
```

- [ ] **Step 4: Attach provenance inside adapters**

In `adapters.py`, update `_append()` so each call can pass `stage`, `analyzer`, and a default contribution skeleton:

```python
def _append(records: list[EvidenceRecord], **kwargs: Any) -> None:
    records.append(
        EvidenceRecord(
            evidence_id=f"ev-{len(records) + 1}",
            scope="direct",
            related_artifact_id=None,
            depth=0,
            tags=(),
            score_contribution={},
            **kwargs,
        )
    )
```

For format-analysis evidence, pass analyzer provenance from `finding.get("analyzer")`.

- [ ] **Step 5: Build score-trace components in the scoring engine**

In `engine.py`, compute a `components` list while scoring evidence:

```python
components.append(
    {
        "type": "evidence",
        "artifact_id": ev.artifact_id,
        "evidence_id": ev.evidence_id,
        "label": ev.kind,
        "base_points": ev.points,
        "applied_points": effective_points,
        "reason": contribution_reason,
    }
)
```

Return:

```python
score_trace={
    "formula": "final = local + inherited + synergy - dampener, then apply gate caps and bounds",
    "components": components,
    "gates": {
        "high_gate_open": high_gate_open,
        "malicious_gate_open": malicious_gate_open,
        "capped_by": capped_by,
    },
    "breakdown": {
        "local_score": local_score,
        "inherited_score": 0,
        "synergy_bonus": synergy_bonus,
        "dampener": 0,
        "final_score": score,
    },
}
```

- [ ] **Step 6: Add descendant-inheritance components in `tree.py`**

When descendant scores are merged, append:

```python
{
    "type": "descendant_inheritance",
    "artifact_id": local_root_artifact_id,
    "related_artifact_id": child_artifact_id,
    "relative_depth": depth,
    "source_score": child_score,
    "applied_points": inherited_points,
    "reason": "direct malicious child artifact inherited into root report",
}
```

- [ ] **Step 7: Re-run scoring tests**

Run in `backend/`:

```bash
poetry run pytest tests/test_scoring_adapters.py tests/test_scoring_engine.py -v
```

Expected: provenance and score-trace expectations pass.

---

## Task 5: Assemble the canonical explainability block in the backend

**Files:**
- Create: `backend/src/malscan/report_explainability.py`
- Create: `backend/tests/test_report_explainability.py`
- Modify: `backend/src/malscan/api/routes.py`

- [ ] **Step 1: Write failing assembly tests**

Add tests that assert the backend helper can:

```python
def test_build_explainability_summary_picks_primary_artifact_and_top_finding():
    report = {
        "job_id": "job-root-1",
        "file": {
            "file_id": "file-1",
            "sha256": "1111",
            "mime": "application/zip",
            "size": 23104,
            "original_filename": "bundle.zip",
        },
        "verdict": "suspicious",
        "score": 73,
        "risk_level": "high",
        "risk": {
            "risk_score": 73,
            "risk_level": "high",
            "legacy_verdict": "suspicious",
            "breakdown": {"local_score": 38, "inherited_score": 35, "synergy_bonus": 0, "dampener": 0, "final_score": 73},
            "evidence": [
                {
                    "id": "ev-1",
                    "artifact_id": "art-2",
                    "source": "format-analysis",
                    "stage": "format-analysis",
                    "analyzer": "script",
                    "kind": "script.encoded_command_execution",
                    "reason": "Encoded payload and execution primitives appear together",
                    "score_contribution": {"applied_points": 30},
                }
            ],
            "score_trace": {"components": [{"type": "descendant_inheritance", "related_artifact_id": "art-2", "applied_points": 35, "reason": "direct malicious child artifact inherited into root report"}]},
        },
        "results": {
            "iocs": {"urls": [], "domains": [], "ips": [], "hashes": {"md5": "", "sha1": "", "sha256": "1111"}},
            "sandbox": {"executed": False, "behaviors": [], "network_connections": [], "is_mock": True},
        },
    }
    artifact_tree = {
        "id": "art-1",
        "filename": "bundle.zip",
        "sha256": "1111",
        "depth": 0,
        "score": 73,
        "risk_level": "high",
        "children": [
            {
                "id": "art-2",
                "filename": "payload.js",
                "sha256": "2222",
                "origin_path": "payload.js",
                "depth": 1,
                "score": 95,
                "risk_level": "malicious",
                "children": [],
            }
        ],
    }
    explainability = build_explainability(report=report, artifact_tree=artifact_tree)
    assert explainability["summary"]["primary_artifact_id"] == "art-2"
    assert explainability["summary"]["top_findings"][0]["artifact_path"] == "bundle.zip!/payload.js"


def test_build_explainability_diagnostics_marks_password_blocked():
    report = build_password_attempts_exhausted_report(
        {
            "job_id": "job-root-1",
            "file_id": "file-1",
            "sha256": "1111",
            "original_filename": "secret.zip",
        }
    )
    explainability = build_explainability(
        report=report,
        artifact_tree=ensure_artifact_tree_root(report, None),
    )
    assert explainability["failure_diagnostics"]["status"] == "blocked"


def test_build_explainability_timeline_links_iocs_and_decoded_strings():
    report = {
        "job_id": "job-root-1",
        "file": {
            "file_id": "file-1",
            "sha256": "1111",
            "mime": "text/plain",
            "size": 120,
            "original_filename": "payload.ps1",
        },
        "verdict": "suspicious",
        "score": 58,
        "risk_level": "medium",
        "risk": {
            "risk_score": 58,
            "risk_level": "medium",
            "legacy_verdict": "suspicious",
            "breakdown": {"local_score": 58, "inherited_score": 0, "synergy_bonus": 0, "dampener": 0, "final_score": 58},
            "evidence": [],
            "score_trace": {"components": []},
        },
        "results": {
            "deobfuscation": {
                "candidates": [
                    {
                        "decoded_id": "decoded::art-2::1",
                        "source_stage": "deobfuscation",
                        "technique": "powershell_base64",
                        "content": "powershell -w hidden -enc SQBtAG0AYQBsAGkAYwBpAG8AdQBzAA==",
                        "content_encoding": "utf-8",
                        "content_truncated": False,
                        "confidence": 0.93,
                        "provenance": {"decoder": "powershell", "offset": 12, "length": 40, "key": None, "meta": {}},
                    }
                ],
                "extracted_iocs": {"urls": ["https://a.test/update"], "domains": [], "ips": []},
            },
            "iocs": {"urls": ["https://a.test/update"], "domains": [], "ips": [], "hashes": {"md5": "", "sha1": "", "sha256": "1111"}},
            "sandbox": {"executed": False, "behaviors": [], "network_connections": [], "is_mock": True},
        },
    }
    artifact_tree = {"id": "art-2", "filename": "payload.ps1", "sha256": "1111", "depth": 0, "children": []}
    explainability = build_explainability(report=report, artifact_tree=artifact_tree)
    assert explainability["timeline"][0]["refs"]["ioc_ids"] == ["ioc::art-2::url::1"]
```

- [ ] **Step 2: Run the new backend tests**

Run in `backend/`:

```bash
poetry run pytest tests/test_report_explainability.py -v
```

Expected: import failure because the helper module does not exist yet.

- [ ] **Step 3: Create a focused assembly helper module**

Create `backend/src/malscan/report_explainability.py` with a small public surface:

```python
def build_explainability(
    *,
    report: dict[str, Any],
    artifact_tree: dict[str, Any] | None,
) -> dict[str, Any]:
    tree = ensure_artifact_tree_root(report, artifact_tree)
    artifacts = _flatten_artifacts(tree)
    findings = _build_finding_groups(report, artifacts)
    iocs = _build_ioc_records(report, findings)
    decoded = _build_decoded_records(report, findings)
    uncertainties = _build_uncertainties(report, artifacts)
    diagnostics = _build_failure_diagnostics(report, artifacts)
    timeline = _build_timeline(report, findings, iocs, decoded)
    return {
        "summary": _build_summary(report, artifacts, findings),
        "artifacts": artifacts,
        "findings": findings,
        "evidence": list(report.get("risk", {}).get("evidence", [])),
        "iocs": iocs,
        "decoded_strings": decoded,
        "uncertainties": uncertainties,
        "timeline": timeline,
        "failure_diagnostics": diagnostics,
    }


def ensure_artifact_tree_root(report: dict[str, Any], artifact_tree: dict[str, Any] | None) -> dict[str, Any]:
    if artifact_tree is not None:
        return artifact_tree

    file_info = report["file"]
    return {
        "id": f"root::{report['job_id']}",
        "filename": file_info["original_filename"],
        "sha256": file_info["sha256"],
        "mime": file_info.get("mime"),
        "size": file_info.get("size", 0),
        "depth": 0,
        "origin_path": None,
        "extraction_source": "upload",
        "archive_type": None,
        "extraction_note": None,
        "verdict": report.get("verdict"),
        "score": report.get("score"),
        "risk_level": report.get("risk_level"),
        "policy_version": report.get("risk", {}).get("policy_version"),
        "job_id": report["job_id"],
        "display_path": file_info["original_filename"],
        "archive_layer": 0,
        "analysis_status": "complete",
        "primary_analyzer": None,
        "finding_ids": [],
        "top_finding_titles": [],
        "children": [],
    }
```

Internal helpers should be narrow and deterministic:

```python
def _flatten_artifacts(tree: dict[str, Any]) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []

    def _walk(node: dict[str, Any], parent_id: str | None, archive_layer: int, path_prefix: str) -> None:
        display_path = node.get("filename") if not path_prefix else f"{path_prefix}!/{node.get('origin_path') or node.get('filename')}"
        current = dict(node)
        current["parent_artifact_id"] = parent_id
        current["display_path"] = display_path
        current["archive_layer"] = archive_layer
        nodes.append(current)
        child_layer = archive_layer + (1 if node.get("archive_type") else 0)
        for child in node.get("children", []):
            _walk(child, str(node["id"]), child_layer, display_path)

    _walk(tree, None, 0, "")
    return nodes


def _build_finding_groups(report: dict[str, Any], artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    artifact_lookup = {str(item["id"]): item for item in artifacts if item.get("id") is not None}
    findings: list[dict[str, Any]] = []
    for index, evidence in enumerate(report.get("risk", {}).get("evidence", []), start=1):
        artifact_id = evidence.get("artifact_id") or artifacts[0]["id"]
        artifact = artifact_lookup.get(str(artifact_id), artifacts[0])
        findings.append(
            {
                "finding_id": f"finding::{artifact_id}::{index}",
                "artifact_id": artifact_id,
                "title": str(evidence.get("reason") or evidence.get("kind") or "finding"),
                "summary": str(evidence.get("reason") or evidence.get("kind") or "finding"),
                "severity": str(evidence.get("severity") or "low"),
                "confidence": "high" if float(evidence.get("confidence", 0.0) or 0.0) >= 0.85 else "medium",
                "kind": str(evidence.get("kind") or "generic"),
                "primary": index == 1,
                "score_impact": int(evidence.get("score_contribution", {}).get("applied_points") or evidence.get("points") or 0),
                "found_by": [{"stage": evidence.get("stage") or evidence.get("source"), "analyzer": evidence.get("analyzer")}],
                "evidence_ids": [evidence.get("id") or evidence.get("evidence_id")],
                "ioc_ids": [],
                "decoded_ids": list(evidence.get("decoded_ids") or []),
                "uncertainty_ids": [],
                "timeline_event_ids": [],
                "artifact_path": artifact.get("display_path") or artifact.get("filename"),
            }
        )
    return findings


def _build_ioc_records(report: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    root_artifact_id = findings[0]["artifact_id"] if findings else f"root::{report['job_id']}"
    urls = list(report.get("results", {}).get("iocs", {}).get("urls", []))
    return [
        {
            "ioc_id": f"ioc::{root_artifact_id}::url::{index + 1}",
            "artifact_id": root_artifact_id,
            "type": "url",
            "value": value,
            "source_stage": "ioc-extract",
            "source_kind": "report_merge",
            "decoder": None,
            "decoded_id": None,
            "first_seen_in": f"timeline::{index + 1}",
            "finding_ids": [findings[0]["finding_id"]] if findings else [],
        }
        for index, value in enumerate(urls)
    ]


def _build_decoded_records(report: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    root_artifact_id = findings[0]["artifact_id"] if findings else f"root::{report['job_id']}"
    for candidate in report.get("results", {}).get("deobfuscation", {}).get("candidates", []):
        records.append(
            {
                "decoded_id": candidate.get("decoded_id") or f"decoded::{root_artifact_id}::{len(records) + 1}",
                "artifact_id": root_artifact_id,
                "source_stage": candidate.get("source_stage") or "deobfuscation",
                "decoder": candidate.get("provenance", {}).get("decoder"),
                "technique": candidate.get("technique"),
                "confidence": candidate.get("confidence", 0.0),
                "content_preview": candidate.get("content", ""),
                "content_encoding": candidate.get("content_encoding"),
                "content_truncated": candidate.get("content_truncated", False),
                "provenance": candidate.get("provenance", {}),
                "ioc_ids": [],
                "finding_ids": [findings[0]["finding_id"]] if findings else [],
            }
        )
    return records


def _build_uncertainties(report: dict[str, Any], artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    uncertainties: list[dict[str, Any]] = []
    if report.get("risk", {}).get("breakdown", {}).get("inherited_score", 0) > 0:
        uncertainties.append(
            {
                "uncertainty_id": f"uncertainty::{artifacts[0]['id']}::1",
                "artifact_id": artifacts[0]["id"],
                "kind": "tree_inheritance_elevated_root",
                "severity": "low",
                "direction": "context_only",
                "message": "The root artifact verdict is elevated by descendant inheritance.",
                "finding_ids": [],
            }
        )
    return uncertainties


def _build_failure_diagnostics(report: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    if report.get("results", {}).get("archive_extract", {}).get("extraction_failed"):
        return {
            "status": "blocked",
            "headline": "Inner archive layers were blocked by extraction failure.",
            "diagnostics": [
                {
                    "diagnostic_id": f"diag::{artifacts[0]['id']}::archive-extract::1",
                    "artifact_id": artifacts[0]["id"],
                    "stage": "archive-extract",
                    "code": "password_attempts_exhausted",
                    "category": "blocked",
                    "severity": "high",
                    "likely_effect": "possible_false_negative",
                    "confidence": "high",
                    "message": report.get("results", {}).get("archive_extract", {}).get("reason"),
                    "recommended_action": "collect the correct password and resubmit",
                }
            ],
            "suspected_miss_stages": [
                {"artifact_id": artifacts[0]["id"], "stage": "archive-extract", "reason": "inner members were never extracted", "confidence": "high"}
            ],
        }
    return {"status": "none", "headline": "", "diagnostics": [], "suspected_miss_stages": []}


def _build_timeline(report: dict[str, Any], findings: list[dict[str, Any]], iocs: list[dict[str, Any]], decoded: list[dict[str, Any]]) -> list[dict[str, Any]]:
    artifact_id = findings[0]["artifact_id"] if findings else f"root::{report['job_id']}"
    events: list[dict[str, Any]] = [
        {
            "timeline_event_id": "timeline::1",
            "seq": 1,
            "artifact_id": artifact_id,
            "kind": "artifact_registered",
            "stage": "upload",
            "analyzer": None,
            "status": "ok",
            "summary": "Artifact registered for analysis.",
            "refs": {"finding_ids": [], "evidence_ids": [], "ioc_ids": [], "decoded_ids": []},
        }
    ]
    if decoded:
        events.append(
            {
                "timeline_event_id": f"timeline::{len(events) + 1}",
                "seq": len(events) + 1,
                "artifact_id": artifact_id,
                "kind": "decoded_string_extracted",
                "stage": "deobfuscation",
                "analyzer": None,
                "status": "ok",
                "summary": "Decoded content was extracted during deobfuscation.",
                "refs": {"finding_ids": [findings[0]["finding_id"]] if findings else [], "evidence_ids": [], "ioc_ids": [iocs[0]["ioc_id"]] if iocs else [], "decoded_ids": [decoded[0]["decoded_id"]]},
            }
        )
    return events
```

- [ ] **Step 4: Route `get_report()` through the helper**

In `backend/src/malscan/api/routes.py`, after artifact tree construction and risk rollup, add:

```python
from malscan.report_explainability import build_explainability, ensure_artifact_tree_root

report["artifact_tree"] = ensure_artifact_tree_root(report, report["artifact_tree"])
report["explainability"] = build_explainability(
    report=report,
    artifact_tree=report["artifact_tree"],
)
```

Also enrich tree nodes in-place with `display_path`, `archive_layer`, `analysis_status`, `primary_analyzer`, `finding_ids`, and `top_finding_titles`.

- [ ] **Step 5: Re-run the backend explainability tests**

Run in `backend/`:

```bash
poetry run pytest tests/test_report_explainability.py tests/test_api.py -k "explainability or synthetic_root or descendant" -v
```

Expected: explainability assembly tests pass and existing endpoint behavior remains intact.

---

## Task 6: Cover blocked and degraded report states

**Files:**
- Modify: `worker/src/malscan_worker/reporting.py`
- Modify: `backend/src/malscan/report_explainability.py`
- Modify: `worker/tests/test_password_flow.py`
- Modify: `backend/tests/test_report_explainability.py`

- [ ] **Step 1: Write failing diagnostics tests**

Add coverage for password exhaustion, unsupported format, parser error, and deobfuscation truncation.

```python
def test_password_exhausted_report_builds_blocked_diagnostic():
    report = build_password_attempts_exhausted_report(job_data)
    assert report["explainability"]["failure_diagnostics"]["status"] == "blocked"


def test_unsupported_format_creates_suspected_miss_stage():
    report = {
        "job_id": "job-root-1",
        "file": {
            "file_id": "file-1",
            "sha256": "1111",
            "mime": "application/octet-stream",
            "size": 10,
            "original_filename": "sample.bin",
        },
        "verdict": "clean",
        "score": 0,
        "risk_level": "clean",
        "risk": {
            "policy_version": "msrs-v1",
            "risk_score": 0,
            "risk_level": "clean",
            "legacy_verdict": "clean",
            "breakdown": {"local_score": 0, "inherited_score": 0, "synergy_bonus": 0, "dampener": 0, "final_score": 0},
            "evidence": [],
            "score_trace": {"components": []},
        },
        "results": {
            "format_analysis": {"analyzer": None, "format_type": None, "risk_score": 0, "risk_factors": [], "indicators": [], "heuristics": [], "features": {}, "reason": "No analyzer matched"},
            "iocs": {"urls": [], "domains": [], "ips": [], "hashes": {"md5": "", "sha1": "", "sha256": "1111"}},
            "sandbox": {"executed": False, "behaviors": [], "network_connections": [], "is_mock": True},
        },
    }
    explainability = build_explainability(
        report=report,
        artifact_tree=ensure_artifact_tree_root(report, None),
    )
    assert explainability["failure_diagnostics"]["suspected_miss_stages"][0]["stage"] == "format-analysis"
```

- [ ] **Step 2: Run targeted tests to verify failure**

Run:

```bash
cd worker && poetry run pytest tests/test_password_flow.py -v
cd ../backend && poetry run pytest tests/test_report_explainability.py -k "blocked or miss" -v
```

Expected: failures because the diagnostics are not populated yet.

- [ ] **Step 3: Add empty explainability contract to password-exhausted worker reports**

In `worker/src/malscan_worker/reporting.py`, extend the return payload with:

```python
"report_schema_version": "mswr-report-v2",
"explainability": {
    "summary": {
        "headline": "Archive contents were not analyzed because password attempts were exhausted.",
        "primary_artifact_id": None,
        "primary_artifact_path": None,
        "top_findings": [],
        "final_verdict_explainer": "This report only reflects outer-file coverage.",
    },
    "artifacts": [],
    "findings": [],
    "evidence": [],
    "iocs": [],
    "decoded_strings": [],
    "uncertainties": [],
    "timeline": [],
    "failure_diagnostics": {
        "status": "blocked",
        "headline": "Inner archive layers were blocked by password exhaustion.",
        "diagnostics": [
            {
                "stage": "archive-extract",
                "code": "password_attempts_exhausted",
                "category": "blocked",
                "severity": "high",
                "likely_effect": "possible_false_negative",
                "confidence": "high",
                "message": "Archive extraction failed after 3 incorrect password attempts.",
                "recommended_action": "collect the correct password and resubmit",
            }
        ],
        "suspected_miss_stages": [
            {"stage": "archive-extract", "reason": "inner members were never extracted", "confidence": "high"}
        ],
    },
},
```

- [ ] **Step 4: Add degraded-state synthesis rules in backend**

Inside `build_explainability()`, detect:

1. `format-analysis` skipped with `No analyzer matched`
2. deobfuscation `stats.candidate_cap_reached` or `stats.wall_time_reached`
3. parser errors in `document_analysis.errors`
4. extraction failures or malicious archive short-circuit reasons

Map them into diagnostics consistently.

- [ ] **Step 5: Re-run the blocked/degraded tests**

Run:

```bash
cd worker && poetry run pytest tests/test_password_flow.py -v
cd ../backend && poetry run pytest tests/test_report_explainability.py -k "blocked or miss or degraded" -v
```

Expected: blocked and degraded diagnostics now render deterministically.

---

## Task 7: Render explainability sections in the frontend

**Files:**
- Create: `frontend/src/components/report/TopFindingsSummary.tsx`
- Create: `frontend/src/components/report/ArtifactTreePanel.tsx`
- Create: `frontend/src/components/report/ScoreTracePanel.tsx`
- Create: `frontend/src/components/report/EvidenceTimelinePanel.tsx`
- Create: `frontend/src/components/report/FailureDiagnosticsPanel.tsx`
- Modify: `frontend/src/pages/ReportPage.tsx`
- Modify: `frontend/src/api/types.ts`

- [ ] **Step 1: Add the smallest safe component interfaces**

Use prop-first component contracts:

```tsx
export interface TopFindingsSummaryProps {
  summary: Report["explainability"]["summary"]
}

export interface ArtifactTreePanelProps {
  artifactTree: Report["artifact_tree"]
}

export interface ScoreTracePanelProps {
  risk: Report["risk"]
}

export interface EvidenceTimelinePanelProps {
  timeline: NonNullable<Report["explainability"]>["timeline"]
}

export interface FailureDiagnosticsPanelProps {
  diagnostics: NonNullable<Report["explainability"]>["failure_diagnostics"]
  uncertainties: NonNullable<Report["explainability"]>["uncertainties"]
}
```

- [ ] **Step 2: Render the new sections only when explainability is present**

In `ReportPage.tsx`, after the verdict card, add:

```tsx
{report.explainability && (
  <>
    <TopFindingsSummary summary={report.explainability.summary} />
    <ScoreTracePanel risk={report.risk} />
    <ArtifactTreePanel artifactTree={report.artifact_tree} />
    <EvidenceTimelinePanel timeline={report.explainability.timeline} />
    <FailureDiagnosticsPanel
      diagnostics={report.explainability.failure_diagnostics}
      uncertainties={report.explainability.uncertainties}
    />
  </>
)}
```

Keep the existing legacy cards below them.

- [ ] **Step 3: Add minimal rendering rules**

The UI should answer the target questions directly:

1. Top findings card shows artifact path, archive layer, analyzer, and score impact.
2. Score trace card shows local, inherited, synergy, and final score plus the top component rows.
3. Artifact tree shows `display_path`, risk badge, and top finding title per node.
4. Timeline shows stage, artifact path, and linked IOC or decoded string previews.
5. Failure diagnostics shows suspected miss stages and confidence.

- [ ] **Step 4: Verify frontend types and build**

Run in `frontend/`:

```bash
npm run typecheck
npm run build
```

Expected: both commands pass.

---

## Task 8: Verify full compatibility and document the contract

**Files:**
- Modify: `README.en.md`
- Modify: `backend/tests/test_api.py`
- Modify: `worker/tests/test_pipeline.py`

- [ ] **Step 1: Add compatibility regression checks**

Make sure the tests still assert:

```python
assert data["verdict"] == "suspicious"
assert data["score"] == 59
assert data["risk_level"] == "medium"
assert data["results"]["archive_extract"]["reason"] == "Archive extraction failed after 3 incorrect password attempts"
assert data["risk"]["descendant_summary"] == {}
```

and additionally assert the new fields exist without changing those old expectations.

- [ ] **Step 2: Document the new contract**

Update `README.en.md` with a short section that says:

1. `GET /api/v1/reports/{job_id}` is still the only public report endpoint.
2. `results.*` remains the raw compatibility section.
3. `explainability` is the new canonical UI/API section.
4. `risk.score_trace` explains score formation.
5. `artifact_tree` nodes now carry layer/path/finding metadata.

- [ ] **Step 3: Run the verification suite**

Run in `worker/`:

```bash
poetry run pytest tests/test_pipeline.py tests/test_password_flow.py tests/test_artifact_tree.py -v
```

Run in `backend/`:

```bash
poetry run pytest tests/test_api.py tests/test_scoring_adapters.py tests/test_scoring_engine.py tests/test_report_explainability.py -v
```

Run in `frontend/`:

```bash
npm run typecheck
npm run build
```

Expected: all commands pass, existing compatibility behavior remains intact, and explainability fields are present.

---

## Self-Review Checklist

- [ ] Top-level `verdict`, `score`, `risk_level`, `risk`, `results`, and `artifact_tree` remain intact.
- [ ] Every finding, evidence record, IOC record, decoded string, uncertainty, and diagnostic points to an `artifact_id`.
- [ ] `risk.score_trace` explains both direct and descendant contributions.
- [ ] Password-exhausted and degraded-analysis states produce explicit diagnostics instead of silent empty sections.
- [ ] The frontend renders explainability additively and does not regress the current report page.
