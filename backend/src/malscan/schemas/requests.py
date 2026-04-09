"""Pydantic schemas for API requests and responses."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class UploadResponse(BaseModel):
    """Response for POST /files."""

    job_id: str
    file_id: str
    sha256: str
    status: Literal["queued"]
    created_at: datetime


class JobProgress(BaseModel):
    """Job progress information."""

    current_stage: str | None
    stages_done: int
    stages_total: int
    percent: int


class JobStatusResponse(BaseModel):
    """Response for GET /jobs/{job_id}."""

    job_id: str
    parent_job_id: str | None = None
    depth: int = 0
    status: Literal["queued", "scanning", "password_required", "done", "failed"]
    password_attempts: int
    password_attempts_remaining: int
    progress: JobProgress
    updated_at: datetime
    error_message: str | None

    # Sub-job statistics overview
    total_sub: int = 0
    completed_sub: int = 0
    malicious_sub: int = 0


class FileMetadata(BaseModel):
    """File metadata in report."""

    file_id: str
    sha256: str
    mime: str
    size: int
    original_filename: str


class AvResult(BaseModel):
    """Antivirus scan result."""

    engine: str
    infected: bool
    threat_name: str | None


class YaraHit(BaseModel):
    """YARA rule match."""

    rule: str
    namespace: str
    description: str = ""
    classification: str = "generic"
    confidence: str = "medium"
    family: str = ""
    severity: str = "medium"
    author: str = ""
    tags: list[str]
    strings: list[str]


class Hashes(BaseModel):
    """File hashes."""

    md5: str
    sha1: str
    sha256: str


class Iocs(BaseModel):
    """Indicators of Compromise."""

    urls: list[str]
    domains: list[str]
    ips: list[str]
    hashes: Hashes


class ArchiveExtractResult(BaseModel):
    """Archive extraction result."""

    archive_type: str | None = None
    extracted_count: int = 0
    sub_jobs_created: int = 0
    total_extracted_bytes: int = 0
    malicious: bool = False
    reason: str | None = None
    extraction_failed: bool | None = None


class SandboxBehavior(BaseModel):
    """Sandbox behavior entry."""

    type: str
    path: str | None = None
    key: str | None = None


class SandboxConnection(BaseModel):
    """Sandbox network connection."""

    dst_ip: str
    dst_port: int
    protocol: str


class SandboxResult(BaseModel):
    """Sandbox analysis result."""

    executed: bool
    behaviors: list[SandboxBehavior]
    network_connections: list[SandboxConnection]
    is_mock: bool


class RiskEvidence(BaseModel):
    """Single normalized risk evidence entry."""

    source: str
    kind: str
    tier: str
    severity: str
    points: int
    scope: str
    depth: int
    reason: str
    raw: dict[str, Any] = Field(default_factory=dict)


class RiskBreakdown(BaseModel):
    """Risk score component breakdown."""

    local_score: int
    inherited_score: int
    synergy_bonus: int
    dampener: int
    final_score: int


class RiskSummary(BaseModel):
    """Top-level risk summary block."""

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


class AnalysisResults(BaseModel):
    """All analysis results."""

    av_result: AvResult
    yara_hits: list[YaraHit]
    iocs: Iocs
    sandbox: SandboxResult
    format_analysis: dict[str, Any] | None = None
    deobfuscation: dict[str, Any] | None = None
    document_analysis: dict[str, Any] | None = None
    archive_extract: ArchiveExtractResult | None = None


class StageTiming(BaseModel):
    """Stage timing information."""

    name: str
    status: str
    duration_ms: int


class Timings(BaseModel):
    """Analysis timings."""

    total_ms: int
    stages: list[StageTiming]


class ChildJobSummary(BaseModel):
    """Summary of a child job."""

    job_id: str
    filename: str
    sha256: str
    status: str
    verdict: str | None = None


class ArtifactTreeNode(BaseModel):
    """A node in the artifact extraction tree."""

    id: str
    filename: str
    sha256: str
    mime: str | None = None
    size: int
    depth: int
    origin_path: str | None = None
    extraction_source: str | None = None
    archive_type: str | None = None
    extraction_note: str | None = None
    verdict: str | None = None
    score: int | None = None
    risk_level: str | None = None
    policy_version: str | None = None
    job_id: str | None = None
    children: list["ArtifactTreeNode"] = Field(default_factory=list)


class ReportResponse(BaseModel):
    """Response for GET /reports/{job_id}."""

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


class ApiError(BaseModel):
    """API error response."""

    code: str
    message: str
    details: dict | None = None


class ApiErrorResponse(BaseModel):
    """Wrapper for API errors."""

    error: ApiError


class PasswordSubmitRequest(BaseModel):
    """Request for POST /jobs/{job_id}/password."""

    password: str = Field(min_length=1, max_length=256)


class PasswordSubmitResponse(BaseModel):
    """Response for POST /jobs/{job_id}/password."""

    job_id: str
    status: Literal["queued", "password_required"]
    message: str
    attempts_used: int
    attempts_remaining: int
