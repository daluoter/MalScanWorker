"""Pydantic schemas for API requests and responses."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


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
    status: Literal["queued", "scanning", "done", "failed"]
    progress: JobProgress
    updated_at: datetime
    error_message: str | None


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


class AnalysisResults(BaseModel):
    """All analysis results."""

    av_result: AvResult
    yara_hits: list[YaraHit]
    iocs: Iocs
    sandbox: SandboxResult


class StageTiming(BaseModel):
    """Stage timing information."""

    name: str
    status: str
    duration_ms: int


class Timings(BaseModel):
    """Analysis timings."""

    total_ms: int
    stages: list[StageTiming]


class ReportResponse(BaseModel):
    """Response for GET /reports/{job_id}."""

    job_id: str
    file: FileMetadata
    verdict: str
    score: int
    results: AnalysisResults
    timings: Timings
    created_at: datetime


class ApiError(BaseModel):
    """API error response."""

    code: str
    message: str
    details: dict | None = None


class ApiErrorResponse(BaseModel):
    """Wrapper for API errors."""

    error: ApiError
