# Recursive Extraction & Artifact Tree Design

**Date:** 2026-04-07
**Status:** Draft
**Approach:** Minimal Overlay (Approach A)

## 1. Problem Statement

The MalScanWorker system already supports basic recursive extraction via `ArchiveExtractStage` and `DocumentAnalysisStage`, with sub-job creation through `InternalJobSubmitter`. However, it lacks:

1. **Structured artifact tree** -- no dedicated data model recording parent-child extraction relationships, origin paths, or extraction provenance
2. **Hierarchical report traceability** -- reports show a flat `child_jobs` array; cannot trace which malicious verdict came from which nesting layer
3. **Robust safety controls** -- hardcoded limits (`max_files=15`), no expansion-ratio zip bomb detection, no cycle detection, no per-extraction timeout
4. **Pluggable format handlers** -- extraction logic is monolithic within `ArchiveExtractStage`; adding ISO or other formats requires modifying the stage directly
5. **Dedup awareness within single extraction** -- same file at multiple paths creates redundant sub-jobs

## 2. Goals

1. Support zip/7z/rar (existing) with a pluggable handler interface extensible to ISO and others
2. Build an artifact tree for every extracted sub-file with parent-child, depth, origin_path, hash, mime, size
3. Re-submit all extracted artifacts into the existing scan pipeline
4. Configurable safety limits: max_depth, max_files, max_extracted_bytes, timeout
5. Detect and handle: zip bombs, path traversal, duplicate files, recursive loops
6. Reports show hierarchical artifact tree with per-layer verdicts

## 3. Architecture Overview

### Approach: Minimal Overlay

Add an `artifacts` table and format handler registry **on top of** the existing architecture. The existing Job hierarchy (`parent_job_id`) remains intact for job scheduling. The artifact tree provides extraction provenance and report traceability.

```
Upload → File table → Job (depth=0) → Pipeline
                                          ├─ PARALLEL: FileType, ClamAV, Yara, IOC
                                          └─ SEQUENTIAL:
                                              ├─ ArchiveExtractStage
                                              │    ├─ detect format (handler registry)
                                              │    ├─ create root Artifact (if depth=0)
                                              │    ├─ extract via FormatHandler
                                              │    ├─ for each extracted file:
                                              │    │    ├─ create child Artifact record
                                              │    │    ├─ cycle detection (check ancestor hashes)
                                              │    │    └─ submit sub-job (InternalJobSubmitter)
                                              │    └─ return findings with artifact metadata
                                              ├─ DocumentAnalysisStage (similar artifact creation)
                                              └─ SandboxStage
```

## 4. Data Model

### 4.1 New `artifacts` Table

```sql
CREATE TABLE artifacts (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tree structure
    parent_id         UUID REFERENCES artifacts(id) ON DELETE CASCADE,
    root_id           UUID REFERENCES artifacts(id) ON DELETE CASCADE,
    depth             INTEGER NOT NULL DEFAULT 0,

    -- File identity
    sha256            VARCHAR(64) NOT NULL,
    md5               VARCHAR(32),
    sha1              VARCHAR(40),
    size              BIGINT NOT NULL,
    mime              VARCHAR(200),
    original_filename VARCHAR(500) NOT NULL,

    -- Extraction provenance
    origin_path       TEXT,
    extraction_source VARCHAR(50),
    archive_type      VARCHAR(20),
    extraction_note   VARCHAR(100),

    -- Linkage to jobs
    job_id            UUID REFERENCES jobs(id) ON DELETE SET NULL,
    root_job_id       UUID REFERENCES jobs(id) ON DELETE CASCADE,

    -- Denormalized scan result (for fast tree queries)
    verdict           VARCHAR(20),
    score             INTEGER,

    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_artifacts_parent_id   ON artifacts(parent_id);
CREATE INDEX ix_artifacts_root_id     ON artifacts(root_id);
CREATE INDEX ix_artifacts_sha256      ON artifacts(sha256);
CREATE INDEX ix_artifacts_job_id      ON artifacts(job_id);
CREATE INDEX ix_artifacts_root_job_id ON artifacts(root_job_id);
```

### 4.2 SQLAlchemy Model

New file: `backend/src/malscan/models/artifact.py`

```python
class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Tree structure
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=True, index=True
    )
    root_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=True, index=True
    )
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # File identity
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    md5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sha1: Mapped[str | None] = mapped_column(String(40), nullable=True)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime: Mapped[str | None] = mapped_column(String(200), nullable=True)
    original_filename: Mapped[str] = mapped_column(String(500), nullable=False)

    # Extraction provenance
    origin_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    extraction_source: Mapped[str | None] = mapped_column(String(50), nullable=True)
    archive_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    extraction_note: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Linkage
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    root_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=True, index=True
    )

    # Denormalized result
    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    parent: Mapped["Artifact | None"] = relationship("Artifact", back_populates="children", remote_side="Artifact.id")
    children: Mapped[list["Artifact"]] = relationship("Artifact", back_populates="parent", cascade="all, delete-orphan")
    job: Mapped["Job | None"] = relationship("Job", foreign_keys=[job_id])
```

### 4.3 Job Table Change

Add nullable FK to `jobs`:

```sql
ALTER TABLE jobs ADD COLUMN artifact_id UUID REFERENCES artifacts(id) ON DELETE SET NULL;
CREATE INDEX ix_jobs_artifact_id ON jobs(artifact_id);
```

> **Out of scope:** The existing `total_sub`, `completed_sub`, and `malicious_sub` columns on the `jobs` table are pre-existing technical debt with incomplete update semantics. This spec does **not** modify or fix them. They remain as-is.

### 4.4 Alembic Migration

New migration: `004_add_artifacts_table.py`

## 5. Format Handler Registry

### 5.1 Interface

New directory: `worker/src/malscan_worker/extractors/`

```python
# extractors/base.py
@dataclass
class ExtractedFile:
    path: str              # absolute path on disk
    original_name: str     # filename within archive
    size: int              # bytes
    origin_path: str       # full path within archive hierarchy

@dataclass
class ExtractionLimits:
    max_files: int = 100
    max_extracted_bytes: int = 500_000_000      # 500MB
    max_single_file_bytes: int = 100_000_000    # 100MB
    max_expansion_ratio: float = 100.0
    timeout_seconds: int = 120

@dataclass
class ExtractionResult:
    files: list[ExtractedFile]
    malicious: bool = False
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    archive_type: str | None = None

class FormatHandler(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool: ...

    @abstractmethod
    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult: ...
```

### 5.2 Built-in Handlers

Each existing extractor method becomes its own class:

| Handler | File | Source |
|---------|------|--------|
| `ZipHandler` | `extractors/zip_handler.py` | From `_extract_zip()` |
| `SevenZipHandler` | `extractors/sevenz_handler.py` | From `_extract_7z()` |
| `RarHandler` | `extractors/rar_handler.py` | From `_extract_rar()` |
| `TarHandler` | `extractors/tar_handler.py` | From `_extract_tar()` |
| `GzipHandler` | `extractors/gzip_handler.py` | From `_extract_single_compressed()` (gzip) |
| `Bz2Handler` | `extractors/bz2_handler.py` | From `_extract_single_compressed()` (bz2) |
| `IsoHandler` | `extractors/iso_handler.py` | Stub: `raise NotImplementedError("ISO support planned")` |

### 5.3 Registry

```python
# extractors/registry.py
class HandlerRegistry:
    def __init__(self) -> None:
        self._handlers: list[FormatHandler] = []

    def register(self, handler: FormatHandler) -> None:
        self._handlers.append(handler)

    def detect(self, file_path: Path, mime: str) -> FormatHandler | None:
        magic = b""
        try:
            with open(file_path, "rb") as f:
                magic = f.read(16)
        except OSError:
            pass
        for handler in self._handlers:
            if handler.can_handle(file_path, mime, magic):
                return handler
        return None

def get_default_registry() -> HandlerRegistry:
    registry = HandlerRegistry()
    registry.register(ZipHandler())
    registry.register(SevenZipHandler())
    registry.register(RarHandler())
    registry.register(TarHandler())
    registry.register(GzipHandler())
    registry.register(Bz2Handler())
    registry.register(IsoHandler())  # stub
    return registry
```

## 6. Enhanced ArchiveExtractStage

### 6.1 Modified Execute Flow

```python
async def execute(self, ctx: StageContext) -> StageResult:
    # 1. Skip checks (file exists, max depth)
    # 2. Detect format via registry
    handler = self.registry.detect(ctx.file_path, mime)
    if handler is None:
        return skipped

    # 3. Build ExtractionLimits from settings
    limits = ExtractionLimits(
        max_files=settings.extraction_max_files,
        ...
    )

    # 4. Create/find root artifact (if depth=0)
    root_artifact_id = ctx.root_artifact_id
    parent_artifact_id = ctx.artifact_id
    if not root_artifact_id:
        root_artifact = await self._create_root_artifact(ctx)
        root_artifact_id = str(root_artifact.id)
        parent_artifact_id = root_artifact_id

    # 5. Extract with timeout
    result = await asyncio.wait_for(
        asyncio.to_thread(handler.extract, ctx.file_path, extract_dir, limits, ctx.archive_password),
        timeout=limits.timeout_seconds,
    )

    # 6. If malicious (zip bomb), record and return
    if result.malicious:
        return malicious_result

    # 7. Cycle detection: load ancestor hashes
    ancestor_hashes = ctx.ancestor_hashes or set()

    # 8. For each extracted file:
    #
    # Dedup operates at two levels:
    #   a) Extraction-level dedup: same SHA256 appears twice within the SAME archive
    #      → Create artifact record for each occurrence (different origin_path),
    #        but only submit a sub-job for the first occurrence.
    #   b) Submitter-level dedup: InternalJobSubmitter already handles File record
    #      reuse across archives. This logic is unchanged.
    #
    seen_hashes_this_extraction = set()
    for ef in result.files:
        sha256 = compute_sha256(ef.path)

        # Cycle detection
        if sha256 in ancestor_hashes:
            log.warning("recursive_loop_detected", ...)
            continue

        # Extraction-level dedup: same hash already seen in this archive
        if sha256 in seen_hashes_this_extraction:
            # Create artifact record but skip sub-job.
            # _create_artifact(..., skip=True) behaviour:
            #   - Creates artifact row with verdict="skipped",
            #     extraction_note="duplicate_within_extraction"
            #   - Does NOT create a corresponding sub-job
            await self._create_artifact(parent_artifact_id, root_artifact_id, ef, sha256, skip=True)
            continue
        seen_hashes_this_extraction.add(sha256)

        # Create artifact record
        artifact = await self._create_artifact(parent_artifact_id, root_artifact_id, ef, sha256)

        # Submit sub-job (enhanced with artifact_id, root_artifact_id, ancestor_hashes)
        await submitter.submit_subjob(
            ...,
            artifact_id=str(artifact.id),
            root_artifact_id=root_artifact_id,
            ancestor_hashes=ancestor_hashes | {ctx.sha256},
        )
```

### 6.2 Enhanced StageContext

```python
@dataclass
class StageContext:
    # ... existing fields ...
    artifact_id: str | None = None
    root_artifact_id: str | None = None
    ancestor_hashes: set[str] = field(default_factory=set)
```

### 6.3 Enhanced RabbitMQ Message

```json
{
    "job_id": "...",
    "file_id": "...",
    "storage_key": "...",
    "sha256": "...",
    "original_filename": "...",
    "archive_password": null,
    "artifact_id": "art-uuid",
    "root_artifact_id": "root-art-uuid",
    "ancestor_hashes": ["sha256_of_parent", "sha256_of_grandparent"]
}
```

### 6.4 DocumentAnalysisStage Artifact Integration

`DocumentAnalysisStage` extracts embedded/OLE objects from documents (e.g., DOCX, XLSX, PDF with embedded executables). These extracted objects must follow the same artifact creation rules as archive extraction:

1. **Artifact record first, sub-job second:** For every embedded object extracted, create an artifact record _before_ submitting the sub-job. The artifact captures provenance even if sub-job submission later fails.

2. **Required artifact fields:**
   - `parent_artifact_id` — the artifact of the document being analysed (may be `None` if the document is a root-level upload without prior extraction)
   - `origin_path` — describes the embedded object's location within the document (e.g., `"OLE:Package/payload.exe"`, `"embedded_image_0"`)
   - `depth` — parent's depth + 1
   - `extraction_source` — `"document-analysis"`

3. **Sub-job submission:** After artifact creation, submit the sub-job via `InternalJobSubmitter` with `artifact_id`, `root_artifact_id`, and `ancestor_hashes` (same as archive extraction).

4. **Extraction-level dedup:** Same rules as archive extraction. If the same SHA256 appears multiple times as embedded objects within one document, create artifact records for each (different `origin_path`) but only submit one sub-job. Use `_create_artifact(..., skip=True)` for duplicates.

5. **Root artifact handling:** If `DocumentAnalysisStage` runs on a file that has no existing `artifact_id` in its `StageContext` (i.e., a directly uploaded document, not extracted from an archive), it should create a root artifact for itself before creating child artifacts for embedded objects. This mirrors the behaviour of `ArchiveExtractStage` at depth=0.

```python
# Pseudocode for DocumentAnalysisStage artifact integration
async def _process_embedded_objects(self, ctx: StageContext, embedded_files: list) -> list:
    root_artifact_id = ctx.root_artifact_id
    parent_artifact_id = ctx.artifact_id

    # Create root artifact if this is a top-level document
    if not root_artifact_id:
        root_artifact = await self._create_root_artifact(ctx)
        root_artifact_id = str(root_artifact.id)
        parent_artifact_id = root_artifact_id

    seen_hashes = set()
    for ef in embedded_files:
        sha256 = compute_sha256(ef.path)

        if sha256 in (ctx.ancestor_hashes or set()):
            continue  # cycle detection

        if sha256 in seen_hashes:
            await self._create_artifact(
                parent_artifact_id, root_artifact_id, ef, sha256, skip=True
            )
            continue
        seen_hashes.add(sha256)

        artifact = await self._create_artifact(
            parent_artifact_id, root_artifact_id, ef, sha256,
            extraction_source="document-analysis",
        )
        await submitter.submit_subjob(
            ...,
            artifact_id=str(artifact.id),
            root_artifact_id=root_artifact_id,
            ancestor_hashes=(ctx.ancestor_hashes or set()) | {ctx.sha256},
        )
```

## 7. Enhanced InternalJobSubmitter

Add parameters to `submit_subjob()`:

```python
async def submit_subjob(
    self,
    *,
    # ... existing params ...
    artifact_id: str | None = None,
    root_artifact_id: str | None = None,
    ancestor_hashes: set[str] | None = None,
) -> str | None:
    # ... existing logic ...

    # Include artifact fields in MQ message
    message_body = {
        # ... existing fields ...
        "artifact_id": artifact_id,
        "root_artifact_id": root_artifact_id,
        "ancestor_hashes": list(ancestor_hashes or set()),
    }
```

## 8. Configuration

New settings in `worker/src/malscan_worker/config.py`:

```python
class Settings(BaseSettings):
    # ... existing ...

    # Extraction limits (depth controlled by existing max_job_depth)
    extraction_max_files: int = 100
    extraction_max_bytes: int = 500_000_000        # 500MB
    extraction_max_single_bytes: int = 100_000_000  # 100MB
    extraction_max_ratio: float = 100.0
    extraction_timeout: int = 120                    # seconds
```

## 9. Report Enhancement

### 9.1 API Change

`GET /reports/{job_id}` response gains `artifact_tree` field.

> **Non-archive/non-container files:** Artifact records are only created during extraction chains (archive extraction or document analysis that yields embedded objects). A root-level upload of a plain file (e.g., a standalone `.exe` or `.txt`) that is not an archive and contains no embedded objects will have **no artifact records** in the database. The report for such files returns `artifact_tree: null`.

### 9.2 Tree Assembly Query

```python
async def _build_artifact_tree(root_job_id: str, db: AsyncSession) -> dict | None:
    stmt = (
        select(Artifact)
        .where(Artifact.root_job_id == UUID(root_job_id))
        .order_by(Artifact.depth, Artifact.created_at)
    )
    result = await db.execute(stmt)
    artifacts = result.scalars().all()

    if not artifacts:
        return None

    # Build tree from flat list
    nodes = {}
    root = None
    for art in artifacts:
        node = {
            "id": str(art.id),
            "filename": art.original_filename,
            "sha256": art.sha256,
            "mime": art.mime,
            "size": art.size,
            "depth": art.depth,
            "origin_path": art.origin_path,
            "extraction_source": art.extraction_source,
            "archive_type": art.archive_type,
            "verdict": art.verdict,
            "score": art.score,
            "job_id": str(art.job_id) if art.job_id else None,
            "children": [],
        }
        nodes[str(art.id)] = node
        if art.parent_id and str(art.parent_id) in nodes:
            nodes[str(art.parent_id)]["children"].append(node)
        if art.depth == 0:
            root = node

    return root
```

### 9.3 Schema Addition

```python
# schemas/requests.py
class ArtifactTreeNode(BaseModel):
    id: str
    filename: str
    sha256: str
    mime: str | None
    size: int
    depth: int
    origin_path: str | None = None
    extraction_source: str | None = None
    archive_type: str | None = None
    verdict: str | None = None
    score: int | None = None
    job_id: str | None = None
    children: list["ArtifactTreeNode"] = []

class ReportResponse(BaseModel):
    # ... existing fields ...
    artifact_tree: ArtifactTreeNode | None = None
```

### 9.4 Verdict Update on Job Completion

After `_build_analysis_result()` in `pipeline.py`, update the artifact's denormalized verdict:

```python
# In run_pipeline(), after update_job_result():
if job_data.get("artifact_id"):
    await update_artifact_verdict(
        artifact_id=job_data["artifact_id"],
        verdict=analysis_result["verdict"],
        score=analysis_result["score"],
    )
```

### 9.5 `update_artifact_verdict()` Helper

New function in `worker/src/malscan_worker/db.py`:

```python
async def update_artifact_verdict(
    artifact_id: str,
    verdict: str,
    score: int,
    session: AsyncSession | None = None,
) -> None:
    """Update the denormalized verdict/score on an artifact record.

    Uses a dedicated session if none provided (same pattern as other db helpers).
    """
    async with _get_session(session) as sess:
        stmt = (
            update(Artifact)
            .where(Artifact.id == UUID(artifact_id))
            .values(verdict=verdict, score=score)
        )
        await sess.execute(stmt)
        await sess.commit()
```

## 10. Safety Measures

### 10.1 Zip Bomb Detection

In each `FormatHandler.extract()`:

```python
# Before extracting each file:
if archive_size > 0:
    ratio = declared_uncompressed_size / archive_size
    if ratio > limits.max_expansion_ratio:
        return ExtractionResult(malicious=True, reason=f"Zip bomb: expansion ratio {ratio:.1f}x")
```

For formats that don't declare size upfront (streaming), monitor bytes written:

```python
total_written = 0
for chunk in stream:
    total_written += len(chunk)
    if archive_size > 0 and total_written / archive_size > limits.max_expansion_ratio:
        cleanup()
        return ExtractionResult(malicious=True, reason="Zip bomb: expansion ratio exceeded during extraction")
```

### 10.2 Path Traversal

Already exists. Strengthened:

```python
def _safe_extract_path(base_dir: str, member_name: str) -> str | None:
    target = os.path.normpath(os.path.join(base_dir, member_name))
    if not target.startswith(os.path.abspath(base_dir) + os.sep):
        return None  # path traversal attempt
    if os.path.isabs(member_name):
        return None
    return target
```

### 10.3 Cycle Detection

Tracked via `ancestor_hashes` set propagated through StageContext and MQ messages:

```python
if extracted_sha256 in ctx.ancestor_hashes:
    log.warning("recursive_loop_detected", sha256=extracted_sha256)
    # Create artifact with verdict="skipped", skip sub-job
```

### 10.4 Symlink Rejection

After extraction, before processing:

```python
for root, dirs, files in os.walk(extract_dir):
    for name in files + dirs:
        full_path = os.path.join(root, name)
        if os.path.islink(full_path):
            os.remove(full_path)
            log.warning("symlink_removed", path=full_path)
```

### 10.5 Resource Limits Summary

| Limit | Default | Env Var | Purpose |
|-------|---------|---------|---------|
| Max files per archive | 100 | `EXTRACTION_MAX_FILES` | Limit file count |
| Max total extracted bytes | 500MB | `EXTRACTION_MAX_BYTES` | Limit disk usage |
| Max single file size | 100MB | `EXTRACTION_MAX_SINGLE_BYTES` | Limit per-file size |
| Max expansion ratio | 100x | `EXTRACTION_MAX_RATIO` | Zip bomb detection |
| Extraction timeout | 120s | `EXTRACTION_TIMEOUT` | Prevent hangs |
| Max job depth (existing) | 3 | `MAX_JOB_DEPTH` | Canonical recursion depth limit for entire extraction chain |

> **Note:** `max_job_depth` is the **single canonical depth control**. Every recursive extraction creates a sub-job, so `max_job_depth` directly limits nesting depth. There is no separate `extraction_max_depth` setting. If a future optimisation introduces in-process nested extraction (without sub-jobs), an extraction-local depth limit should be reintroduced at that time.

## 11. Failure Handling & Rollback

| Failure | Behavior |
|---------|----------|
| Extraction throws exception | Artifact NOT created for that file. Stage returns `status="failed"` with error. Pipeline continues. |
| Zip bomb detected | Artifact created with `verdict="malicious"`, `reason` field set. No sub-jobs. |
| Max depth reached | Artifact created with `verdict="skipped"`. No sub-job. |
| Cycle detected | Artifact created with `verdict="skipped"`, `reason="recursive loop"`. No sub-job. |
| Sub-job MQ publish fails | Artifact exists with `job_id=NULL`. Job record marked failed. Artifact shows "unscanned" in tree. |
| Worker crash mid-extraction | Temp files cleaned by `_cleanup_temp_dir()`. Partial artifacts in DB are harmless (verdict=NULL). |
| DB write fails for artifact | Logged as error. Sub-job still submitted (best effort). Artifact missing from tree but job still scanned. |
| Password required | `ArchivePasswordRequiredError` propagates up. Root artifact exists but no children until retry. |

## 12. Test Cases

| # | Name | Input | Expected |
|---|------|-------|----------|
| 1 | Single-layer ZIP, clean | `clean.zip` → `readme.txt` + `data.csv` | 3 artifacts (root + 2 children), all clean |
| 2 | Multi-layer (3 levels) | `outer.zip` → `inner.zip` → `deep.zip` → `file.txt` | 4 artifacts at depth 0-3, tree depth=3 |
| 3 | ZIP with malicious file | `mal.zip` → `trojan.exe` (YARA match) | Root verdict elevated to malicious, tree traces to child |
| 4 | ZIP with clean files only | `safe.zip` → 5 text files | All verdicts clean |
| 5 | Zip bomb | 1KB → 10GB expansion | `malicious=True`, `reason="zip bomb"`, no sub-jobs |
| 6 | Path traversal | Entry `../../etc/passwd` | Entry skipped, warning logged, other entries normal |
| 7 | Password-protected | Encrypted ZIP, no password | `ArchivePasswordRequiredError`, root artifact, no children |
| 8 | Duplicate files (same SHA256) | `a/f.txt` and `b/f.txt` same content | 2 artifacts (different origin_path), 1 sub-job (dedup) |
| 9 | Huge single file | 150MB file in ZIP (limit=100MB) | Artifact with verdict="skipped", other files extracted |
| 10 | Deep nesting > max_depth | 10-level nested, max_depth=5 | Stops at depth 5, skipped artifacts |
| 11 | Recursive loop | ZIP contains itself | Cycle detected, second artifact verdict="skipped" |
| 12 | Mixed formats | ZIP → 7z → DOCX (OLE embed) | 3 extraction sources in tree, correct provenance |

## 13. Files Changed

### New Files

| File | Purpose |
|------|---------|
| `backend/src/malscan/models/artifact.py` | Artifact SQLAlchemy model |
| `backend/alembic/versions/004_add_artifacts_table.py` | DB migration |
| `worker/src/malscan_worker/extractors/__init__.py` | Package init |
| `worker/src/malscan_worker/extractors/base.py` | FormatHandler ABC, ExtractionLimits, ExtractionResult |
| `worker/src/malscan_worker/extractors/registry.py` | HandlerRegistry |
| `worker/src/malscan_worker/extractors/zip_handler.py` | ZIP extraction |
| `worker/src/malscan_worker/extractors/sevenz_handler.py` | 7z extraction |
| `worker/src/malscan_worker/extractors/rar_handler.py` | RAR extraction |
| `worker/src/malscan_worker/extractors/tar_handler.py` | tar extraction |
| `worker/src/malscan_worker/extractors/gzip_handler.py` | gzip extraction |
| `worker/src/malscan_worker/extractors/bz2_handler.py` | bz2 extraction |
| `worker/src/malscan_worker/extractors/iso_handler.py` | ISO stub |
| `worker/tests/test_extractors/` | Unit tests for handlers |
| `worker/tests/test_artifact_tree.py` | Artifact tree creation tests |
| `worker/tests/test_safety_limits.py` | Safety limit tests |

### Modified Files

| File | Change |
|------|--------|
| `backend/src/malscan/models/__init__.py` | Export Artifact |
| `backend/src/malscan/models/job.py` | Add `artifact_id` FK |
| `backend/src/malscan/schemas/requests.py` | Add `ArtifactTreeNode`, update `ReportResponse` |
| `backend/src/malscan/api/routes.py` | Enhance report endpoint to include artifact tree |
| `worker/src/malscan_worker/stages/base.py` | Add artifact fields to StageContext |
| `worker/src/malscan_worker/stages/archive_extract.py` | Use handler registry, create artifacts, cycle detection |
| `worker/src/malscan_worker/stages/document_analysis.py` | Create artifacts for extracted OLE objects |
| `worker/src/malscan_worker/utils/submission.py` | Accept artifact_id, root_artifact_id, ancestor_hashes |
| `worker/src/malscan_worker/pipeline.py` | Pass artifact context, update artifact verdict on completion |
| `worker/src/malscan_worker/consumer.py` | Parse artifact fields from MQ message |
| `worker/src/malscan_worker/config.py` | Add extraction limit settings |
| `worker/src/malscan_worker/db.py` | Add artifact CRUD helpers: `create_artifact()`, `update_artifact_verdict()` |

## 14. Report JSON Example

```json
{
  "job_id": "abc-123",
  "file": {
    "file_id": "file-001",
    "sha256": "aaaa1111...",
    "mime": "application/zip",
    "size": 1048576,
    "original_filename": "suspicious.zip"
  },
  "verdict": "malicious",
  "score": 92,
  "results": {
    "av_result": { "engine": "ClamAV", "infected": false, "threat_name": null },
    "yara_hits": [],
    "iocs": { "urls": [], "domains": [], "ips": [], "hashes": { "md5": "...", "sha1": "...", "sha256": "aaaa1111..." } },
    "document_analysis": {},
    "sandbox": { "executed": false, "behaviors": [], "network_connections": [], "is_mock": true },
    "archive_extract": {
      "archive_type": "zip",
      "extracted_count": 2,
      "sub_jobs_created": 2,
      "total_extracted_bytes": 557056
    }
  },
  "artifact_tree": {
    "id": "art-root",
    "filename": "suspicious.zip",
    "sha256": "aaaa1111...",
    "mime": "application/zip",
    "size": 1048576,
    "depth": 0,
    "origin_path": null,
    "extraction_source": null,
    "archive_type": null,
    "verdict": "malicious",
    "score": 92,
    "job_id": "abc-123",
    "children": [
      {
        "id": "art-child-1",
        "filename": "inner.zip",
        "sha256": "bbbb2222...",
        "mime": "application/zip",
        "size": 524288,
        "depth": 1,
        "origin_path": "inner.zip",
        "extraction_source": "archive-extract",
        "archive_type": "zip",
        "verdict": "malicious",
        "score": 90,
        "job_id": "def-456",
        "children": [
          {
            "id": "art-grandchild-1",
            "filename": "payload.exe",
            "sha256": "cccc3333...",
            "mime": "application/x-dosexec",
            "size": 32768,
            "depth": 2,
            "origin_path": "inner.zip/payload.exe",
            "extraction_source": "archive-extract",
            "archive_type": null,
            "verdict": "malicious",
            "score": 90,
            "job_id": "ghi-789",
            "children": []
          }
        ]
      },
      {
        "id": "art-child-2",
        "filename": "readme.txt",
        "sha256": "dddd4444...",
        "mime": "text/plain",
        "size": 1024,
        "depth": 1,
        "origin_path": "readme.txt",
        "extraction_source": "archive-extract",
        "archive_type": null,
        "verdict": "clean",
        "score": 0,
        "job_id": "jkl-012",
        "children": []
      }
    ]
  },
  "timings": {
    "total_ms": 5432,
    "stages": [
      { "name": "file-type", "status": "ok", "duration_ms": 50 },
      { "name": "clamav", "status": "ok", "duration_ms": 1200 },
      { "name": "yara", "status": "ok", "duration_ms": 300 },
      { "name": "ioc-extract", "status": "ok", "duration_ms": 100 },
      { "name": "archive-extract", "status": "ok", "duration_ms": 2500 },
      { "name": "document-analysis", "status": "skipped", "duration_ms": 10 },
      { "name": "sandbox", "status": "ok", "duration_ms": 1200 }
    ]
  },
  "child_jobs": [
    { "job_id": "def-456", "filename": "inner.zip", "sha256": "bbbb2222...", "status": "done", "verdict": "malicious" },
    { "job_id": "jkl-012", "filename": "readme.txt", "sha256": "dddd4444...", "status": "done", "verdict": "clean" }
  ],
  "created_at": "2026-04-07T10:30:00Z"
}
```

## 15. Migration Strategy

1. Migration `004` creates `artifacts` table and adds `artifact_id` to `jobs`
2. Existing jobs without artifacts continue to work (all new fields are nullable)
3. New jobs get artifact records; old reports simply have `artifact_tree: null`
4. No data backfill required -- forward-compatible only
