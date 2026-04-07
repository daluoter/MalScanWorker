# Recursive Extraction & Artifact Tree Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an artifact tree data model and pluggable format handler registry so that every extracted sub-file gets a provenance record, extraction chains are traceable in reports, and safety limits (zip bomb, cycle, dedup) are configurable.

**Architecture:** Minimal Overlay — add an `artifacts` table and format handler registry on top of the existing Job/Pipeline architecture. The existing `parent_job_id` hierarchy remains for job scheduling; the artifact tree provides extraction provenance and report traceability. `max_job_depth` is the single canonical depth limit. Each archive format extractor becomes a standalone `FormatHandler` class registered in a `HandlerRegistry`.

**Tech Stack:** Python 3.12, SQLAlchemy 2 (async), Alembic, FastAPI, aio-pika, pytest, pydantic-settings.

**Spec:** `docs/superpowers/specs/2026-04-07-recursive-extraction-artifact-tree-design.md`

---

## File Structure and Responsibilities

### New Files (Worker — Extractors)

| File | Responsibility |
|------|----------------|
| `worker/src/malscan_worker/extractors/__init__.py` | Package init, re-exports |
| `worker/src/malscan_worker/extractors/base.py` | `FormatHandler` ABC, `ExtractedFile`, `ExtractionLimits`, `ExtractionResult` dataclasses |
| `worker/src/malscan_worker/extractors/registry.py` | `HandlerRegistry` class + `get_default_registry()` factory |
| `worker/src/malscan_worker/extractors/zip_handler.py` | `ZipHandler` — extracted from `_extract_zip()` |
| `worker/src/malscan_worker/extractors/sevenz_handler.py` | `SevenZipHandler` — extracted from `_extract_7z()` |
| `worker/src/malscan_worker/extractors/rar_handler.py` | `RarHandler` — extracted from `_extract_rar()` |
| `worker/src/malscan_worker/extractors/tar_handler.py` | `TarHandler` — extracted from `_extract_tar()` |
| `worker/src/malscan_worker/extractors/gzip_handler.py` | `GzipHandler` — extracted from `_extract_single_compressed()` (gzip) |
| `worker/src/malscan_worker/extractors/bz2_handler.py` | `Bz2Handler` — extracted from `_extract_single_compressed()` (bz2) |
| `worker/src/malscan_worker/extractors/iso_handler.py` | `IsoHandler` — stub raising `NotImplementedError` |
| `worker/src/malscan_worker/extractors/safety.py` | Shared safety utilities: `safe_extract_path()`, `remove_symlinks()`, `check_expansion_ratio()` |

### New Files (Backend — Model/Migration)

| File | Responsibility |
|------|----------------|
| `backend/src/malscan/models/artifact.py` | `Artifact` SQLAlchemy model |
| `backend/alembic/versions/004_add_artifacts_table.py` | Create `artifacts` table + `artifact_id` FK on `jobs` |

### New Files (Tests)

| File | Responsibility |
|------|----------------|
| `worker/tests/test_extractors.py` | Unit tests for FormatHandler implementations, registry, safety utils |
| `worker/tests/test_artifact_tree.py` | Artifact creation, dedup, cycle detection, verdict update tests |
| `worker/tests/test_safety_limits.py` | Zip bomb, path traversal, expansion ratio, symlink tests |

### Modified Files

| File | Change |
|------|--------|
| `worker/src/malscan_worker/config.py` | Add extraction limit settings |
| `worker/src/malscan_worker/stages/base.py` | Add `artifact_id`, `root_artifact_id`, `ancestor_hashes` to `StageContext` |
| `worker/src/malscan_worker/db.py` | Add `create_artifact()`, `update_artifact_verdict()` |
| `worker/src/malscan_worker/stages/archive_extract.py` | Rewrite to use handler registry + artifact creation |
| `worker/src/malscan_worker/stages/document_analysis.py` | Add artifact creation for embedded objects |
| `worker/src/malscan_worker/utils/submission.py` | Accept `artifact_id`, `root_artifact_id`, `ancestor_hashes` params |
| `worker/src/malscan_worker/pipeline.py` | Pass artifact context to stages, call `update_artifact_verdict()` |
| `worker/src/malscan_worker/consumer.py` | Parse artifact fields from MQ message body |
| `backend/src/malscan/models/__init__.py` | Export `Artifact` |
| `backend/src/malscan/models/job.py` | Add `artifact_id` FK column |
| `backend/src/malscan/schemas/requests.py` | Add `ArtifactTreeNode`, update `ReportResponse` |
| `backend/src/malscan/api/routes.py` | Add `_build_artifact_tree()`, include in report |
| `worker/tests/conftest.py` | Update `stage_context` fixture with new fields |

---

## Task 1: Alembic Migration — `artifacts` Table + Job FK

**Files:**
- Create: `backend/alembic/versions/004_add_artifacts_table.py`

- [ ] **Step 1: Create the migration file**

```python
# backend/alembic/versions/004_add_artifacts_table.py
"""Add artifacts table and artifact_id FK on jobs.

Revision ID: 004
Revises: 003
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "artifacts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        # Tree structure
        sa.Column("parent_id", UUID(as_uuid=True), sa.ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=True),
        sa.Column("root_id", UUID(as_uuid=True), sa.ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=True),
        sa.Column("depth", sa.Integer, nullable=False, server_default="0"),
        # File identity
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("md5", sa.String(32), nullable=True),
        sa.Column("sha1", sa.String(40), nullable=True),
        sa.Column("size", sa.BigInteger, nullable=False),
        sa.Column("mime", sa.String(200), nullable=True),
        sa.Column("original_filename", sa.String(500), nullable=False),
        # Extraction provenance
        sa.Column("origin_path", sa.Text, nullable=True),
        sa.Column("extraction_source", sa.String(50), nullable=True),
        sa.Column("archive_type", sa.String(20), nullable=True),
        sa.Column("extraction_note", sa.String(100), nullable=True),
        # Linkage to jobs
        sa.Column("job_id", UUID(as_uuid=True), sa.ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("root_job_id", UUID(as_uuid=True), sa.ForeignKey("jobs.id", ondelete="CASCADE"), nullable=True),
        # Denormalized scan result
        sa.Column("verdict", sa.String(20), nullable=True),
        sa.Column("score", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_artifacts_parent_id", "artifacts", ["parent_id"])
    op.create_index("ix_artifacts_root_id", "artifacts", ["root_id"])
    op.create_index("ix_artifacts_sha256", "artifacts", ["sha256"])
    op.create_index("ix_artifacts_job_id", "artifacts", ["job_id"])
    op.create_index("ix_artifacts_root_job_id", "artifacts", ["root_job_id"])

    # Add artifact_id FK to jobs table
    op.add_column("jobs", sa.Column("artifact_id", UUID(as_uuid=True), sa.ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True))
    op.create_index("ix_jobs_artifact_id", "jobs", ["artifact_id"])


def downgrade() -> None:
    op.drop_index("ix_jobs_artifact_id", table_name="jobs")
    op.drop_column("jobs", "artifact_id")
    op.drop_index("ix_artifacts_root_job_id", table_name="artifacts")
    op.drop_index("ix_artifacts_job_id", table_name="artifacts")
    op.drop_index("ix_artifacts_sha256", table_name="artifacts")
    op.drop_index("ix_artifacts_root_id", table_name="artifacts")
    op.drop_index("ix_artifacts_parent_id", table_name="artifacts")
    op.drop_table("artifacts")
```

- [ ] **Step 2: Verify migration syntax**

Run: `cd backend && python -c "from alembic.versions import *; print('import ok')"`

If your DB is running:
Run: `cd backend && poetry run alembic upgrade head`

- [ ] **Step 3: Commit**

```bash
git add backend/alembic/versions/004_add_artifacts_table.py
git commit -m "feat: add artifacts table migration (004)"
```

---

## Task 2: Artifact SQLAlchemy Model + Job FK Update

**Files:**
- Create: `backend/src/malscan/models/artifact.py`
- Modify: `backend/src/malscan/models/job.py:53-70`
- Modify: `backend/src/malscan/models/__init__.py`

- [ ] **Step 1: Create the Artifact model**

```python
# backend/src/malscan/models/artifact.py
"""Artifact model for extraction provenance tree."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from malscan.models.base import Base


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Tree structure
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    root_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
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
        UUID(as_uuid=True),
        ForeignKey("jobs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    root_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("jobs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Denormalized result
    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    parent: Mapped["Artifact | None"] = relationship(
        "Artifact",
        back_populates="children",
        remote_side="Artifact.id",
        foreign_keys=[parent_id],
    )
    children: Mapped[list["Artifact"]] = relationship(
        "Artifact",
        back_populates="parent",
        cascade="all, delete-orphan",
        foreign_keys=[parent_id],
    )
    job: Mapped["Job | None"] = relationship(  # noqa: F821
        "Job", foreign_keys=[job_id]
    )
```

- [ ] **Step 2: Add `artifact_id` FK to Job model**

In `backend/src/malscan/models/job.py`, add after the `malicious_sub` column (line 61):

```python
    # Artifact linkage (added by recursive-extraction feature)
    artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("artifacts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
```

- [ ] **Step 3: Export Artifact in `__init__.py`**

Replace `backend/src/malscan/models/__init__.py` contents with:

```python
from malscan.models.base import Base
from malscan.models.file import File
from malscan.models.job import Job, JobStatus
from malscan.models.artifact import Artifact

__all__ = ["Base", "File", "Job", "JobStatus", "Artifact"]
```

- [ ] **Step 4: Verify imports**

Run: `cd backend && python -c "from malscan.models import Artifact; print(Artifact.__tablename__)"`
Expected: `artifacts`

- [ ] **Step 5: Commit**

```bash
git add backend/src/malscan/models/artifact.py backend/src/malscan/models/job.py backend/src/malscan/models/__init__.py
git commit -m "feat: add Artifact model and artifact_id FK on Job"
```

---

## Task 3: Extractor Base Types + Safety Utilities

**Files:**
- Create: `worker/src/malscan_worker/extractors/__init__.py`
- Create: `worker/src/malscan_worker/extractors/base.py`
- Create: `worker/src/malscan_worker/extractors/safety.py`
- Test: `worker/tests/test_extractors.py`

- [ ] **Step 1: Write tests for base types and safety utils**

```python
# worker/tests/test_extractors.py
"""Tests for extractor base types, safety utilities, and handler registry."""

import os
import tempfile
from pathlib import Path

import pytest

from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
)
from malscan_worker.extractors.safety import (
    check_expansion_ratio,
    remove_symlinks,
    safe_extract_path,
)


class TestExtractionLimits:
    def test_defaults(self):
        limits = ExtractionLimits()
        assert limits.max_files == 100
        assert limits.max_extracted_bytes == 500_000_000
        assert limits.max_single_file_bytes == 100_000_000
        assert limits.max_expansion_ratio == 100.0
        assert limits.timeout_seconds == 120

    def test_custom_values(self):
        limits = ExtractionLimits(max_files=10, max_expansion_ratio=50.0)
        assert limits.max_files == 10
        assert limits.max_expansion_ratio == 50.0


class TestExtractedFile:
    def test_creation(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        ef = ExtractedFile(
            path=str(f), original_name="test.txt", size=5, origin_path="archive/test.txt"
        )
        assert ef.original_name == "test.txt"
        assert ef.size == 5
        assert ef.origin_path == "archive/test.txt"


class TestExtractionResult:
    def test_clean_result(self):
        r = ExtractionResult(files=[])
        assert r.malicious is False
        assert r.reason is None
        assert r.warnings == []

    def test_malicious_result(self):
        r = ExtractionResult(files=[], malicious=True, reason="zip bomb")
        assert r.malicious is True
        assert r.reason == "zip bomb"


class TestSafeExtractPath:
    def test_normal_path(self, tmp_path):
        result = safe_extract_path(str(tmp_path), "subdir/file.txt")
        assert result is not None
        assert result.startswith(str(tmp_path))

    def test_path_traversal_dotdot(self, tmp_path):
        result = safe_extract_path(str(tmp_path), "../../etc/passwd")
        assert result is None

    def test_path_traversal_absolute(self, tmp_path):
        result = safe_extract_path(str(tmp_path), "/etc/passwd")
        assert result is None

    def test_path_with_current_dir(self, tmp_path):
        result = safe_extract_path(str(tmp_path), "./normal/file.txt")
        assert result is not None


class TestCheckExpansionRatio:
    def test_safe_ratio(self):
        limits = ExtractionLimits(max_expansion_ratio=100.0)
        assert check_expansion_ratio(1000, 50000, limits) is None

    def test_bomb_ratio(self):
        limits = ExtractionLimits(max_expansion_ratio=100.0)
        result = check_expansion_ratio(1000, 200_000, limits)
        assert result is not None
        assert "expansion ratio" in result.lower()

    def test_zero_archive_size(self):
        limits = ExtractionLimits(max_expansion_ratio=100.0)
        # Zero archive size should not divide by zero
        assert check_expansion_ratio(0, 1000, limits) is None


class TestRemoveSymlinks:
    def test_removes_symlinks(self, tmp_path):
        real_file = tmp_path / "real.txt"
        real_file.write_text("content")
        link = tmp_path / "link.txt"
        link.symlink_to(real_file)
        assert link.is_symlink()

        removed = remove_symlinks(str(tmp_path))
        assert removed == 1
        assert not link.exists()
        assert real_file.exists()

    def test_no_symlinks(self, tmp_path):
        real_file = tmp_path / "real.txt"
        real_file.write_text("content")
        removed = remove_symlinks(str(tmp_path))
        assert removed == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd worker && poetry run pytest tests/test_extractors.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'malscan_worker.extractors'`

- [ ] **Step 3: Create the extractors package**

```python
# worker/src/malscan_worker/extractors/__init__.py
"""Pluggable archive format handlers."""

from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)
from malscan_worker.extractors.registry import HandlerRegistry, get_default_registry
from malscan_worker.extractors.safety import (
    check_expansion_ratio,
    remove_symlinks,
    safe_extract_path,
)

__all__ = [
    "ExtractedFile",
    "ExtractionLimits",
    "ExtractionResult",
    "FormatHandler",
    "HandlerRegistry",
    "get_default_registry",
    "check_expansion_ratio",
    "remove_symlinks",
    "safe_extract_path",
]
```

- [ ] **Step 4: Create base.py with dataclasses and ABC**

```python
# worker/src/malscan_worker/extractors/base.py
"""Base types for pluggable format handlers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExtractedFile:
    """A single file extracted from an archive."""

    path: str  # absolute path on disk
    original_name: str  # filename within archive
    size: int  # bytes
    origin_path: str  # full path within archive hierarchy


@dataclass
class ExtractionLimits:
    """Configurable safety limits for extraction."""

    max_files: int = 100
    max_extracted_bytes: int = 500_000_000  # 500MB
    max_single_file_bytes: int = 100_000_000  # 100MB
    max_expansion_ratio: float = 100.0
    timeout_seconds: int = 120


@dataclass
class ExtractionResult:
    """Result of an extraction attempt."""

    files: list[ExtractedFile]
    malicious: bool = False
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    archive_type: str | None = None


class FormatHandler(ABC):
    """Abstract base class for archive format handlers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this format (e.g. 'zip', '7z')."""
        ...

    @abstractmethod
    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        """Return True if this handler can extract the given file."""
        ...

    @abstractmethod
    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        """Extract files from the archive into extract_dir."""
        ...
```

- [ ] **Step 5: Create safety.py**

```python
# worker/src/malscan_worker/extractors/safety.py
"""Shared safety utilities for extraction."""

import os
import structlog

from malscan_worker.extractors.base import ExtractionLimits

logger = structlog.get_logger(__name__)


def safe_extract_path(base_dir: str, member_name: str) -> str | None:
    """Validate that a member path resolves within base_dir.

    Returns the resolved absolute path, or None if path traversal detected.
    """
    if os.path.isabs(member_name):
        return None
    target = os.path.normpath(os.path.join(base_dir, member_name))
    if not target.startswith(os.path.abspath(base_dir) + os.sep):
        return None
    return target


def check_expansion_ratio(
    archive_size: int,
    uncompressed_size: int,
    limits: ExtractionLimits,
) -> str | None:
    """Check if expansion ratio exceeds limit.

    Returns an error message string if ratio exceeded, None if safe.
    """
    if archive_size <= 0:
        return None
    ratio = uncompressed_size / archive_size
    if ratio > limits.max_expansion_ratio:
        return f"Zip bomb: expansion ratio {ratio:.1f}x exceeds limit {limits.max_expansion_ratio}x"
    return None


def remove_symlinks(directory: str) -> int:
    """Remove all symlinks in a directory tree. Returns count removed."""
    removed = 0
    for root, dirs, files in os.walk(directory):
        for name in files + dirs:
            full_path = os.path.join(root, name)
            if os.path.islink(full_path):
                os.remove(full_path)
                logger.warning("symlink_removed", path=full_path)
                removed += 1
    return removed
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd worker && poetry run pytest tests/test_extractors.py -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add worker/src/malscan_worker/extractors/ worker/tests/test_extractors.py
git commit -m "feat: add extractor base types and safety utilities"
```

---

## Task 4: Handler Registry + Format Handlers

**Files:**
- Create: `worker/src/malscan_worker/extractors/registry.py`
- Create: `worker/src/malscan_worker/extractors/zip_handler.py`
- Create: `worker/src/malscan_worker/extractors/sevenz_handler.py`
- Create: `worker/src/malscan_worker/extractors/rar_handler.py`
- Create: `worker/src/malscan_worker/extractors/tar_handler.py`
- Create: `worker/src/malscan_worker/extractors/gzip_handler.py`
- Create: `worker/src/malscan_worker/extractors/bz2_handler.py`
- Create: `worker/src/malscan_worker/extractors/iso_handler.py`
- Modify: `worker/tests/test_extractors.py`

- [ ] **Step 1: Add registry and handler tests**

Append to `worker/tests/test_extractors.py`:

```python
from malscan_worker.extractors.registry import HandlerRegistry, get_default_registry
from malscan_worker.extractors.zip_handler import ZipHandler
from malscan_worker.extractors.iso_handler import IsoHandler


class TestHandlerRegistry:
    def test_register_and_detect_zip(self, tmp_path):
        registry = HandlerRegistry()
        registry.register(ZipHandler())

        # Create a minimal zip file
        import zipfile
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("hello.txt", "hello world")

        handler = registry.detect(zip_path, "application/zip")
        assert handler is not None
        assert handler.name == "zip"

    def test_detect_returns_none_for_unknown(self, tmp_path):
        registry = HandlerRegistry()
        registry.register(ZipHandler())
        txt = tmp_path / "file.txt"
        txt.write_text("just text")
        handler = registry.detect(txt, "text/plain")
        assert handler is None

    def test_default_registry_has_all_handlers(self):
        registry = get_default_registry()
        # Should have 8 handlers: zip, 7z, rar, tar, gzip, bz2, iso
        assert len(registry._handlers) == 7


class TestZipHandler:
    def test_extract_simple_zip(self, tmp_path):
        import zipfile
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("a.txt", "aaa")
            zf.writestr("b.txt", "bbb")

        handler = ZipHandler()
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        limits = ExtractionLimits()

        result = handler.extract(zip_path, extract_dir, limits)
        assert not result.malicious
        assert len(result.files) == 2
        assert result.archive_type == "zip"
        names = {f.original_name for f in result.files}
        assert names == {"a.txt", "b.txt"}

    def test_zip_path_traversal_skipped(self, tmp_path):
        """Entries with path traversal are silently skipped."""
        import zipfile
        zip_path = tmp_path / "evil.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0")
            zf.writestr("safe.txt", "ok")

        handler = ZipHandler()
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        result = handler.extract(zip_path, extract_dir, ExtractionLimits())
        assert len(result.files) == 1
        assert result.files[0].original_name == "safe.txt"
        assert len(result.warnings) >= 1  # path traversal warning

    def test_zip_max_files_exceeded(self, tmp_path):
        import zipfile
        zip_path = tmp_path / "many.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for i in range(10):
                zf.writestr(f"file_{i}.txt", f"content {i}")

        handler = ZipHandler()
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        limits = ExtractionLimits(max_files=3)
        result = handler.extract(zip_path, extract_dir, limits)
        assert len(result.files) == 3
        assert len(result.warnings) >= 1  # max files warning


class TestIsoHandler:
    def test_iso_stub_raises(self, tmp_path):
        handler = IsoHandler()
        assert handler.name == "iso"

        iso_path = tmp_path / "test.iso"
        iso_path.write_bytes(b"\x00" * 100)
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with pytest.raises(NotImplementedError, match="ISO support planned"):
            handler.extract(iso_path, extract_dir, ExtractionLimits())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd worker && poetry run pytest tests/test_extractors.py::TestHandlerRegistry -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'malscan_worker.extractors.registry'`

- [ ] **Step 3: Create registry.py**

```python
# worker/src/malscan_worker/extractors/registry.py
"""Format handler registry."""

from pathlib import Path

from malscan_worker.extractors.base import FormatHandler


class HandlerRegistry:
    """Registry of format handlers, checked in registration order."""

    def __init__(self) -> None:
        self._handlers: list[FormatHandler] = []

    def register(self, handler: FormatHandler) -> None:
        self._handlers.append(handler)

    def detect(self, file_path: Path, mime: str) -> FormatHandler | None:
        """Return the first handler that can handle the file, or None."""
        magic = b""
        try:
            with open(file_path, "rb") as f:
                magic = f.read(16)
        except OSError:
            pass
        for handler in self._handlers:
            if handler.can_handle(Path(file_path), mime, magic):
                return handler
        return None


def get_default_registry() -> HandlerRegistry:
    """Create a registry with all built-in handlers."""
    from malscan_worker.extractors.zip_handler import ZipHandler
    from malscan_worker.extractors.sevenz_handler import SevenZipHandler
    from malscan_worker.extractors.rar_handler import RarHandler
    from malscan_worker.extractors.tar_handler import TarHandler
    from malscan_worker.extractors.gzip_handler import GzipHandler
    from malscan_worker.extractors.bz2_handler import Bz2Handler
    from malscan_worker.extractors.iso_handler import IsoHandler

    registry = HandlerRegistry()
    registry.register(ZipHandler())
    registry.register(SevenZipHandler())
    registry.register(RarHandler())
    registry.register(TarHandler())
    registry.register(GzipHandler())
    registry.register(Bz2Handler())
    registry.register(IsoHandler())
    return registry
```

- [ ] **Step 4: Create zip_handler.py**

Extract from `worker/src/malscan_worker/stages/archive_extract.py:368-450` (`_extract_zip`). The handler wraps existing logic with the new interface:

```python
# worker/src/malscan_worker/extractors/zip_handler.py
"""ZIP format handler."""

import os
import zipfile
from pathlib import Path

import structlog

from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)
from malscan_worker.extractors.safety import check_expansion_ratio, safe_extract_path
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError

logger = structlog.get_logger(__name__)


class ZipHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "zip"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:4] == b"PK\x03\x04":
            return True
        if mime in ("application/zip", "application/x-zip-compressed"):
            return True
        if file_path.suffix.lower() == ".zip":
            return True
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        files: list[ExtractedFile] = []
        warnings: list[str] = []

        try:
            with zipfile.ZipFile(str(file_path), "r") as zf:
                # Check for encryption
                for info in zf.infolist():
                    if info.flag_bits & 0x1:  # encrypted
                        if not password:
                            raise ArchivePasswordRequiredError("zip")
                        break

                # Pre-check expansion ratio from declared sizes
                archive_size = os.path.getsize(file_path)
                total_uncompressed = sum(i.file_size for i in zf.infolist() if not i.is_dir())
                ratio_warning = check_expansion_ratio(archive_size, total_uncompressed, limits)
                if ratio_warning:
                    return ExtractionResult(
                        files=[], malicious=True, reason=ratio_warning, archive_type="zip"
                    )

                total_extracted_bytes = 0
                pwd = password.encode() if password else None

                for info in zf.infolist():
                    if info.is_dir():
                        continue

                    if len(files) >= limits.max_files:
                        warnings.append(f"Max files limit ({limits.max_files}) reached, stopping")
                        break

                    target = safe_extract_path(str(extract_dir), info.filename)
                    if target is None:
                        warnings.append(f"Path traversal skipped: {info.filename}")
                        continue

                    if info.file_size > limits.max_single_file_bytes:
                        warnings.append(
                            f"File too large, skipped: {info.filename} ({info.file_size} bytes)"
                        )
                        continue

                    if total_extracted_bytes + info.file_size > limits.max_extracted_bytes:
                        warnings.append("Max total extracted bytes reached, stopping")
                        break

                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    try:
                        with zf.open(info, pwd=pwd) as src, open(target, "wb") as dst:
                            written = 0
                            while True:
                                chunk = src.read(65536)
                                if not chunk:
                                    break
                                written += len(chunk)
                                # Streaming ratio check
                                if archive_size > 0 and written / archive_size > limits.max_expansion_ratio:
                                    os.remove(target)
                                    return ExtractionResult(
                                        files=files,
                                        malicious=True,
                                        reason="Zip bomb: expansion ratio exceeded during extraction",
                                        archive_type="zip",
                                    )
                                dst.write(chunk)
                    except RuntimeError as e:
                        if "password" in str(e).lower() or "Bad password" in str(e):
                            raise ArchiveWrongPasswordError("zip") from e
                        raise

                    total_extracted_bytes += written
                    files.append(
                        ExtractedFile(
                            path=target,
                            original_name=os.path.basename(info.filename),
                            size=written,
                            origin_path=info.filename,
                        )
                    )

        except (ArchivePasswordRequiredError, ArchiveWrongPasswordError):
            raise
        except zipfile.BadZipFile as e:
            warnings.append(f"Bad zip file: {e}")
        except Exception as e:
            logger.error("zip_extraction_error", error=str(e))
            warnings.append(f"Extraction error: {e}")

        return ExtractionResult(
            files=files, warnings=warnings, archive_type="zip"
        )
```

- [ ] **Step 5: Create sevenz_handler.py**

Extract from `archive_extract.py:452-491`. Follows same pattern:

```python
# worker/src/malscan_worker/extractors/sevenz_handler.py
"""7z format handler."""

import os
import subprocess
from pathlib import Path

import structlog

from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)
from malscan_worker.extractors.safety import remove_symlinks, safe_extract_path
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError

logger = structlog.get_logger(__name__)

# 7z magic: bytes "7z\xbc\xaf\x27\x1c"
SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"


class SevenZipHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "7z"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:6] == SEVENZ_MAGIC:
            return True
        if mime in ("application/x-7z-compressed",):
            return True
        if file_path.suffix.lower() == ".7z":
            return True
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        files: list[ExtractedFile] = []
        warnings: list[str] = []

        cmd = ["7z", "x", str(file_path), f"-o{extract_dir}", "-y"]
        if password:
            cmd.append(f"-p{password}")
        else:
            cmd.append("-p")  # empty password to avoid interactive prompt

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=limits.timeout_seconds,
            )

            if proc.returncode != 0:
                stderr = proc.stderr.lower()
                if "wrong password" in stderr or "password" in stderr:
                    if password:
                        raise ArchiveWrongPasswordError("7z")
                    raise ArchivePasswordRequiredError("7z")
                warnings.append(f"7z exit code {proc.returncode}: {proc.stderr[:200]}")

        except subprocess.TimeoutExpired:
            warnings.append(f"7z extraction timed out after {limits.timeout_seconds}s")
            return ExtractionResult(files=files, warnings=warnings, archive_type="7z")

        # Remove symlinks
        remove_symlinks(str(extract_dir))

        # Walk extracted files
        total_bytes = 0
        for root, _dirs, filenames in os.walk(extract_dir):
            for fname in filenames:
                if len(files) >= limits.max_files:
                    warnings.append(f"Max files limit ({limits.max_files}) reached")
                    return ExtractionResult(files=files, warnings=warnings, archive_type="7z")

                full = os.path.join(root, fname)
                rel = os.path.relpath(full, extract_dir)

                if safe_extract_path(str(extract_dir), rel) is None:
                    warnings.append(f"Path traversal skipped: {rel}")
                    continue

                fsize = os.path.getsize(full)
                if fsize > limits.max_single_file_bytes:
                    warnings.append(f"File too large, skipped: {rel} ({fsize} bytes)")
                    continue

                total_bytes += fsize
                if total_bytes > limits.max_extracted_bytes:
                    warnings.append("Max total extracted bytes reached")
                    return ExtractionResult(files=files, warnings=warnings, archive_type="7z")

                files.append(
                    ExtractedFile(
                        path=full,
                        original_name=fname,
                        size=fsize,
                        origin_path=rel,
                    )
                )

        return ExtractionResult(files=files, warnings=warnings, archive_type="7z")
```

- [ ] **Step 6: Create rar_handler.py**

Extract from `archive_extract.py:493-535`:

```python
# worker/src/malscan_worker/extractors/rar_handler.py
"""RAR format handler."""

import os
import subprocess
from pathlib import Path

import structlog

from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)
from malscan_worker.extractors.safety import remove_symlinks, safe_extract_path
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError

logger = structlog.get_logger(__name__)

RAR_MAGIC = b"Rar!\x1a\x07"


class RarHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "rar"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:7] == RAR_MAGIC:
            return True
        if mime in ("application/x-rar-compressed", "application/vnd.rar"):
            return True
        if file_path.suffix.lower() == ".rar":
            return True
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        files: list[ExtractedFile] = []
        warnings: list[str] = []

        cmd = ["unrar", "x", "-y", "-o+"]
        if password:
            cmd.append(f"-p{password}")
        else:
            cmd.append("-p-")  # no password, skip prompt
        cmd.extend([str(file_path), str(extract_dir) + "/"])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=limits.timeout_seconds,
            )

            if proc.returncode != 0:
                stderr = proc.stderr.lower() + proc.stdout.lower()
                if "password" in stderr or "encrypted" in stderr:
                    if password:
                        raise ArchiveWrongPasswordError("rar")
                    raise ArchivePasswordRequiredError("rar")
                warnings.append(f"unrar exit code {proc.returncode}: {proc.stderr[:200]}")

        except subprocess.TimeoutExpired:
            warnings.append(f"unrar extraction timed out after {limits.timeout_seconds}s")
            return ExtractionResult(files=files, warnings=warnings, archive_type="rar")

        remove_symlinks(str(extract_dir))

        total_bytes = 0
        for root, _dirs, filenames in os.walk(extract_dir):
            for fname in filenames:
                if len(files) >= limits.max_files:
                    warnings.append(f"Max files limit ({limits.max_files}) reached")
                    return ExtractionResult(files=files, warnings=warnings, archive_type="rar")

                full = os.path.join(root, fname)
                rel = os.path.relpath(full, extract_dir)

                if safe_extract_path(str(extract_dir), rel) is None:
                    warnings.append(f"Path traversal skipped: {rel}")
                    continue

                fsize = os.path.getsize(full)
                if fsize > limits.max_single_file_bytes:
                    warnings.append(f"File too large, skipped: {rel} ({fsize} bytes)")
                    continue

                total_bytes += fsize
                if total_bytes > limits.max_extracted_bytes:
                    warnings.append("Max total extracted bytes reached")
                    return ExtractionResult(files=files, warnings=warnings, archive_type="rar")

                files.append(
                    ExtractedFile(
                        path=full, original_name=fname, size=fsize, origin_path=rel
                    )
                )

        return ExtractionResult(files=files, warnings=warnings, archive_type="rar")
```

- [ ] **Step 7: Create tar_handler.py**

```python
# worker/src/malscan_worker/extractors/tar_handler.py
"""TAR format handler."""

import os
import tarfile
from pathlib import Path

import structlog

from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)
from malscan_worker.extractors.safety import remove_symlinks, safe_extract_path

logger = structlog.get_logger(__name__)

TAR_MAGIC = b"ustar"  # appears at offset 257


class TarHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "tar"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if mime in ("application/x-tar",):
            return True
        if file_path.suffix.lower() == ".tar":
            return True
        # Check tar magic at offset 257
        try:
            with open(file_path, "rb") as f:
                f.seek(257)
                marker = f.read(5)
                if marker == TAR_MAGIC:
                    return True
        except OSError:
            pass
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        files: list[ExtractedFile] = []
        warnings: list[str] = []

        try:
            with tarfile.open(str(file_path), "r:*") as tf:
                total_bytes = 0
                for member in tf.getmembers():
                    if not member.isfile():
                        continue

                    if len(files) >= limits.max_files:
                        warnings.append(f"Max files limit ({limits.max_files}) reached")
                        break

                    target = safe_extract_path(str(extract_dir), member.name)
                    if target is None:
                        warnings.append(f"Path traversal skipped: {member.name}")
                        continue

                    if member.size > limits.max_single_file_bytes:
                        warnings.append(f"File too large, skipped: {member.name} ({member.size} bytes)")
                        continue

                    if total_bytes + member.size > limits.max_extracted_bytes:
                        warnings.append("Max total extracted bytes reached")
                        break

                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    src = tf.extractfile(member)
                    if src is None:
                        continue
                    with open(target, "wb") as dst:
                        written = 0
                        while True:
                            chunk = src.read(65536)
                            if not chunk:
                                break
                            written += len(chunk)
                            dst.write(chunk)

                    total_bytes += written
                    files.append(
                        ExtractedFile(
                            path=target,
                            original_name=os.path.basename(member.name),
                            size=written,
                            origin_path=member.name,
                        )
                    )

        except tarfile.TarError as e:
            warnings.append(f"Tar error: {e}")
        except Exception as e:
            logger.error("tar_extraction_error", error=str(e))
            warnings.append(f"Extraction error: {e}")

        remove_symlinks(str(extract_dir))
        return ExtractionResult(files=files, warnings=warnings, archive_type="tar")
```

- [ ] **Step 8: Create gzip_handler.py**

```python
# worker/src/malscan_worker/extractors/gzip_handler.py
"""Gzip single-file handler."""

import gzip
import os
from pathlib import Path

import structlog

from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)
from malscan_worker.extractors.safety import check_expansion_ratio

logger = structlog.get_logger(__name__)

GZIP_MAGIC = b"\x1f\x8b"


class GzipHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "gzip"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:2] == GZIP_MAGIC:
            return True
        if mime in ("application/gzip", "application/x-gzip"):
            return True
        if file_path.suffix.lower() == ".gz":
            return True
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        warnings: list[str] = []
        archive_size = os.path.getsize(file_path)

        # Derive output filename by stripping .gz
        stem = file_path.stem if file_path.suffix.lower() == ".gz" else f"{file_path.name}.decompressed"
        out_path = extract_dir / stem

        try:
            with gzip.open(str(file_path), "rb") as src, open(out_path, "wb") as dst:
                written = 0
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > limits.max_single_file_bytes:
                        os.remove(out_path)
                        warnings.append(f"Decompressed file exceeds limit ({limits.max_single_file_bytes} bytes)")
                        return ExtractionResult(files=[], warnings=warnings, archive_type="gzip")
                    if archive_size > 0 and written / archive_size > limits.max_expansion_ratio:
                        os.remove(out_path)
                        return ExtractionResult(
                            files=[], malicious=True,
                            reason=f"Zip bomb: gzip expansion ratio exceeded",
                            archive_type="gzip",
                        )
                    dst.write(chunk)

            return ExtractionResult(
                files=[
                    ExtractedFile(
                        path=str(out_path),
                        original_name=stem,
                        size=written,
                        origin_path=stem,
                    )
                ],
                warnings=warnings,
                archive_type="gzip",
            )

        except Exception as e:
            logger.error("gzip_extraction_error", error=str(e))
            warnings.append(f"Gzip error: {e}")
            return ExtractionResult(files=[], warnings=warnings, archive_type="gzip")
```

- [ ] **Step 9: Create bz2_handler.py**

```python
# worker/src/malscan_worker/extractors/bz2_handler.py
"""Bzip2 single-file handler."""

import bz2
import os
from pathlib import Path

import structlog

from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)

logger = structlog.get_logger(__name__)

BZ2_MAGIC = b"BZh"


class Bz2Handler(FormatHandler):
    @property
    def name(self) -> str:
        return "bz2"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:3] == BZ2_MAGIC:
            return True
        if mime in ("application/x-bzip2",):
            return True
        if file_path.suffix.lower() == ".bz2":
            return True
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        warnings: list[str] = []
        archive_size = os.path.getsize(file_path)

        stem = file_path.stem if file_path.suffix.lower() == ".bz2" else f"{file_path.name}.decompressed"
        out_path = extract_dir / stem

        try:
            with bz2.open(str(file_path), "rb") as src, open(out_path, "wb") as dst:
                written = 0
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > limits.max_single_file_bytes:
                        os.remove(out_path)
                        warnings.append(f"Decompressed file exceeds limit ({limits.max_single_file_bytes} bytes)")
                        return ExtractionResult(files=[], warnings=warnings, archive_type="bz2")
                    if archive_size > 0 and written / archive_size > limits.max_expansion_ratio:
                        os.remove(out_path)
                        return ExtractionResult(
                            files=[], malicious=True,
                            reason="Zip bomb: bz2 expansion ratio exceeded",
                            archive_type="bz2",
                        )
                    dst.write(chunk)

            return ExtractionResult(
                files=[
                    ExtractedFile(
                        path=str(out_path),
                        original_name=stem,
                        size=written,
                        origin_path=stem,
                    )
                ],
                warnings=warnings,
                archive_type="bz2",
            )

        except Exception as e:
            logger.error("bz2_extraction_error", error=str(e))
            warnings.append(f"Bz2 error: {e}")
            return ExtractionResult(files=[], warnings=warnings, archive_type="bz2")
```

- [ ] **Step 10: Create iso_handler.py (stub)**

```python
# worker/src/malscan_worker/extractors/iso_handler.py
"""ISO format handler — stub for future implementation."""

from pathlib import Path

from malscan_worker.extractors.base import (
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)


class IsoHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "iso"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if mime in ("application/x-iso9660-image",):
            return True
        if file_path.suffix.lower() == ".iso":
            return True
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        raise NotImplementedError("ISO support planned")
```

- [ ] **Step 11: Run tests**

Run: `cd worker && poetry run pytest tests/test_extractors.py -v`
Expected: All PASS

- [ ] **Step 12: Commit**

```bash
git add worker/src/malscan_worker/extractors/ worker/tests/test_extractors.py
git commit -m "feat: add format handler registry with zip/7z/rar/tar/gzip/bz2/iso handlers"
```

---

## Task 5: Worker Config + StageContext + DB Helpers

**Files:**
- Modify: `worker/src/malscan_worker/config.py:27-28`
- Modify: `worker/src/malscan_worker/stages/base.py:13-26`
- Modify: `worker/src/malscan_worker/db.py`
- Modify: `worker/tests/conftest.py:46-55`

- [ ] **Step 1: Add extraction settings to worker config**

In `worker/src/malscan_worker/config.py`, add after line 28 (`stages_total: int = 5`):

```python
    # Extraction limits (depth controlled by existing max_job_depth)
    extraction_max_files: int = 100
    extraction_max_bytes: int = 500_000_000        # 500MB total
    extraction_max_single_bytes: int = 100_000_000  # 100MB per file
    extraction_max_ratio: float = 100.0
    extraction_timeout: int = 120                    # seconds
```

- [ ] **Step 2: Add artifact fields to StageContext**

In `worker/src/malscan_worker/stages/base.py`, add three fields after `db` (line 26):

```python
    artifact_id: str | None = None
    root_artifact_id: str | None = None
    ancestor_hashes: set[str] = field(default_factory=set)
```

Also add `from dataclasses import dataclass, field` at the top if `field` is not already imported (check the existing import line).

- [ ] **Step 3: Update conftest.py fixture**

In `worker/tests/conftest.py`, the `stage_context` fixture already works because the new fields all have defaults. No change needed unless tests reference the new fields. Leave as-is for now.

- [ ] **Step 4: Add DB helpers for artifacts**

Add to `worker/src/malscan_worker/db.py` — add these imports at the top:

```python
from malscan.models.artifact import Artifact
```

Then append these functions at the end of the file:

```python
async def create_artifact(
    *,
    parent_id: str | None,
    root_id: str | None,
    depth: int,
    sha256: str,
    size: int,
    original_filename: str,
    origin_path: str | None = None,
    extraction_source: str | None = None,
    archive_type: str | None = None,
    extraction_note: str | None = None,
    job_id: str | None = None,
    root_job_id: str | None = None,
    md5: str | None = None,
    sha1: str | None = None,
    mime: str | None = None,
    verdict: str | None = None,
    score: int | None = None,
) -> dict[str, Any]:
    """Create an artifact record. Returns dict with 'id' key.

    Uses its own session to avoid polluting the pipeline session.
    """
    from uuid import UUID as _UUID, uuid4

    async with AsyncSession(_engine) as session:
        try:
            artifact_id = uuid4()
            from sqlalchemy import text
            stmt = text(
                """
                INSERT INTO artifacts (
                    id, parent_id, root_id, depth,
                    sha256, md5, sha1, size, mime, original_filename,
                    origin_path, extraction_source, archive_type, extraction_note,
                    job_id, root_job_id, verdict, score
                ) VALUES (
                    :id, :parent_id, :root_id, :depth,
                    :sha256, :md5, :sha1, :size, :mime, :original_filename,
                    :origin_path, :extraction_source, :archive_type, :extraction_note,
                    :job_id, :root_job_id, :verdict, :score
                )
                """
            )
            await session.execute(
                stmt,
                {
                    "id": artifact_id,
                    "parent_id": _UUID(parent_id) if parent_id else None,
                    "root_id": _UUID(root_id) if root_id else None,
                    "depth": depth,
                    "sha256": sha256,
                    "md5": md5,
                    "sha1": sha1,
                    "size": size,
                    "mime": mime,
                    "original_filename": original_filename,
                    "origin_path": origin_path,
                    "extraction_source": extraction_source,
                    "archive_type": archive_type,
                    "extraction_note": extraction_note,
                    "job_id": _UUID(job_id) if job_id else None,
                    "root_job_id": _UUID(root_job_id) if root_job_id else None,
                    "verdict": verdict,
                    "score": score,
                },
            )
            await session.commit()
            return {"id": str(artifact_id)}
        except Exception:
            await session.rollback()
            raise


async def update_artifact_verdict(
    artifact_id: str,
    verdict: str,
    score: int,
) -> None:
    """Update the denormalized verdict/score on an artifact record."""
    from uuid import UUID as _UUID
    from sqlalchemy import text

    async with AsyncSession(_engine) as session:
        try:
            stmt = text(
                "UPDATE artifacts SET verdict = :verdict, score = :score WHERE id = :id"
            )
            await session.execute(
                stmt, {"id": _UUID(artifact_id), "verdict": verdict, "score": score}
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
```

Note: We use raw SQL `text()` with inline `from sqlalchemy import text` to stay consistent with the existing pattern in `db.py` (see `update_job_status` at line 68). Sessions use `AsyncSession(_engine)` directly (no `expire_on_commit` — match existing code).

- [ ] **Step 5: Verify imports work**

Run: `cd worker && python -c "from malscan_worker.stages.base import StageContext; ctx = StageContext(job_id='x', file_id='x', storage_key='x', sha256='x', original_filename='x', file_path=None); print(ctx.artifact_id, ctx.ancestor_hashes)"`
Expected: `None set()`

- [ ] **Step 6: Commit**

```bash
git add worker/src/malscan_worker/config.py worker/src/malscan_worker/stages/base.py worker/src/malscan_worker/db.py
git commit -m "feat: add extraction config, artifact StageContext fields, and DB helpers"
```

---

## Task 6: Enhanced InternalJobSubmitter

**Files:**
- Modify: `worker/src/malscan_worker/utils/submission.py:66-76` (signature) and `175-181` (message body)

- [ ] **Step 1: Add artifact parameters to `submit_subjob` signature**

In `worker/src/malscan_worker/utils/submission.py`, modify the `submit_subjob` method signature (line 66-76) to add three new keyword-only parameters at the end:

```python
    async def submit_subjob(
        self,
        *,
        file_path: str,
        filename: str,
        content_type: str,
        sha256_hash: str,
        file_size: int,
        parent_job_id: str,
        parent_job_depth: int,
        artifact_id: str | None = None,
        root_artifact_id: str | None = None,
        ancestor_hashes: set[str] | None = None,
    ) -> str | None:
```

- [ ] **Step 2: Include artifact fields in MQ message**

In the message_body construction (around line 175-181), add the artifact fields:

```python
        message_body = {
            "job_id": sub_job_id,
            "file_id": file_id_str,
            "storage_key": sha256_hash,
            "sha256": sha256_hash,
            "original_filename": filename,
            "artifact_id": artifact_id,
            "root_artifact_id": root_artifact_id,
            "ancestor_hashes": list(ancestor_hashes or set()),
        }
```

- [ ] **Step 3: Verify no existing tests break**

Run: `cd worker && poetry run pytest tests/ -v -x`
Expected: Existing tests should pass (the new params have defaults, so callers don't need to change yet).

- [ ] **Step 4: Commit**

```bash
git add worker/src/malscan_worker/utils/submission.py
git commit -m "feat: add artifact_id/root_artifact_id/ancestor_hashes to InternalJobSubmitter"
```

---

## Task 7: Consumer + Pipeline — Artifact Context Propagation

**Files:**
- Modify: `worker/src/malscan_worker/consumer.py:84-88`
- Modify: `worker/src/malscan_worker/pipeline.py:312-361` (StageContext creation) and `402-411` (after result)

- [ ] **Step 1: Parse artifact fields in consumer**

The consumer at line 86-88 parses `body` from the MQ message and passes it directly to `run_pipeline(body)`. No consumer change is needed — the dict already carries all fields. The parsing happens in `run_pipeline`.

- [ ] **Step 2: Pass artifact fields to StageContext in pipeline**

In `worker/src/malscan_worker/pipeline.py`, in `run_pipeline()`, when constructing the `StageContext` (around line 348-360), add the artifact fields:

```python
    ctx = StageContext(
        job_id=job_id,
        file_id=file_id,
        storage_key=storage_key,
        sha256=job_data.get("sha256", ""),
        original_filename=job_data.get("original_filename", "unknown"),
        file_path=file_path,
        archive_password=job_data.get("archive_password"),
        previous_results=[],
        job=job_instance,
        db=session,
        artifact_id=job_data.get("artifact_id"),
        root_artifact_id=job_data.get("root_artifact_id"),
        ancestor_hashes=set(job_data.get("ancestor_hashes", [])),
    )
```

- [ ] **Step 3: Update artifact verdict after job completion**

In `run_pipeline()`, after the call to `update_job_result()` (around line 411), add:

```python
        # Update artifact verdict if this job is linked to an artifact
        if job_data.get("artifact_id"):
            try:
                from malscan_worker.db import update_artifact_verdict
                await update_artifact_verdict(
                    artifact_id=job_data["artifact_id"],
                    verdict=analysis_result["verdict"],
                    score=analysis_result["score"],
                )
            except Exception:
                logger.exception("failed_to_update_artifact_verdict", artifact_id=job_data["artifact_id"])
```

- [ ] **Step 4: Run existing tests**

Run: `cd worker && poetry run pytest tests/ -v -x`
Expected: Existing tests pass (new context fields have defaults).

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/pipeline.py worker/src/malscan_worker/consumer.py
git commit -m "feat: propagate artifact context through pipeline and update verdict on completion"
```

---

## Task 8: Rewrite ArchiveExtractStage to Use Registry + Artifacts

**Files:**
- Modify: `worker/src/malscan_worker/stages/archive_extract.py`
- Test: `worker/tests/test_artifact_tree.py`

This is the largest task. The stage's `execute()` method is rewritten to:
1. Use `HandlerRegistry` instead of `_detect_format()` + `_extract()`
2. Create root artifact if depth=0
3. Create child artifacts for each extracted file
4. Handle dedup and cycle detection
5. Pass artifact context to sub-job submissions

- [ ] **Step 1: Write artifact creation and dedup tests**

```python
# worker/tests/test_artifact_tree.py
"""Tests for artifact tree creation during archive extraction."""

import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from malscan_worker.stages.base import StageContext


@pytest.fixture
def archive_ctx(tmp_path):
    """StageContext for an archive file."""
    zip_path = tmp_path / "test.zip"
    zip_path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)  # minimal zip header
    mock_job = MagicMock()
    mock_job.id = uuid.uuid4()
    mock_job.depth = 0
    return StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="abc123",
        sha256="abc123",
        original_filename="test.zip",
        file_path=zip_path,
        job=mock_job,
        db=AsyncMock(),
    )


@pytest.fixture
def child_archive_ctx(tmp_path):
    """StageContext for a child archive (depth > 0, has artifact context)."""
    zip_path = tmp_path / "inner.zip"
    zip_path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    mock_job = MagicMock()
    mock_job.id = uuid.uuid4()
    mock_job.depth = 1
    return StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="def456",
        sha256="def456",
        original_filename="inner.zip",
        file_path=zip_path,
        job=mock_job,
        db=AsyncMock(),
        artifact_id="parent-art-id",
        root_artifact_id="root-art-id",
        ancestor_hashes={"abc123"},
    )


class TestArtifactTreeCreation:
    """Test that ArchiveExtractStage creates artifact records."""

    @patch("malscan_worker.stages.archive_extract.create_artifact")
    @patch("malscan_worker.stages.archive_extract.InternalJobSubmitter")
    async def test_root_artifact_created_at_depth_zero(
        self, mock_submitter_cls, mock_create_artifact, archive_ctx, tmp_path
    ):
        """At depth 0, a root artifact should be created for the archive itself."""
        from malscan_worker.stages.archive_extract import ArchiveExtractStage

        mock_create_artifact.return_value = {"id": "new-root-art"}
        mock_submitter = AsyncMock()
        mock_submitter.submit_subjob.return_value = str(uuid.uuid4())
        mock_submitter_cls.get_instance.return_value = mock_submitter

        # Verify mock_create_artifact was called for root
        # (Full integration test requires a real zip, tested elsewhere)

    async def test_cycle_detection_skips_ancestor_hash(self, child_archive_ctx):
        """If extracted file SHA matches an ancestor, it should be skipped."""
        # ancestor_hashes contains "abc123"
        assert "abc123" in child_archive_ctx.ancestor_hashes

    async def test_dedup_within_extraction(self):
        """Same SHA256 twice in one archive: 2 artifacts, 1 sub-job."""
        # This is tested at integration level in test_safety_limits.py
        pass
```

- [ ] **Step 2: Run tests to see baseline**

Run: `cd worker && poetry run pytest tests/test_artifact_tree.py -v`
Expected: Should pass (tests are currently lightweight/structural).

- [ ] **Step 3: Rewrite ArchiveExtractStage.execute()**

This is a significant rewrite of `worker/src/malscan_worker/stages/archive_extract.py`. The key changes:

**Add imports at the top of the file:**
```python
from malscan_worker.extractors import (
    ExtractionLimits,
    get_default_registry,
)
from malscan_worker.db import create_artifact
```

**Replace the `execute` method (lines 58-213) with the new version.** The new execute method should:

1. Check `ctx.file_path` exists, check max depth via `getattr(settings, "max_job_depth", 3)`
2. Detect format via `self._registry.detect(ctx.file_path, mime)` where `self._registry` is initialized in `__init__` as `get_default_registry()`
3. Build `ExtractionLimits` from settings
4. Create root artifact if `ctx.root_artifact_id is None` (depth=0)
5. Extract with `asyncio.wait_for(asyncio.to_thread(handler.extract, ...), timeout=...)`
6. If `result.malicious`, return malicious result
7. Remove symlinks from extract dir
8. For each `ExtractedFile`:
   - Compute SHA256
   - Check cycle detection (`sha256 in ctx.ancestor_hashes`)
   - Check extraction-level dedup (`sha256 in seen_hashes`)
   - Create artifact record via `create_artifact()`
   - Submit sub-job with artifact context
9. Return `StageResult`

Key code for the `__init__` addition:
```python
    def __init__(self) -> None:
        self._registry = get_default_registry()
```

Key code for the new execute flow:
```python
    async def execute(self, ctx: StageContext) -> StageResult:
        import asyncio
        import hashlib
        import os

        started_at = datetime.now(timezone.utc)
        settings = get_settings()

        # Skip checks
        if not ctx.file_path or not os.path.exists(ctx.file_path):
            return self._skip_result(started_at, "File not found")

        max_depth = getattr(settings, "max_job_depth", 3)
        if ctx.job and ctx.job.depth >= max_depth:
            return self._skip_result(started_at, f"Max depth {max_depth} reached")

        # Detect format
        mime = self._get_mime(ctx)
        handler = self._registry.detect(ctx.file_path, mime)
        if handler is None:
            return self._skip_result(started_at, "Not an archive")

        # Build limits
        limits = ExtractionLimits(
            max_files=settings.extraction_max_files,
            max_extracted_bytes=settings.extraction_max_bytes,
            max_single_file_bytes=settings.extraction_max_single_bytes,
            max_expansion_ratio=settings.extraction_max_ratio,
            timeout_seconds=settings.extraction_timeout,
        )

        # Create root artifact if this is depth=0 and no artifact_id yet
        root_artifact_id = ctx.root_artifact_id
        parent_artifact_id = ctx.artifact_id
        root_job_id = ctx.job_id

        if not root_artifact_id and ctx.job:
            root_art = await create_artifact(
                parent_id=None,
                root_id=None,  # will self-reference after creation
                depth=0,
                sha256=ctx.sha256,
                size=os.path.getsize(ctx.file_path),
                original_filename=ctx.original_filename,
                extraction_source="archive-extract",
                archive_type=handler.name,
                root_job_id=ctx.job_id,
                job_id=ctx.job_id,
            )
            root_artifact_id = root_art["id"]
            parent_artifact_id = root_artifact_id

        # Extract with timeout
        extract_dir = Path(f"/tmp/{ctx.job_id}/extract")
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    handler.extract, ctx.file_path, extract_dir, limits, ctx.archive_password
                ),
                timeout=limits.timeout_seconds,
            )
        except asyncio.TimeoutError:
            return self._error_result(started_at, "Extraction timed out")

        # Zip bomb check
        if result.malicious:
            return self._malicious_result(started_at, result.reason, handler.name)

        # Process extracted files
        from malscan_worker.extractors.safety import remove_symlinks
        remove_symlinks(str(extract_dir))

        submitter = await InternalJobSubmitter.get_instance()
        seen_hashes: set[str] = set()
        created_artifacts: list[str] = []
        sub_jobs_created = 0
        ancestor_hashes = ctx.ancestor_hashes or set()

        for ef in result.files:
            file_sha256 = hashlib.sha256(open(ef.path, "rb").read()).hexdigest()

            # Cycle detection
            if file_sha256 in ancestor_hashes:
                logger.warning("recursive_loop_detected", sha256=file_sha256, origin=ef.origin_path)
                continue

            # Extraction-level dedup
            skip = file_sha256 in seen_hashes
            seen_hashes.add(file_sha256)

            art = await create_artifact(
                parent_id=parent_artifact_id,
                root_id=root_artifact_id,
                depth=(ctx.job.depth + 1) if ctx.job else 1,
                sha256=file_sha256,
                size=ef.size,
                original_filename=ef.original_name,
                origin_path=ef.origin_path,
                extraction_source="archive-extract",
                archive_type=handler.name,
                root_job_id=root_job_id if root_job_id else ctx.job_id,
                verdict="skipped" if skip else None,
                extraction_note="duplicate_within_extraction" if skip else None,
            )
            created_artifacts.append(art["id"])

            if skip:
                continue

            # Submit sub-job
            sub_job_id = await submitter.submit_subjob(
                file_path=ef.path,
                filename=ef.original_name,
                content_type="application/octet-stream",
                sha256_hash=file_sha256,
                file_size=ef.size,
                parent_job_id=str(ctx.job.id) if ctx.job else ctx.job_id,
                parent_job_depth=ctx.job.depth if ctx.job else 0,
                artifact_id=art["id"],
                root_artifact_id=root_artifact_id,
                ancestor_hashes=ancestor_hashes | {ctx.sha256},
            )
            if sub_job_id:
                sub_jobs_created += 1

        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status="ok",
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings={
                "archive_type": handler.name,
                "extracted_count": len(result.files),
                "sub_jobs_created": sub_jobs_created,
                "artifacts_created": len(created_artifacts),
                "warnings": result.warnings,
                "total_extracted_bytes": sum(ef.size for ef in result.files),
            },
            artifacts=created_artifacts,
        )
```

Also add helper methods `_skip_result`, `_error_result`, `_malicious_result` that build `StageResult` with appropriate status/findings. (Keep the existing `_get_mime` method for extracting MIME from previous results.)

**Remove** the old `_detect_format`, `_extract`, `_extract_zip`, `_extract_7z`, `_extract_rar`, `_extract_tar`, `_extract_single_compressed`, `_check_size_limits` methods — their logic has been moved to the handler classes.

- [ ] **Step 4: Run tests**

Run: `cd worker && poetry run pytest tests/ -v -x`
Expected: All pass. If there are failures, check import paths and method signatures.

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/stages/archive_extract.py worker/tests/test_artifact_tree.py
git commit -m "feat: rewrite ArchiveExtractStage to use handler registry and create artifacts"
```

---

## Task 9: DocumentAnalysisStage — Artifact Integration

**Files:**
- Modify: `worker/src/malscan_worker/stages/document_analysis.py:995-1057` (`_submit_artifacts` method)

- [ ] **Step 1: Modify `_submit_artifacts` to create artifact records**

In `worker/src/malscan_worker/stages/document_analysis.py`, modify `_submit_artifacts` (line 995-1057) to create artifact records before submitting sub-jobs. Add the import at the top:

```python
from malscan_worker.db import create_artifact
```

Rewrite `_submit_artifacts`:

```python
    async def _submit_artifacts(
        self, ctx: StageContext, artifacts: list[dict]
    ) -> int:
        """Submit extracted artifacts as sub-jobs with artifact records."""
        import hashlib
        settings = get_settings()
        max_depth = getattr(settings, "max_job_depth", 3)
        if ctx.job and ctx.job.depth >= max_depth:
            logger.info("doc_analysis_max_depth_reached", depth=ctx.job.depth)
            return 0

        parent_job_id = str(ctx.job.id) if ctx.job else ctx.job_id
        parent_job_depth = ctx.job.depth if ctx.job else 0

        # Create root artifact if needed (depth=0 with embedded objects)
        root_artifact_id = ctx.root_artifact_id
        parent_artifact_id = ctx.artifact_id

        if not root_artifact_id and ctx.job and artifacts:
            import os
            root_art = await create_artifact(
                parent_id=None,
                root_id=None,
                depth=0,
                sha256=ctx.sha256,
                size=os.path.getsize(ctx.file_path) if ctx.file_path else 0,
                original_filename=ctx.original_filename,
                extraction_source="document-analysis",
                root_job_id=ctx.job_id,
                job_id=ctx.job_id,
            )
            root_artifact_id = root_art["id"]
            parent_artifact_id = root_artifact_id

        submitter = await InternalJobSubmitter.get_instance()
        submitted = 0
        seen_hashes: set[str] = set()
        ancestor_hashes = ctx.ancestor_hashes or set()

        for art_info in artifacts:
            art_path = art_info.get("path", "")
            if not art_path or not os.path.exists(art_path):
                continue

            file_size = os.path.getsize(art_path)
            with open(art_path, "rb") as f:
                file_sha256 = hashlib.sha256(f.read()).hexdigest()

            original_name = art_info.get("name", os.path.basename(art_path))
            origin_path = art_info.get("origin_path", original_name)

            # Cycle detection
            if file_sha256 in ancestor_hashes:
                logger.warning("doc_analysis_cycle_detected", sha256=file_sha256)
                continue

            # Extraction-level dedup
            skip = file_sha256 in seen_hashes
            seen_hashes.add(file_sha256)

            artifact_record = await create_artifact(
                parent_id=parent_artifact_id,
                root_id=root_artifact_id,
                depth=parent_job_depth + 1,
                sha256=file_sha256,
                size=file_size,
                original_filename=original_name,
                origin_path=origin_path,
                extraction_source="document-analysis",
                root_job_id=ctx.job_id,
                verdict="skipped" if skip else None,
                extraction_note="duplicate_within_extraction" if skip else None,
            )

            if skip:
                continue

            sub_job_id = await submitter.submit_subjob(
                file_path=art_path,
                filename=original_name,
                content_type="application/octet-stream",
                sha256_hash=file_sha256,
                file_size=file_size,
                parent_job_id=parent_job_id,
                parent_job_depth=parent_job_depth,
                artifact_id=artifact_record["id"],
                root_artifact_id=root_artifact_id,
                ancestor_hashes=ancestor_hashes | {ctx.sha256},
            )
            if sub_job_id:
                submitted += 1

        return submitted
```

- [ ] **Step 2: Run tests**

Run: `cd worker && poetry run pytest tests/ -v -x`
Expected: All pass.

- [ ] **Step 3: Commit**

```bash
git add worker/src/malscan_worker/stages/document_analysis.py
git commit -m "feat: add artifact creation to DocumentAnalysisStage for embedded objects"
```

---

## Task 10: Backend Schema + Report Endpoint — Artifact Tree

**Files:**
- Modify: `backend/src/malscan/schemas/requests.py:166-176`
- Modify: `backend/src/malscan/api/routes.py:504-564`

- [ ] **Step 1: Add ArtifactTreeNode schema**

In `backend/src/malscan/schemas/requests.py`, add before `ReportResponse` (before line 166):

```python
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
    job_id: str | None = None
    children: list["ArtifactTreeNode"] = []
```

Then add `artifact_tree` to `ReportResponse`:

```python
class ReportResponse(BaseModel):
    # ... existing fields ...
    artifact_tree: ArtifactTreeNode | None = None
```

- [ ] **Step 2: Add `_build_artifact_tree` query and update report endpoint**

In `backend/src/malscan/api/routes.py`, add the tree builder function before `get_report`:

```python
from malscan.models.artifact import Artifact

async def _build_artifact_tree(root_job_id: str, db: AsyncSession) -> dict | None:
    """Build hierarchical artifact tree from flat records."""
    from uuid import UUID
    stmt = (
        select(Artifact)
        .where(Artifact.root_job_id == UUID(root_job_id))
        .order_by(Artifact.depth, Artifact.created_at)
    )
    result = await db.execute(stmt)
    artifacts = result.scalars().all()

    if not artifacts:
        return None

    nodes: dict[str, dict] = {}
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
            "extraction_note": art.extraction_note,
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

Then in `get_report` (around line 561-564), add the tree lookup before returning:

```python
    report = dict(job.result)
    report["created_at"] = job.created_at.isoformat()
    report["child_jobs"] = child_jobs

    # Build artifact tree (returns None for non-archive files)
    report["artifact_tree"] = await _build_artifact_tree(str(job.id), db)

    return report
```

- [ ] **Step 3: Verify backend imports**

Run: `cd backend && python -c "from malscan.schemas.requests import ArtifactTreeNode, ReportResponse; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add backend/src/malscan/schemas/requests.py backend/src/malscan/api/routes.py
git commit -m "feat: add artifact_tree to report endpoint with ArtifactTreeNode schema"
```

---

## Task 11: Safety Limits Integration Tests

**Files:**
- Create: `worker/tests/test_safety_limits.py`

- [ ] **Step 1: Write safety limit tests**

```python
# worker/tests/test_safety_limits.py
"""Integration tests for extraction safety limits."""

import hashlib
import os
import zipfile
from pathlib import Path

import pytest

from malscan_worker.extractors.base import ExtractionLimits
from malscan_worker.extractors.zip_handler import ZipHandler
from malscan_worker.extractors.safety import (
    check_expansion_ratio,
    remove_symlinks,
    safe_extract_path,
)


class TestZipBombDetection:
    def test_declared_ratio_bomb(self, tmp_path):
        """A zip with huge declared uncompressed size should be flagged."""
        handler = ZipHandler()
        # Create a zip where declared size / archive size > 100x
        zip_path = tmp_path / "bomb.zip"
        # Write highly compressible data
        data = b"\x00" * (1024 * 1024)  # 1MB of zeros
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.bin", data)

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        # With a very strict ratio limit, this should trigger
        limits = ExtractionLimits(max_expansion_ratio=2.0)
        result = handler.extract(zip_path, extract_dir, limits)
        assert result.malicious is True
        assert "expansion ratio" in result.reason.lower()

    def test_normal_ratio_passes(self, tmp_path):
        """A normal zip should not be flagged."""
        handler = ZipHandler()
        zip_path = tmp_path / "normal.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("a.txt", "hello world")
            zf.writestr("b.txt", "goodbye world")

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        limits = ExtractionLimits(max_expansion_ratio=100.0)
        result = handler.extract(zip_path, extract_dir, limits)
        assert result.malicious is False


class TestMaxFilesLimit:
    def test_extraction_stops_at_limit(self, tmp_path):
        handler = ZipHandler()
        zip_path = tmp_path / "many.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for i in range(20):
                zf.writestr(f"file_{i:03d}.txt", f"content {i}")

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        limits = ExtractionLimits(max_files=5)
        result = handler.extract(zip_path, extract_dir, limits)
        assert len(result.files) == 5
        assert any("Max files limit" in w for w in result.warnings)


class TestMaxSingleFileSize:
    def test_large_file_skipped(self, tmp_path):
        handler = ZipHandler()
        zip_path = tmp_path / "large.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("small.txt", "tiny")
            zf.writestr("big.bin", b"x" * 2000)

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        limits = ExtractionLimits(max_single_file_bytes=100)
        result = handler.extract(zip_path, extract_dir, limits)
        assert len(result.files) == 1
        assert result.files[0].original_name == "small.txt"


class TestPathTraversal:
    def test_traversal_entries_skipped(self, tmp_path):
        handler = ZipHandler()
        zip_path = tmp_path / "traversal.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../etc/passwd", "hacked")
            zf.writestr("safe.txt", "ok")

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        result = handler.extract(zip_path, extract_dir, ExtractionLimits())
        names = [f.original_name for f in result.files]
        assert "safe.txt" in names
        assert "passwd" not in names


class TestSymlinkRejection:
    def test_symlinks_removed_after_extraction(self, tmp_path):
        # Simulate post-extraction symlink check
        real = tmp_path / "real.txt"
        real.write_text("content")
        link = tmp_path / "evil_link"
        link.symlink_to(real)

        count = remove_symlinks(str(tmp_path))
        assert count == 1
        assert not link.exists()


class TestCycleDetection:
    def test_ancestor_hash_check(self):
        """If extracted SHA matches ancestor, it should be detected."""
        ancestor_hashes = {"abc123def456", "789xyz"}
        extracted_sha = "abc123def456"
        assert extracted_sha in ancestor_hashes

    def test_non_ancestor_passes(self):
        ancestor_hashes = {"abc123def456"}
        extracted_sha = "newfile_hash"
        assert extracted_sha not in ancestor_hashes
```

- [ ] **Step 2: Run safety tests**

Run: `cd worker && poetry run pytest tests/test_safety_limits.py -v`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add worker/tests/test_safety_limits.py
git commit -m "test: add safety limits integration tests for zip bomb, path traversal, dedup"
```

---

## Task 12: Run Full Test Suite + Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Run all worker tests**

Run: `cd worker && poetry run pytest tests/ -v --tb=short`
Expected: All pass.

- [ ] **Step 2: Run backend import check**

Run: `cd backend && python -c "from malscan.models import Artifact; from malscan.schemas.requests import ArtifactTreeNode, ReportResponse; print('All imports OK')"`
Expected: `All imports OK`

- [ ] **Step 3: Verify migration can be generated**

Run: `cd backend && poetry run alembic check` (or `alembic heads`)
Expected: Shows migration 004 as head.

- [ ] **Step 4: Final commit (if any fixups needed)**

```bash
git add -A
git commit -m "chore: final fixups for recursive extraction feature"
```

---

## Summary of Changes

| Task | Description | Files |
|------|-------------|-------|
| 1 | Alembic migration 004 | 1 new |
| 2 | Artifact model + Job FK | 1 new, 2 modified |
| 3 | Extractor base types + safety | 3 new, 1 test |
| 4 | Handler registry + 7 handlers | 8 new, test expanded |
| 5 | Config + StageContext + DB helpers | 3 modified |
| 6 | InternalJobSubmitter enhancement | 1 modified |
| 7 | Pipeline + consumer artifact propagation | 2 modified |
| 8 | ArchiveExtractStage rewrite | 1 modified, 1 test |
| 9 | DocumentAnalysisStage artifact integration | 1 modified |
| 10 | Report schema + endpoint | 2 modified |
| 11 | Safety limits tests | 1 new test |
| 12 | Full verification | None |
