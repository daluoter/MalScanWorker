# Format-Specific Analyzer Layer Design

**Date:** 2026-04-08
**Status:** Draft
**Approach:** Analyzer Registry (Approach A)

## 1. Problem Statement

The MalScanWorker pipeline currently has deep file analysis only for Office documents (RTF, OLE, OOXML) via `DocumentAnalysisStage`. This stage is 1112 lines, handles three formats in one file, and cannot be extended to non-document formats without growing further. The system has no analysis capability for PE executables, PDF files, or script files (JS/VBS/PowerShell).

Specific problems:

1. **Monolithic stage** -- `DocumentAnalysisStage` (1112 lines) mixes RTF parsing, OLE inspection, OOXML analysis, VBA macro extraction, and artifact submission in a single file. Adding new formats would make this worse.
2. **No PE analysis** -- Windows executables pass through ClamAV and YARA but get no structural analysis (header inspection, import analysis, packing detection).
3. **No PDF analysis** -- PDF files get no inspection for embedded JavaScript, launch actions, or malicious streams.
4. **No script analysis** -- JavaScript, VBScript, and PowerShell files get no deobfuscation or suspicious pattern detection beyond YARA rules.
5. **No extensibility pattern** -- adding a new format requires modifying the stage directly. There is no plugin interface for format-specific analysis.

## 2. Goals

1. Create a `FormatAnalyzer` ABC with an `AnalyzerRegistry`, mirroring the existing `FormatHandler`/`HandlerRegistry` pattern in `extractors/`.
2. Refactor `DocumentAnalysisStage` into three focused analyzers (`RtfAnalyzer`, `OleAnalyzer`, `OoxmlAnalyzer`) with no behavior changes.
3. Add three new analyzers: `PeAnalyzer`, `PdfAnalyzer`, `ScriptAnalyzer`.
4. Replace `DocumentAnalysisStage` with a single `FormatAnalysisStage` that dispatches to the matching analyzer.
5. All analyzers return a unified `AnalysisResult` dataclass -- the stage and scoring logic are format-agnostic.
6. Per-analyzer enable/disable configuration flags for safe rollout.

## 3. Architecture Overview

```
Upload -> File table -> Job -> Pipeline
                                  |-- PARALLEL: FileType, ClamAV, Yara, IOC
                                  |-- SEQUENTIAL:
                                      |-- ArchiveExtractStage
                                      |-- FormatAnalysisStage (NEW, replaces DocumentAnalysisStage)
                                      |     |-- AnalyzerRegistry.detect(file_path, mime)
                                      |     |-- matched analyzer.analyze(file_path, extract_dir, ctx)
                                      |     |-- submit extracted artifacts as sub-jobs
                                      |     |-- return unified findings dict
                                      |-- SandboxStage
```

### Analyzer dispatch flow

```
FormatAnalysisStage.execute(ctx)
  |-- skip if file missing or too large
  |-- mime = get_mime(ctx)
  |-- analyzer = registry.detect(file_path, mime)
  |-- if None: return skipped
  |-- analyzer_ctx = AnalyzerContext(job_id, sha256, filename, size)
  |-- extract_dir = /tmp/{job_id}/analysis_artifacts/
  |-- result = await asyncio.to_thread(analyzer.analyze, file_path, extract_dir, analyzer_ctx)
  |-- findings = result_to_findings(result)
  |-- sub_jobs = submit_artifacts(ctx, result.extracted_artifacts)
  |-- return StageResult("format-analysis", "ok", findings)
```

## 4. Core Abstractions

### 4.1 FormatAnalyzer ABC

New file: `worker/src/malscan_worker/analyzers/base.py`

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AnalyzerContext:
    """Read-only context passed to analyzers. No DB session, no job model."""
    job_id: str
    sha256: str
    original_filename: str
    file_size: int


@dataclass
class MacroResult:
    """VBA/macro analysis result. Used by document format analyzers."""
    found: bool = False
    auto_exec: bool = False
    suspicious: bool = False
    sources: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Unified result from any format analyzer."""
    format_type: str                                    # "pe", "pdf", "rtf", "ole", "ooxml", "script"
    findings: list[dict[str, Any]] = field(default_factory=list)           # structural/parser findings
    exploit_indicators: list[dict[str, Any]] = field(default_factory=list) # CVEs, suspicious constructs
    embedded_objects: list[dict[str, Any]] = field(default_factory=list)   # objects found inside the file
    extracted_artifacts: list[dict[str, Any]] = field(default_factory=list)# artifacts on disk for sub-jobs
    suspicious_keywords: list[str] = field(default_factory=list)           # flagged VBA keywords, script patterns, etc. PE uses metadata.suspicious_imports instead.
    macros: MacroResult | None = None                                      # None for non-macro formats
    errors: list[str] = field(default_factory=list)                        # non-fatal parse errors
    metadata: dict[str, Any] = field(default_factory=dict)                 # format-specific metadata


class FormatAnalyzer(ABC):
    """Abstract base class for format-specific file analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier: 'pe', 'pdf', 'rtf', 'ole', 'ooxml', 'script'."""
        ...

    @abstractmethod
    def can_analyze(self, file_path: Path, mime: str, magic: bytes) -> bool:
        """Return True if this analyzer handles the given file.

        Args:
            file_path: Path to the file on disk.
            mime: MIME type from FileTypeStage.
            magic: First 4096 bytes of the file.
        """
        ...

    @abstractmethod
    def analyze(
        self,
        file_path: Path,
        extract_dir: Path,
        ctx: AnalyzerContext,
    ) -> AnalysisResult:
        """Perform format-specific analysis. Synchronous -- run via asyncio.to_thread by the stage.

        Analyzers MUST NOT access the database or submit jobs. They only:
        - Read the input file
        - Write extracted artifacts to extract_dir
        - Return an AnalysisResult

        The stage handles artifact submission, DB writes, and artifact tree integration.

        Args:
            file_path: Path to the file to analyze.
            extract_dir: Directory to write extracted artifacts into.
            ctx: Read-only context with job metadata.
        """
        ...
```

Design decisions:

- `AnalyzerContext` is intentionally slim. Analyzers are pure analysis functions with no side effects beyond writing extracted files to disk.
- `analyze()` is synchronous. The stage runs it in a thread via `asyncio.to_thread()`, matching the `FormatHandler.extract()` pattern.
- `magic` is 4096 bytes (vs 16 bytes for extractors) because format detection for analysis requires deeper inspection (e.g., PDF version, script shebangs).
- `macros` is `None` for non-document formats. The scoring logic checks `macros is not None` before applying macro-related scoring.
- `metadata` is a catch-all dict for format-specific data. The frontend renders format-specific detail panels based on `format_type`.

### 4.2 AnalyzerRegistry

New file: `worker/src/malscan_worker/analyzers/registry.py`

```python
from pathlib import Path

from malscan_worker.analyzers.base import FormatAnalyzer


class AnalyzerRegistry:
    """Ordered registry of format analyzers. First match wins."""

    def __init__(self) -> None:
        self._analyzers: list[FormatAnalyzer] = []

    def register(self, analyzer: FormatAnalyzer) -> None:
        self._analyzers.append(analyzer)

    def detect(self, file_path: Path, mime: str) -> FormatAnalyzer | None:
        """Return the first analyzer that can handle this file, or None."""
        magic = b""
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4096)
        except OSError:
            pass
        for analyzer in self._analyzers:
            if analyzer.can_analyze(file_path, mime, magic):
                return analyzer
        return None


def get_default_analyzer_registry() -> AnalyzerRegistry:
    """Build the default analyzer registry with all built-in analyzers.

    Registration order matters -- first match wins.
    RTF before OLE (RTF can contain OLE magic bytes).
    PE before Script (a .vbs file should not match PE).
    """
    from malscan_worker.analyzers.ole_analyzer import OleAnalyzer
    from malscan_worker.analyzers.ooxml_analyzer import OoxmlAnalyzer
    from malscan_worker.analyzers.pdf_analyzer import PdfAnalyzer
    from malscan_worker.analyzers.pe_analyzer import PeAnalyzer
    from malscan_worker.analyzers.rtf_analyzer import RtfAnalyzer
    from malscan_worker.analyzers.script_analyzer import ScriptAnalyzer

    from malscan_worker.config import get_settings
    settings = get_settings()

    registry = AnalyzerRegistry()

    # Document formats (refactored from DocumentAnalysisStage)
    registry.register(RtfAnalyzer())
    registry.register(OleAnalyzer())
    registry.register(OoxmlAnalyzer())

    # New formats (gated by config flags)
    if settings.pe_analysis_enabled:
        registry.register(PeAnalyzer())
    if settings.pdf_analysis_enabled:
        registry.register(PdfAnalyzer())
    if settings.script_analysis_enabled:
        registry.register(ScriptAnalyzer())

    return registry
```

## 5. Refactored Document Analyzers

These are mechanical extractions from `DocumentAnalysisStage` with no behavior changes.

### 5.1 Shared Modules

#### `analyzers/_constants.py`

Moved from `document_analysis.py`: `SUSPICIOUS_VBA_KEYWORDS`, `RTF_SUSPICIOUS_CONTROLS`, `EQUATION_EDITOR_CLSIDS`, `DANGEROUS_OLE_CLASSES`, `ARTIFACT_CONTENT_TYPES`, `MAX_EMBEDDED_OBJECTS`, `MAX_EXTRACTED_ARTIFACT_SIZE`, `MAX_MACRO_SOURCE_LEN`.

#### `analyzers/_helpers.py`

Moved from `document_analysis.py`: `_sha256_bytes()`, `_safe_filename()`, `_looks_like_pe()`, `_looks_like_shellcode()`, `_guess_artifact_ext()`.

Also moved: `_OLE_MAGIC`, `_OOXML_MAGIC`, `_RTF_RE` magic byte constants.

#### `analyzers/_vba_helpers.py`

Extracted from `DocumentAnalysisStage._analyse_vba()`:

```python
def analyze_vba_macros(file_path: Path) -> MacroResult:
    """Analyze VBA macros using olevba. Used by OleAnalyzer and OoxmlAnalyzer.

    Returns a MacroResult with macro presence, auto-exec detection,
    suspicious keyword detection, and source code previews.
    """
    if not HAS_OLEVBA:
        return MacroResult()  # graceful degradation

    try:
        vba = VBA_Parser(str(file_path))
    except Exception:
        return MacroResult()

    result = MacroResult()
    try:
        if not vba.detect_vba_macros():
            return result

        result.found = True
        keyword_hits: set[str] = set()

        for vba_filename, stream_path, vba_code_str in vba.extract_macros():
            source_entry = {
                "stream": stream_path or "",
                "module": vba_filename or "",
                "code_length": len(vba_code_str),
            }

            code_lower = vba_code_str.lower() if vba_code_str else ""
            for kw in SUSPICIOUS_VBA_KEYWORDS:
                if kw.lower() in code_lower:
                    keyword_hits.add(kw)

            auto_exec_patterns = [
                "autoopen", "auto_open", "autoclose", "auto_close",
                "autoexec", "document_open", "document_close", "workbook_open",
            ]
            if any(p in code_lower for p in auto_exec_patterns):
                result.auto_exec = True
                source_entry["auto_exec"] = True

            if vba_code_str:
                source_entry["code_preview"] = vba_code_str[:MAX_MACRO_SOURCE_LEN]

            result.sources.append(source_entry)

        if keyword_hits:
            result.suspicious = True

        return result
    finally:
        try:
            vba.close()
        except Exception:
            pass
```

### 5.2 RtfAnalyzer

New file: `worker/src/malscan_worker/analyzers/rtf_analyzer.py` (~200 lines)

Extracted from: `DocumentAnalysisStage._analyse_rtf()`, `_rtfobj_extract()`, `_rtf_fallback_extract()`.

```python
class RtfAnalyzer(FormatAnalyzer):
    @property
    def name(self) -> str:
        return "rtf"

    def can_analyze(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if _RTF_RE.match(magic):
            return True
        ml = mime.lower()
        return "rtf" in ml or "richtext" in ml

    def analyze(self, file_path: Path, extract_dir: Path, ctx: AnalyzerContext) -> AnalysisResult:
        raw = file_path.read_bytes()
        result = AnalysisResult(format_type="rtf")

        # 1. Structural scan for suspicious control words
        for ctrl in RTF_SUSPICIOUS_CONTROLS:
            if ctrl in raw:
                result.findings.append(
                    {"type": "rtf_control", "value": ctrl.decode("ascii", errors="replace")}
                )

        # 2. rtfobj extraction (oletools) or fallback hex extraction
        if HAS_RTFOBJ:
            self._rtfobj_extract(raw, result, extract_dir)
        else:
            self._rtf_fallback_extract(raw, result, extract_dir)

        # 3. Equation Editor detection
        if b"Equation" in raw or b"equation" in raw:
            result.exploit_indicators.append({
                "type": "equation_editor_reference",
                "detail": "RTF contains Equation Editor class reference",
                "cves": ["CVE-2017-11882", "CVE-2018-0802"],
            })

        # 4. External template / URL moniker
        if b"\\*\\template " in raw or b"TEMPLATE" in raw.upper():
            result.exploit_indicators.append({
                "type": "external_template",
                "detail": "RTF references an external template -- possible template injection",
            })

        return result

    def _rtfobj_extract(self, raw, result, extract_dir):
        # Same logic as DocumentAnalysisStage._rtfobj_extract()
        # Populates result.embedded_objects, result.exploit_indicators, result.extracted_artifacts
        ...

    def _rtf_fallback_extract(self, raw, result, extract_dir):
        # Same logic as DocumentAnalysisStage._rtf_fallback_extract()
        ...
```

### 5.3 OleAnalyzer

New file: `worker/src/malscan_worker/analyzers/ole_analyzer.py` (~300 lines)

Extracted from: `_analyse_ole()`, `_oleid_scan()`, `_oleobj_extract()`, `_ole_stream_scan()`. Also calls `analyze_vba_macros()` from `_vba_helpers.py`.

```python
class OleAnalyzer(FormatAnalyzer):
    @property
    def name(self) -> str:
        return "ole"

    def can_analyze(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:8] == _OLE_MAGIC:
            return True
        ml = mime.lower()
        return "msword" in ml or "ms-word" in ml or "ole" in ml

    def analyze(self, file_path: Path, extract_dir: Path, ctx: AnalyzerContext) -> AnalysisResult:
        raw = file_path.read_bytes()
        result = AnalysisResult(format_type="ole")

        # 1. oleid indicators
        if HAS_OLEID:
            self._oleid_scan(file_path, result)

        # 2. Embedded OLE objects via oleobj
        if HAS_OLEOBJ:
            self._oleobj_extract(file_path, result, extract_dir)

        # 3. Stream scan for Equation Editor / suspicious CLSIDs
        self._ole_stream_scan(raw, result)

        # 4. External link / template reference
        if b"http://" in raw or b"https://" in raw or b"\\\\\\\\1" in raw:
            result.findings.append(
                {"type": "external_reference", "detail": "OLE document contains URL/UNC reference"}
            )

        # 5. VBA macro analysis
        result.macros = analyze_vba_macros(file_path)
        if result.macros.suspicious:
            result.suspicious_keywords = [...]  # from VBA keyword hits

        return result
```

### 5.4 OoxmlAnalyzer

New file: `worker/src/malscan_worker/analyzers/ooxml_analyzer.py` (~250 lines)

Extracted from: `_analyse_ooxml()`, `_scan_rels_xml()`. Also calls `analyze_vba_macros()`.

```python
class OoxmlAnalyzer(FormatAnalyzer):
    @property
    def name(self) -> str:
        return "ooxml"

    def can_analyze(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:4] == _OOXML_MAGIC:
            return True
        ml = mime.lower()
        return "officedocument" in ml or "vnd.openxmlformats" in ml or "vnd.ms-excel" in ml or "vnd.ms-powerpoint" in ml

    def analyze(self, file_path: Path, extract_dir: Path, ctx: AnalyzerContext) -> AnalysisResult:
        result = AnalysisResult(format_type="ooxml")

        # 1. ZIP validation
        # 2. vbaProject.bin detection
        # 3. .rels parsing for external targets
        # 4. Embedded OLE object extraction
        # 5. VBA macro analysis
        result.macros = analyze_vba_macros(file_path)

        return result
```

## 6. New Format Analyzers

### 6.1 PeAnalyzer

New file: `worker/src/malscan_worker/analyzers/pe_analyzer.py` (~350 lines)

**New dependency:** `pefile` (add to `pyproject.toml`)

**Detection:**

```python
class PeAnalyzer(FormatAnalyzer):
    @property
    def name(self) -> str:
        return "pe"

    def can_analyze(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:2] == b"MZ" and len(magic) > 64:
            return True
        ml = mime.lower()
        return "x-dosexec" in ml or "x-msdownload" in ml or "x-ms-dos-executable" in ml
```

**Analysis capabilities:**

1. **Header analysis** -- `IMAGE_FILE_HEADER`: machine type, timestamp, characteristics (DLL flag, 32/64-bit). Anomaly detection: timestamp in the future, timestamp = 0 (provenance stripping), mismatched address-of-entry-point.

2. **Section analysis** -- for each section:
   - Name, virtual size, raw size, entropy, characteristics
   - High entropy (>7.0) = likely packed/encrypted
   - Writable + executable = self-modifying code
   - Section name anomalies: empty names, `.UPX`, `.aspack`, `.themida`, non-ASCII
   - Virtual size >> raw size = runtime unpacking

3. **Import analysis** -- enumerate imported DLLs and functions. Flag suspicious imports:
   - Process injection: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtCreateThreadEx`
   - DLL injection: `LoadLibraryA` + `GetProcAddress` combined, `SetWindowsHookEx`
   - Anti-debug: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`
   - Persistence: `RegSetValueEx`, `RegCreateKeyEx`
   - Network: `InternetOpenA`, `HttpSendRequestA`, `URLDownloadToFile`, `WSAStartup`
   - Crypto: `CryptEncrypt`, `CryptDecrypt` (ransomware indicator)

4. **Packing detection** -- heuristics:
   - Few imports (< 10) + high entropy sections = likely packed
   - Known packer section names (UPX, ASPack, Themida, VMProtect, PECompact)
   - Entry point in non-`.text` section
   - Only `LoadLibraryA` + `GetProcAddress` imports = manual import resolution

5. **Resource analysis** -- enumerate resources by type:
   - Executable resources (PE inside PE)
   - Very large resources (> 1MB) = potential embedded payload
   - Extracted to `extract_dir` and added to `extracted_artifacts`

6. **Metadata output:**

```python
{
    "machine": "AMD64",          # IMAGE_FILE_MACHINE_AMD64
    "compile_timestamp": "2026-01-15T10:30:00Z",
    "compile_timestamp_suspicious": False,
    "entry_point": "0x1000",
    "entry_point_section": ".text",
    "subsystem": "WINDOWS_GUI",
    "is_dll": False,
    "is_64bit": True,
    "sections": [
        {
            "name": ".text",
            "entropy": 6.2,
            "virtual_size": 65536,
            "raw_size": 64000,
            "characteristics": ["EXECUTE", "READ"],
        }
    ],
    "imported_dlls": ["KERNEL32.dll", "USER32.dll"],
    "import_count": 47,
    "suspicious_imports": ["VirtualAllocEx", "CreateRemoteThread"],
    "is_packed": False,
    "packer_indicators": [],
    "resource_count": 3,
    "has_digital_signature": True,
}
```

### 6.2 PdfAnalyzer

New file: `worker/src/malscan_worker/analyzers/pdf_analyzer.py` (~300 lines)

**New dependency:** `pypdf` (add to `pyproject.toml`)

**Detection:**

```python
class PdfAnalyzer(FormatAnalyzer):
    @property
    def name(self) -> str:
        return "pdf"

    def can_analyze(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:5] == b"%PDF-":
            return True
        return "pdf" in mime.lower()
```

**Analysis capabilities:**

1. **Structure analysis** -- parse with `pypdf`:
   - Page count, PDF version, encryption status
   - Info dict (author, creator, producer, dates)
   - Detect linearized PDFs, cross-reference anomalies

2. **JavaScript detection** -- scan raw bytes for `/JS`, `/JavaScript`, `/OpenAction`, `/AA` keys. Extract JavaScript content for inspection:
   - Flag: `eval()`, `unescape()`, `String.fromCharCode()`, `this.exportDataObject`, `app.launchURL`, `util.printf`
   - Detect heap spray: long NOP-sled-like strings, repeated `%u` sequences
   - Name obfuscation detection: `/J#61vaScript` (hex-encoded names for `/JavaScript`)

3. **Action/launch detection** -- `/Launch`, `/GoToR`, `/URI`, `/SubmitForm`:
   - `/Launch` with executable = direct payload execution
   - `/GoToR` with external URI = external resource loading
   - `/URI` actions = potential phishing redirects

4. **Embedded file detection** -- `/EmbeddedFiles`, `/FileAttachment`:
   - Extract embedded files to disk (added to `extracted_artifacts`)
   - Flag executable attachments (.exe, .dll, .scr, .bat, .ps1)

5. **Stream analysis** -- suspicious filter chains:
   - Multiple decode filters stacked for obfuscation
   - `/JBIG2Decode` (CVE-2021-30860)
   - `/DCTDecode` with malformed JPEG data

6. **Exploit indicators:**
   - `/U3D` (CVE-2009-3953), `/XFA` forms, `/AcroForm` with JavaScript
   - Malformed cross-reference tables
   - Object stream obfuscation

7. **Metadata output:**

```python
{
    "pdf_version": "1.7",
    "page_count": 3,
    "is_encrypted": False,
    "has_javascript": True,
    "javascript_count": 2,
    "js_sources": ["OpenAction JS, 245 bytes", "Page 1 AA, 120 bytes"],
    "has_embedded_files": True,
    "embedded_file_count": 1,
    "has_launch_action": False,
    "has_goto_remote": False,
    "suspicious_filters": [],
    "info": {"author": "...", "creator": "...", "producer": "..."},
}
```

### 6.3 ScriptAnalyzer

New file: `worker/src/malscan_worker/analyzers/script_analyzer.py` (~250 lines)

**No new dependencies** -- regex/pattern-based analysis + stdlib `base64`.

**Detection:**

```python
class ScriptAnalyzer(FormatAnalyzer):
    @property
    def name(self) -> str:
        return "script"

    def can_analyze(self, file_path: Path, mime: str, magic: bytes) -> bool:
        # MIME check
        ml = mime.lower()
        if any(t in ml for t in ("javascript", "vbscript", "x-powershell", "x-bat", "x-sh")):
            return True
        # Extension check
        ext = file_path.suffix.lower()
        if ext in (".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1", ".bat", ".cmd", ".wsf", ".hta"):
            return True
        # Shebang check
        if magic[:2] == b"#!" and any(s in magic[:80] for s in (b"python", b"node", b"bash", b"perl", b"ruby")):
            return True
        return False
```

**Analysis capabilities:**

1. **Script type detection** -- determine language from content + extension + shebang:
   - JavaScript: `.js`, `.jse`, `.wsf`, patterns (`function`, `var `, `const `, `let `)
   - VBScript: `.vbs`, `.vbe`, patterns (`Dim `, `Sub `, `Function `, `WScript`)
   - PowerShell: `.ps1`, `.psm1`, patterns (`$PSVersionTable`, `Invoke-`, `Get-`, `Set-`)
   - Batch: `.bat`, `.cmd`, patterns (`@echo off`, `goto `, `set `)
   - HTA: `.hta`, `<HTA:APPLICATION`

2. **Obfuscation detection:**
   - String concatenation abuse: `"h" & "t" & "t" & "p"` (VBS), `"h"+"t"+"t"+"p"` (JS)
   - Char code building: `String.fromCharCode(104,116,116,112)` (JS), `Chr(104) & Chr(116)` (VBS)
   - Base64 payloads: detect base64-encoded strings > 50 chars, flag if decoded content looks like PE/script
   - PowerShell encoding: `-EncodedCommand`, `-enc`, `[Convert]::FromBase64String`
   - Escaped variable names: `${e}${x}${e}${c}` (PS), `%comspec%` indirection (batch)
   - Very long lines (> 1000 chars) with high character diversity

3. **Suspicious pattern matching** (per script type):
   - Download/execute: `DownloadFile`, `DownloadString`, `Invoke-WebRequest`, `XMLHttpRequest`, `Net.WebClient`, `BitsTransfer`
   - Execution: `WScript.Shell`, `Shell.Application`, `Start-Process`, `Invoke-Expression`, `IEX`, `cmd /c`, `eval(`
   - Persistence: `RegWrite`, `schtasks`, `HKCU\...\Run`, Startup folder references
   - Evasion: `Sleep`, `Start-Sleep`, environment checks

4. **Decoded payload extraction:**
   - If a base64 string decodes to PE or another script, write decoded content to `extract_dir`, add to `extracted_artifacts`
   - Same for hex-encoded payloads

5. **Metadata output:**

```python
{
    "script_type": "powershell",
    "file_size": 4521,
    "line_count": 87,
    "max_line_length": 342,
    "encoding": "utf-8",
    "has_obfuscation": True,
    "obfuscation_indicators": ["base64_payload", "string_concatenation"],
    "decoded_payloads": 1,
    "download_indicators": ["Invoke-WebRequest", "Net.WebClient"],
    "execution_indicators": ["Invoke-Expression", "Start-Process"],
}
```

## 7. FormatAnalysisStage

New file: `worker/src/malscan_worker/stages/format_analysis.py`

Replaces `DocumentAnalysisStage`. Single pipeline integration point.

```python
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from malscan_worker.analyzers.base import AnalysisResult, AnalyzerContext
from malscan_worker.analyzers.registry import get_default_analyzer_registry
from malscan_worker.config import get_settings
from malscan_worker.db import create_artifact
from malscan_worker.stages.base import Stage, StageContext, StageResult
from malscan_worker.utils.submission import InternalJobSubmitter

log = structlog.get_logger()

MAX_FILE_SIZE_FOR_ANALYSIS = 50 * 1024 * 1024  # 50 MB, overridden by config


class FormatAnalysisStage(Stage):
    """Format-specific deep analysis. Dispatches to the matching FormatAnalyzer."""

    def __init__(self) -> None:
        self._registry = get_default_analyzer_registry()

    @property
    def name(self) -> str:
        return "format-analysis"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)
        settings = get_settings()
        max_size = getattr(settings, "analysis_max_file_size", MAX_FILE_SIZE_FOR_ANALYSIS)

        if not ctx.file_path or not ctx.file_path.exists():
            return self._result(started_at, "skipped", {"reason": "File not found"})

        file_size = ctx.file_path.stat().st_size
        if file_size > max_size:
            return self._result(started_at, "skipped", {"reason": f"Too large ({file_size} bytes)"})

        mime = self._get_mime(ctx)
        analyzer = self._registry.detect(ctx.file_path, mime)
        if analyzer is None:
            return self._result(started_at, "skipped", {"reason": "No matching analyzer"})

        log.info("format_analysis_start", job_id=ctx.job_id, analyzer=analyzer.name, file=str(ctx.file_path))

        analyzer_ctx = AnalyzerContext(
            job_id=ctx.job_id,
            sha256=ctx.sha256,
            original_filename=ctx.original_filename,
            file_size=file_size,
        )

        extract_dir = Path(f"/tmp/{ctx.job_id}/analysis_artifacts")
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            result = await asyncio.to_thread(analyzer.analyze, ctx.file_path, extract_dir, analyzer_ctx)
        except Exception as exc:
            log.error("format_analysis_error", job_id=ctx.job_id, analyzer=analyzer.name, error=str(exc), exc_info=True)
            return self._result(started_at, "failed", {"error": str(exc), "analyzer": analyzer.name})

        findings = self._result_to_findings(result)

        # Submit extracted artifacts as sub-jobs
        sub_jobs = 0
        if result.extracted_artifacts and ctx.job:
            sub_jobs = await self._submit_artifacts(ctx, result.extracted_artifacts)
        findings["sub_jobs_created"] = sub_jobs

        # Truncate large lists
        findings["suspicious_keywords"] = findings.get("suspicious_keywords", [])[:100]
        findings["findings"] = findings.get("findings", [])[:200]

        log.info(
            "format_analysis_done",
            job_id=ctx.job_id,
            analyzer=analyzer.name,
            format_type=result.format_type,
            exploit_indicators=len(result.exploit_indicators),
            embedded_objects=len(result.embedded_objects),
            artifacts_extracted=len(result.extracted_artifacts),
            sub_jobs=sub_jobs,
        )

        return self._result(started_at, "ok", findings)

    def _result_to_findings(self, result: AnalysisResult) -> dict[str, Any]:
        """Convert AnalysisResult to findings dict for backward-compatible report format."""
        findings: dict[str, Any] = {
            "format_type": result.format_type,
            "findings": result.findings,
            "exploit_indicators": result.exploit_indicators,
            "embedded_objects": result.embedded_objects,
            "extracted_artifacts": [
                {"filename": a.get("filename"), "sha256": a.get("sha256"), "size": a.get("size"), "source": a.get("source")}
                for a in result.extracted_artifacts
            ],
            "suspicious_keywords": result.suspicious_keywords,
            "errors": result.errors,
            "metadata": result.metadata,
        }
        if result.macros is not None:
            findings["macros"] = {
                "found": result.macros.found,
                "auto_exec": result.macros.auto_exec,
                "suspicious": result.macros.suspicious,
                "sources": result.macros.sources,
            }
        else:
            findings["macros"] = {}
        return findings

    async def _submit_artifacts(self, ctx: StageContext, artifacts: list[dict[str, Any]]) -> int:
        """Submit extracted artifacts as sub-jobs with artifact records.

        Same logic as the old DocumentAnalysisStage._submit_artifacts(), moved here
        because analyzers do not access the DB or submit jobs.
        """
        # ... identical to DocumentAnalysisStage._submit_artifacts() ...
        # Creates root artifact if needed, cycle detection, dedup, submission
        ...

    @staticmethod
    def _get_mime(ctx: StageContext) -> str:
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
            artifacts=[f["filename"] for f in findings.get("extracted_artifacts", [])],
        )
```

## 8. Pipeline Integration

### 8.1 Stage Replacement

```python
# pipeline.py
from malscan_worker.stages.format_analysis import FormatAnalysisStage

SEQUENTIAL_STAGES = [
    ArchiveExtractStage(),
    FormatAnalysisStage(),    # was: DocumentAnalysisStage()
    SandboxStage(),
]
```

### 8.2 Scoring Changes in `_build_analysis_result()`

The scoring section changes from `stage_findings.get("document-analysis", {})` to `stage_findings.get("format-analysis", {})`.

New format-specific scoring rules are added alongside the existing document scoring:

```python
# In _build_analysis_result():

fmt = stage_findings.get("format-analysis", {})
format_type = fmt.get("format_type")
exploit_indicators = fmt.get("exploit_indicators", [])
macros = fmt.get("macros", {})
embedded_objects = fmt.get("embedded_objects", [])
suspicious_keywords = fmt.get("suspicious_keywords", [])

# --- Universal exploit indicator scoring (unchanged, works for all formats) ---
if exploit_indicators:
    has_equation = any(
        "equation_editor" in ind.get("type", "") or ind.get("cves")
        for ind in exploit_indicators
    )
    has_external_template = any(
        ind.get("type") in ("external_template", "external_relationship")
        for ind in exploit_indicators
    )
    has_dde = any(ind.get("type") == "dde_field" for ind in exploit_indicators)
    has_dangerous_class = any(ind.get("type") == "dangerous_ole_class" for ind in exploit_indicators)

    if has_equation:
        verdict = "malicious"
        score = max(score, 85)
    if has_external_template:
        if verdict == "clean":
            verdict = "suspicious"
        score = max(score, 70)
    if has_dde:
        if verdict == "clean":
            verdict = "suspicious"
        score = max(score, 60)
    if has_dangerous_class:
        if verdict == "clean":
            verdict = "suspicious"
        score = max(score, 55)

    extra = max(0, len(exploit_indicators) - 1) * 5
    score = max(score, 50 + extra)
    if verdict == "clean":
        verdict = "suspicious"

# --- Macro scoring (unchanged, applies to ole/ooxml/rtf) ---
if macros.get("found"):
    if macros.get("auto_exec") and macros.get("suspicious"):
        if verdict == "clean":
            verdict = "suspicious"
        score = max(score, 65 + min(len(suspicious_keywords), 10) * 2)
    elif macros.get("auto_exec"):
        if verdict == "clean":
            verdict = "suspicious"
        score = max(score, 45)
    elif macros.get("suspicious"):
        if verdict == "clean":
            verdict = "suspicious"
        score = max(score, 40)
    else:
        score = max(score, 15)

# --- Embedded objects scoring (unchanged) ---
if len(embedded_objects) > 3:
    score = max(score, 30 + len(embedded_objects) * 2)
    if verdict == "clean":
        verdict = "suspicious"

# --- PE-specific scoring (NEW) ---
if format_type == "pe":
    metadata = fmt.get("metadata", {})
    if metadata.get("is_packed"):
        score = max(score, 40)
        if verdict == "clean":
            verdict = "suspicious"
    suspicious_imports = metadata.get("suspicious_imports", [])
    if len(suspicious_imports) >= 3:
        score = max(score, 50 + min(len(suspicious_imports), 15) * 3)
        if verdict == "clean":
            verdict = "suspicious"
    if metadata.get("compile_timestamp_suspicious"):
        score = max(score, 25)

# --- PDF-specific scoring (NEW) ---
if format_type == "pdf":
    metadata = fmt.get("metadata", {})
    if metadata.get("has_javascript"):
        score = max(score, 45)
        if verdict == "clean":
            verdict = "suspicious"
    if metadata.get("has_launch_action"):
        score = max(score, 65)
        if verdict == "clean":
            verdict = "suspicious"
    if metadata.get("has_embedded_files"):
        score = max(score, 30)

# --- Script-specific scoring (NEW) ---
if format_type == "script":
    metadata = fmt.get("metadata", {})
    if metadata.get("has_obfuscation"):
        score = max(score, 40)
        if verdict == "clean":
            verdict = "suspicious"
    if metadata.get("decoded_payloads", 0) > 0:
        score = max(score, 55)
        if verdict == "clean":
            verdict = "suspicious"
    download_inds = metadata.get("download_indicators", [])
    exec_inds = metadata.get("execution_indicators", [])
    if download_inds and exec_inds:
        # Download + execute pattern = high risk
        score = max(score, 65)
        if verdict == "clean":
            verdict = "suspicious"
```

### 8.3 Report Format

The `results` section of the report changes:

**Before:**
```json
{
    "results": {
        "document_analysis": {
            "document_type": "ole",
            "exploit_indicators": [...],
            ...
        }
    }
}
```

**After:**
```json
{
    "results": {
        "format_analysis": {
            "format_type": "pe",
            "findings": [...],
            "exploit_indicators": [...],
            "embedded_objects": [...],
            "extracted_artifacts": [...],
            "suspicious_keywords": [...],
            "macros": {},
            "metadata": { "machine": "AMD64", "is_packed": true, ... },
            "errors": [],
            "sub_jobs_created": 0
        }
    }
}
```

The key name changes from `document_analysis` to `format_analysis`. The `document_type` field becomes `format_type`. A new `metadata` field carries format-specific data. Old reports stored in DB remain unaffected (they have `document_analysis` key which the frontend can check for backward compatibility).

## 9. Configuration

```python
# config.py additions:

class Settings(BaseSettings):
    # ... existing settings ...

    # Format analysis
    analysis_max_file_size: int = 50_000_000    # 50MB (replaces hardcoded MAX_FILE_SIZE_FOR_PARSE)
    pe_analysis_enabled: bool = True
    pdf_analysis_enabled: bool = True
    script_analysis_enabled: bool = True
```

Environment variables: `ANALYSIS_MAX_FILE_SIZE`, `PE_ANALYSIS_ENABLED`, `PDF_ANALYSIS_ENABLED`, `SCRIPT_ANALYSIS_ENABLED`.

Per-analyzer flags allow operators to disable new analyzers without code changes during rollout. Document analyzers (RTF/OLE/OOXML) are always enabled since they are existing functionality.

## 10. Dependencies

New entries in `worker/pyproject.toml`:

```toml
[project]
dependencies = [
    # ... existing ...
    "pefile>=2023.2.7",
    "pypdf>=4.0",
]
```

Both are pure Python, well-maintained, widely used in the security tooling ecosystem.

## 11. Test Cases

### 11.1 Unit Tests Per Analyzer

Each analyzer gets its own test file with synthetic test samples. Test data is built in fixtures -- no real malware in the repo.

| Test file | Source | Key tests |
|-----------|--------|-----------|
| `tests/test_rtf_analyzer.py` | From `test_document_analysis.py` RTF tests | RTF magic detection, control word scanning, Equation Editor detection, rtfobj extraction, fallback hex extraction |
| `tests/test_ole_analyzer.py` | From `test_document_analysis.py` OLE tests | OLE magic detection, oleid scanning, oleobj extraction, stream scanning, DDE detection, VBA macro analysis |
| `tests/test_ooxml_analyzer.py` | From `test_document_analysis.py` OOXML tests | OOXML magic detection, .rels parsing, external target detection, vbaProject.bin detection, embedded OLE extraction |
| `tests/test_pe_analyzer.py` | NEW | MZ detection, header parsing, section entropy, import flagging, packing detection, resource extraction |
| `tests/test_pdf_analyzer.py` | NEW | %PDF detection, JS detection, action scanning, embedded file extraction, name obfuscation detection |
| `tests/test_script_analyzer.py` | NEW | Script type detection, obfuscation detection, base64 decoding, pattern matching per script type |
| `tests/test_analyzer_registry.py` | NEW | Registration order, first-match wins, fallthrough to None, config flag gating |
| `tests/test_format_analysis_stage.py` | NEW | Stage integration: context building, analyzer dispatch, artifact submission, scoring |

### 11.2 Key Test Scenarios

| # | Test | Input | Expected |
|---|------|-------|----------|
| 1 | PE packed | Synthetic PE with UPX section name + high entropy | `is_packed: True`, score >= 40 |
| 2 | PE with injection imports | PE importing VirtualAllocEx + CreateRemoteThread | `suspicious_imports` populated, score >= 50 |
| 3 | PE clean | Minimal PE with normal imports | No findings, score 0 |
| 4 | PDF with JavaScript | PDF with `/OpenAction` + `/JS` | `has_javascript: True`, JS extracted, score >= 45 |
| 5 | PDF with launch action | PDF with `/Launch` action | `has_launch_action: True`, score >= 65 |
| 6 | PDF with embedded file | PDF with `/EmbeddedFiles` | File extracted to artifacts, score >= 30 |
| 7 | PDF clean | Normal PDF with text pages | No findings, score 0 |
| 8 | PS1 with base64 payload | PowerShell with `-EncodedCommand` + base64 PE | `has_obfuscation: True`, decoded payload extracted, score >= 55 |
| 9 | VBS with download+exec | VBScript with `DownloadString` + `Execute` | Download + execution indicators, score >= 65 |
| 10 | JS with char code obfuscation | JavaScript with `String.fromCharCode` chains | Obfuscation detected, score >= 40 |
| 11 | Batch clean | Simple batch file | No suspicious patterns, score 0 |
| 12 | Registry detection order | File matching both OLE and PE (unlikely but tested) | First registered match wins |
| 13 | Config disable PE | `PE_ANALYSIS_ENABLED=false` + PE file | Stage returns "skipped" (no PE analyzer registered) |
| 14 | RTF backward compat | Same RTF test data as existing tests | Same findings, same exploit indicators |

### 11.3 Synthetic Test Data Examples

**PE test fixture:**
```python
def _make_minimal_pe(tmp_path) -> Path:
    """Create a minimal valid PE file for testing."""
    # MZ header + PE signature + minimal headers
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)  # e_lfanew = 64
    pe_sig = b"PE\x00\x00"
    file_header = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x22)  # AMD64, 1 section
    # ... minimal optional header and section table
    pe_file = tmp_path / "test.exe"
    pe_file.write_bytes(dos_header + pe_sig + file_header + ...)
    return pe_file
```

**PDF test fixture:**
```python
def _make_pdf_with_js(tmp_path, js_code: str = "app.alert('test')") -> Path:
    """Create a minimal PDF with JavaScript."""
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj <</Type /Catalog /Pages 2 0 R /OpenAction 3 0 R>> endobj\n"
        b"3 0 obj <</S /JavaScript /JS (" + js_code.encode() + b")>> endobj\n"
        # ... minimal page tree and xref
    )
    pdf_file = tmp_path / "test.pdf"
    pdf_file.write_bytes(pdf)
    return pdf_file
```

## 12. Files Changed

### New Files (14)

| File | Purpose | Lines (est.) |
|------|---------|-------------|
| `worker/src/malscan_worker/analyzers/__init__.py` | Package init, exports | 20 |
| `worker/src/malscan_worker/analyzers/base.py` | FormatAnalyzer ABC, AnalysisResult, MacroResult, AnalyzerContext | 80 |
| `worker/src/malscan_worker/analyzers/registry.py` | AnalyzerRegistry + get_default_analyzer_registry() | 50 |
| `worker/src/malscan_worker/analyzers/_constants.py` | Shared constants (from document_analysis.py) | 80 |
| `worker/src/malscan_worker/analyzers/_helpers.py` | Shared helpers (from document_analysis.py) | 70 |
| `worker/src/malscan_worker/analyzers/_vba_helpers.py` | VBA macro analysis (shared by OLE + OOXML) | 90 |
| `worker/src/malscan_worker/analyzers/rtf_analyzer.py` | RTF format analyzer | 200 |
| `worker/src/malscan_worker/analyzers/ole_analyzer.py` | OLE format analyzer | 300 |
| `worker/src/malscan_worker/analyzers/ooxml_analyzer.py` | OOXML format analyzer | 250 |
| `worker/src/malscan_worker/analyzers/pe_analyzer.py` | PE format analyzer | 350 |
| `worker/src/malscan_worker/analyzers/pdf_analyzer.py` | PDF format analyzer | 300 |
| `worker/src/malscan_worker/analyzers/script_analyzer.py` | Script format analyzer | 250 |
| `worker/src/malscan_worker/stages/format_analysis.py` | FormatAnalysisStage | 180 |
| `worker/tests/test_analyzer_registry.py` | Registry unit tests | 80 |

### Modified Files (4)

| File | Change |
|------|--------|
| `worker/src/malscan_worker/pipeline.py` | Replace DocumentAnalysisStage import/usage with FormatAnalysisStage; update scoring section to use "format-analysis" key and add PE/PDF/script scoring rules |
| `worker/src/malscan_worker/config.py` | Add `analysis_max_file_size`, `pe_analysis_enabled`, `pdf_analysis_enabled`, `script_analysis_enabled` settings |
| `worker/pyproject.toml` | Add `pefile>=2023.2.7` and `pypdf>=4.0` to dependencies |
| `worker/tests/conftest.py` | No changes needed (existing fixtures work as-is) |

### Deleted Files (1)

| File | Reason |
|------|--------|
| `worker/src/malscan_worker/stages/document_analysis.py` | Logic moved to `analyzers/` package |

### Test Files (9 new, 1 deleted)

| File | Status |
|------|--------|
| `worker/tests/test_document_analysis.py` | DELETED (split into per-analyzer tests) |
| `worker/tests/test_rtf_analyzer.py` | NEW (from existing RTF tests) |
| `worker/tests/test_ole_analyzer.py` | NEW (from existing OLE tests) |
| `worker/tests/test_ooxml_analyzer.py` | NEW (from existing OOXML tests) |
| `worker/tests/test_pe_analyzer.py` | NEW |
| `worker/tests/test_pdf_analyzer.py` | NEW |
| `worker/tests/test_script_analyzer.py` | NEW |
| `worker/tests/test_analyzer_registry.py` | NEW |
| `worker/tests/test_format_analysis_stage.py` | NEW |

## 13. Migration / Rollout Strategy

1. **No database migration needed** -- this is a worker-internal change. No new tables, no schema changes.
2. **Report key change** -- `document_analysis` -> `format_analysis` in the report JSON. Frontend needs updating to read either key for backward compatibility with old stored reports.
3. **Gradual rollout** -- new analyzers (PE, PDF, Script) can be disabled via config flags (`PE_ANALYSIS_ENABLED=false`) during initial deployment. Enable one at a time.
4. **Existing behavior preserved** -- RTF/OLE/OOXML analysis produces identical findings. The refactoring is mechanical extraction with no logic changes.
5. **Dependency addition** -- `pefile` and `pypdf` are pure Python wheels, no system-level dependencies. `pip install` in the existing Dockerfile handles it.
