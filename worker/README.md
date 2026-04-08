# MalScan Worker

Malware analysis worker with staged static and recursive analysis.

## Pipeline Overview

Current pipeline flow:

1. **Parallel static stages**
   - `file-type` - file type detection using `python-magic`
   - `clamav` - ClamAV scanning
   - `yara` - YARA rule matching
   - `ioc-extract` - regex IOC extraction
2. **Format-specific stage**
   - `format-analysis` - dispatch to a format analyzer via `AnalyzerRegistry`
3. **Sequential stages**
   - `archive-extract` - recursive extraction + sub-job creation
   - `sandbox` - sandbox analysis (mock in MVP)

## Format-Specific Analyzer Layer (Phase 1)

### What `AnalyzerRegistry` is

`AnalyzerRegistry` is a first-match dispatch registry for pluggable analyzers.

- It reads file MIME + first bytes (magic)
- It selects the first analyzer whose `can_handle(...)` returns `True`
- It enforces deterministic analyzer priority order

Current default order:

1. `PEAnalyzer`
2. `OfficeAnalyzerAdapter`
3. `PDFAnalyzer`
4. `LNKAnalyzer`
5. `ScriptAnalyzer`

### Supported formats in this phase

- **PE** (`.exe`, `.dll`-like binaries)
- **Office documents** (`RTF`, OLE, OOXML) via adapter/shim
- **PDF**
- **LNK** (Windows shortcut)
- **Scripts** (PowerShell, JavaScript, VBScript, Batch, HTA)

### Office integration approach (adapter/shim)

`DocumentAnalysisStage` was not rewritten. Instead, it is wrapped by
`OfficeAnalyzerAdapter`, which:

- reuses existing Office parsing/exploit detection logic
- converts `DocumentAnalysisStage` findings into unified `AnalyzerResult`
- maps legacy Office indicator semantics into shared severity-based scoring

This allows incremental migration without breaking existing Office internals.

### Behavior and scoring changes

- A new `format-analysis` stage runs after parallel static stages.
- Pipeline scoring now includes `format-analysis` indicator severity and analyzer risk score.
- Reports now include `results.format_analysis`.
- `results.document_analysis` remains in output for backward compatibility.
- Format analyzers can submit extracted artifacts as sub-jobs through stage-level handling.
- Artifact submission now enforces recursive depth limits (same guard style as other recursive stages).

### What is intentionally not included yet

- Full `DocumentAnalysisStage` decomposition into native Office analyzer internals
- Advanced PDF JavaScript emulation/deobfuscation
- Full LNK extra-data ecosystem parsing
- AST/symbolic execution level script analysis
- Cross-format correlation (e.g., LNK -> script -> downloader chain attribution)

### Known limitations / follow-up work

- Some parser libraries are optional and degrade gracefully when unavailable.
- Heuristic indicators prioritize coverage and explainability over perfect precision.
- Existing third-party deprecation warnings (Pydantic/oletools stack) remain and are unrelated to this feature.
- Future work should add deeper format semantics, correlation, and threat intel enrichment.

## Development

```bash
poetry install
poetry run python -m malscan_worker.main
```
