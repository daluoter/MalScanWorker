# MalScan Worker

Malware analysis worker with staged static and recursive analysis.

## Pipeline Overview

Current pipeline flow:

1. **Parallel static stages**
   - `file-type` - file type detection using `python-magic`
   - `clamav` - ClamAV scanning
   - `yara` - YARA rule matching
   - `ioc-extract` - regex IOC extraction
   - `deobfuscation` - decode and normalize obfuscated strings to recover hidden IOCs
2. **Format-specific stage**
   - `format-analysis` - dispatch to a format analyzer via `AnalyzerRegistry`
3. **Sequential stages**
   - `archive-extract` - recursive extraction + sub-job creation
   - `document-analysis` - document parsing and artifact extraction
   - `sandbox` - deferred sandbox dispatch / provider-backed dynamic analysis

## Stages

1. **file-type** - File type detection using python-magic
2. **clamav** - ClamAV scanning using clamscan CLI
3. **yara** - YARA rule matching using yara CLI
4. **ioc-extract** - IOC extraction using regex patterns
5. **deobfuscation** - Decoding and normalization of obfuscated content to recover IOCs
6. **format-analysis** - AnalyzerRegistry dispatch and unified format risk scoring
7. **archive-extract** - Archive extraction and recursive artifact scheduling
8. **document-analysis** - Document parsing and artifact extraction
9. **sandbox** - Sandbox dispatch stage with provider-backed dynamic analysis

## Sandbox Architecture

The worker now uses two roles:

1. `python -m malscan_worker.main`
   - consumes `malscan.jobs`
   - finishes static/recursive analysis
   - stores a partial report if sandbox work is deferred
   - publishes a follow-up message to `malscan.jobs.sandbox`

2. `python -m malscan_worker.sandbox_main`
   - consumes `malscan.jobs.sandbox`
   - runs the configured sandbox provider
   - writes normalized `results.sandbox`
   - recomputes direct risk and marks the job `done`

## Sandbox Providers

Supported provider names:

1. `mock`
2. `capev2`

Relevant environment variables:

- `SANDBOX_PROVIDER`
- `SANDBOX_BASE_URL`
- `SANDBOX_API_TOKEN`
- `SANDBOX_TIMEOUT_SECONDS`
- `SANDBOX_POLL_INTERVAL_SECONDS`
- `SANDBOX_ENABLE_URL_SUBMISSION`
- `RABBITMQ_SANDBOX_QUEUE`

If the configured provider is unavailable, the worker falls back to `mock` and records the reason in `results.sandbox.errors`.

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
- Deobfuscation output is merged into IOC/report results via `results.deobfuscation`.
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
poetry run python -m malscan_worker.sandbox_main
```
