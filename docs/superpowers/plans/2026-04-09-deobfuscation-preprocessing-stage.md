# Deobfuscation Preprocessing Stage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement an additive `DeobfuscationStage` that runs in parallel, decodes single-layer obfuscation patterns (6 decoders), extracts hidden IOCs, and merges them into final report/scoring safely.

**Architecture:** Add a new `deobfuscation/` package (models, safety guard, engine, decoders) and wrap it in `stages/deobfuscation.py`. Keep existing stages unchanged, then update `_build_analysis_result()` to merge deobfuscated IOCs, expose a `results.deobfuscation` section, and apply a conservative additive score boost. Enforce strict resource limits (file size, candidate count, decoded bytes, wall-time, expansion ratio).

**Tech Stack:** Python 3.11, asyncio, dataclasses, regex, base64, pytest/pytest-asyncio, prometheus_client

**Spec:** `docs/superpowers/specs/2026-04-08-deobfuscation-preprocessing-stage-design.md`

---

## File Structure

### New files (create)

| File | Responsibility |
|------|---------------|
| `worker/src/malscan_worker/deobfuscation/__init__.py` | Export deobfuscation package public API |
| `worker/src/malscan_worker/deobfuscation/models.py` | `Provenance`, `CandidateString`, `ExtractedIOCs`, `ResourceStats`, `DeobfuscationResult` |
| `worker/src/malscan_worker/deobfuscation/safety.py` | `SafetyLimits` and `SafetyGuard` |
| `worker/src/malscan_worker/deobfuscation/engine.py` | Decoder orchestration + IOC extraction |
| `worker/src/malscan_worker/deobfuscation/decoders/__init__.py` | Decoder exports |
| `worker/src/malscan_worker/deobfuscation/decoders/base.py` | `DecoderBase` ABC |
| `worker/src/malscan_worker/deobfuscation/decoders/base64_decoder.py` | Base64 decoder |
| `worker/src/malscan_worker/deobfuscation/decoders/hex_decoder.py` | Hex decoder |
| `worker/src/malscan_worker/deobfuscation/decoders/powershell_decoder.py` | PowerShell `-enc`/`FromBase64String` decoder |
| `worker/src/malscan_worker/deobfuscation/decoders/js_decoder.py` | JS `fromCharCode` / concat / `atob` / escapes decoder |
| `worker/src/malscan_worker/deobfuscation/decoders/url_reassembly.py` | URL/domain reassembly decoder |
| `worker/src/malscan_worker/deobfuscation/decoders/xor_decoder.py` | Single-byte XOR decoder |
| `worker/src/malscan_worker/stages/deobfuscation.py` | New pipeline stage wrapper |
| `worker/tests/stages/test_deobfuscation.py` | Stage tests |
| `worker/tests/test_deobfuscation_engine.py` | Engine + decoders + models + safety tests |
| `worker/tests/test_deobfuscation_pipeline_integration.py` | `_build_analysis_result()` merge/scoring tests |
| `worker/tests/test_recall_improvement.py` | Recall-before-vs-after regression test |
| `worker/tests/fixtures/deobfuscation/base64_url.bin` | Fixture sample |
| `worker/tests/fixtures/deobfuscation/base64_url.bin.expected.json` | Fixture expected IOC ground truth |
| `worker/tests/fixtures/deobfuscation/ps_enc_command.ps1` | Fixture sample |
| `worker/tests/fixtures/deobfuscation/ps_enc_command.ps1.expected.json` | Fixture expected IOC ground truth |
| `worker/tests/fixtures/deobfuscation/js_fromcharcode.js` | Fixture sample |
| `worker/tests/fixtures/deobfuscation/js_fromcharcode.js.expected.json` | Fixture expected IOC ground truth |
| `worker/tests/fixtures/deobfuscation/clean_no_obfuscation.txt` | Negative fixture sample |
| `worker/tests/fixtures/deobfuscation/clean_no_obfuscation.txt.expected.json` | Negative fixture expected output |

### Existing files (modify)

| File | Change |
|------|--------|
| `worker/src/malscan_worker/pipeline.py` | Add `DeobfuscationStage` into `PARALLEL_STAGES`, merge deobfuscated IOCs, add report section, additive risk boost (cap 25), keep compatibility with existing IOC key shapes |
| `worker/src/malscan_worker/config.py` | Add deobfuscation settings and update default `stages_total` from 5 to 6 |
| `worker/src/malscan_worker/metrics.py` | Add deobfuscation counters |
| `worker/src/malscan_worker/stages/__init__.py` | Export `DeobfuscationStage` |
| `worker/README.md` | Update stage inventory and pipeline stage count |

---

## Task 1: Core data models and safety guard (TDD)

**Files:**
- Create: `worker/src/malscan_worker/deobfuscation/__init__.py`
- Create: `worker/src/malscan_worker/deobfuscation/models.py`
- Create: `worker/src/malscan_worker/deobfuscation/safety.py`
- Create: `worker/tests/test_deobfuscation_engine.py`

- [ ] **Step 1: Write failing tests for models + safety guard**

Create `worker/tests/test_deobfuscation_engine.py` with the first test block:

```python
"""Tests for deobfuscation engine, decoders, and safety limits."""

import time

from malscan_worker.deobfuscation.models import CandidateString, Provenance
from malscan_worker.deobfuscation.safety import SafetyGuard, SafetyLimits


def test_candidate_string_defaults():
    prov = Provenance(offset=10, length=24, raw_snippet="aHR0cDov")
    candidate = CandidateString(
        decoded="http://evil.com",
        encoding="base64",
        confidence=0.95,
        provenance=prov,
    )

    assert candidate.encoding == "base64"
    assert candidate.tags == []
    assert candidate.provenance.decoder_chain == []


def test_safety_guard_stops_on_candidate_cap():
    limits = SafetyLimits(max_total_candidates=1, max_decoded_bytes_total=10_000)
    guard = SafetyGuard(limits)

    c1 = CandidateString(
        decoded="http://a.com",
        encoding="base64",
        confidence=0.9,
        provenance=Provenance(offset=0, length=20, raw_snippet="AAAA"),
    )
    c2 = CandidateString(
        decoded="http://b.com",
        encoding="base64",
        confidence=0.9,
        provenance=Provenance(offset=20, length=20, raw_snippet="BBBB"),
    )

    assert guard.accept_candidate(c1) is True
    assert guard.accept_candidate(c2) is False
    assert guard.truncated is True
    assert guard.truncation_reason == "max_total_candidates reached"


def test_safety_guard_stops_on_wall_time_limit():
    limits = SafetyLimits(max_wall_time_ms=1)
    guard = SafetyGuard(limits)

    time.sleep(0.01)
    assert guard.should_stop() is True
    assert guard.truncated is True
    assert guard.truncation_reason == "wall_time_limit reached"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd worker && poetry run pytest tests/test_deobfuscation_engine.py::test_candidate_string_defaults -v`

Expected: `ModuleNotFoundError: No module named 'malscan_worker.deobfuscation'`

- [ ] **Step 3: Create deobfuscation package init**

Create `worker/src/malscan_worker/deobfuscation/__init__.py`:

```python
"""Deobfuscation package for recovering obfuscated strings and IOCs."""

from malscan_worker.deobfuscation.engine import DeobfuscationEngine
from malscan_worker.deobfuscation.models import (
    CandidateString,
    DeobfuscationResult,
    ExtractedIOCs,
    Provenance,
    ResourceStats,
)
from malscan_worker.deobfuscation.safety import SafetyGuard, SafetyLimits

__all__ = [
    "CandidateString",
    "DeobfuscationEngine",
    "DeobfuscationResult",
    "ExtractedIOCs",
    "Provenance",
    "ResourceStats",
    "SafetyGuard",
    "SafetyLimits",
]
```

- [ ] **Step 4: Implement models dataclasses**

Create `worker/src/malscan_worker/deobfuscation/models.py`:

```python
"""Dataclasses used by deobfuscation engine and stage."""

from dataclasses import dataclass, field


@dataclass
class Provenance:
    """Tracks where a decoded candidate originated from raw input."""

    offset: int
    length: int
    raw_snippet: str
    decoder_chain: list[str] = field(default_factory=list)


@dataclass
class CandidateString:
    """One decoded candidate emitted by a decoder."""

    decoded: str
    encoding: str
    confidence: float
    provenance: Provenance
    tags: list[str] = field(default_factory=list)


@dataclass
class ExtractedIOCs:
    """IOCs extracted from all accepted decoded candidates."""

    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)


@dataclass
class ResourceStats:
    """Resource usage and truncation metadata."""

    decoders_applied: list[str] = field(default_factory=list)
    total_candidates: int = 0
    total_decoded_bytes: int = 0
    wall_time_ms: int = 0
    truncated: bool = False
    truncation_reason: str | None = None


@dataclass
class DeobfuscationResult:
    """Aggregate result returned by the engine."""

    candidates: list[CandidateString] = field(default_factory=list)
    extracted_iocs: ExtractedIOCs = field(default_factory=ExtractedIOCs)
    stats: ResourceStats = field(default_factory=ResourceStats)
```

- [ ] **Step 5: Implement safety limits and guard**

Create `worker/src/malscan_worker/deobfuscation/safety.py`:

```python
"""Resource guards for deobfuscation processing."""

import time
from dataclasses import dataclass

from malscan_worker.deobfuscation.models import CandidateString


@dataclass
class SafetyLimits:
    max_input_size: int = 10 * 1024 * 1024
    max_candidates_per_decoder: int = 50
    max_total_candidates: int = 200
    max_decoded_bytes_total: int = 5 * 1024 * 1024
    max_wall_time_ms: int = 10_000
    max_xor_blob_size: int = 4096
    max_entropy_scan_bytes: int = 1 * 1024 * 1024
    min_confidence_threshold: float = 0.3
    max_expansion_ratio: float = 10.0


class SafetyGuard:
    """Tracks aggregate limits and decides whether to accept candidates."""

    def __init__(self, limits: SafetyLimits):
        self.limits = limits
        self.total_candidates = 0
        self.total_decoded_bytes = 0
        self.truncated = False
        self.truncation_reason: str | None = None
        self._start = time.monotonic()

    def should_stop(self) -> bool:
        if self.truncated:
            return True

        elapsed_ms = (time.monotonic() - self._start) * 1000
        if elapsed_ms >= self.limits.max_wall_time_ms:
            self.truncated = True
            self.truncation_reason = "wall_time_limit reached"
            return True

        return False

    def accept_candidate(self, candidate: CandidateString) -> bool:
        if self.should_stop():
            return False

        decoded_len = len(candidate.decoded.encode("utf-8", errors="replace"))
        encoded_len = max(candidate.provenance.length, 1)

        if decoded_len / encoded_len > self.limits.max_expansion_ratio:
            return False

        if self.total_candidates + 1 > self.limits.max_total_candidates:
            self.truncated = True
            self.truncation_reason = "max_total_candidates reached"
            return False

        if self.total_decoded_bytes + decoded_len > self.limits.max_decoded_bytes_total:
            self.truncated = True
            self.truncation_reason = "max_decoded_bytes reached"
            return False

        self.total_candidates += 1
        self.total_decoded_bytes += decoded_len
        return True
```

- [ ] **Step 6: Run tests to verify pass**

Run: `cd worker && poetry run pytest tests/test_deobfuscation_engine.py::test_candidate_string_defaults tests/test_deobfuscation_engine.py::test_safety_guard_stops_on_candidate_cap tests/test_deobfuscation_engine.py::test_safety_guard_stops_on_wall_time_limit -v`

Expected: `3 passed`

- [ ] **Step 7: Commit**

```bash
git add worker/src/malscan_worker/deobfuscation/__init__.py worker/src/malscan_worker/deobfuscation/models.py worker/src/malscan_worker/deobfuscation/safety.py worker/tests/test_deobfuscation_engine.py
git commit -m "feat: add deobfuscation core models and safety guard"
```

---

## Task 2: Decoder base + Base64 and Hex decoders (TDD)

**Files:**
- Create: `worker/src/malscan_worker/deobfuscation/decoders/__init__.py`
- Create: `worker/src/malscan_worker/deobfuscation/decoders/base.py`
- Create: `worker/src/malscan_worker/deobfuscation/decoders/base64_decoder.py`
- Create: `worker/src/malscan_worker/deobfuscation/decoders/hex_decoder.py`
- Modify: `worker/tests/test_deobfuscation_engine.py`

- [ ] **Step 1: Add failing tests for Base64 + Hex decoders**

Append to `worker/tests/test_deobfuscation_engine.py`:

```python
from malscan_worker.deobfuscation.decoders.base64_decoder import Base64Decoder
from malscan_worker.deobfuscation.decoders.hex_decoder import HexDecoder


def test_base64_decoder_extracts_url_candidate():
    content = b"prefix aHR0cDovL2V2aWwuY29tL3BheWxvYWQuZXhl suffix"
    decoder = Base64Decoder()

    out = decoder.extract_candidates(content, limit=10)

    assert any(c.decoded == "http://evil.com/payload.exe" for c in out)
    assert any(c.encoding == "base64" for c in out)
    assert any(c.confidence >= 0.9 for c in out)


def test_hex_decoder_extracts_hex_escape_url():
    content = br"\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d"
    decoder = HexDecoder()

    out = decoder.extract_candidates(content, limit=10)

    assert any("http://evil.com" in c.decoded for c in out)
    assert all(c.encoding == "hex" for c in out)


def test_base64_decoder_discards_short_payloads():
    content = b"dGVzdA=="  # "test"
    decoder = Base64Decoder()

    out = decoder.extract_candidates(content, limit=10)

    assert out == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd worker && poetry run pytest tests/test_deobfuscation_engine.py::test_base64_decoder_extracts_url_candidate tests/test_deobfuscation_engine.py::test_hex_decoder_extracts_hex_escape_url tests/test_deobfuscation_engine.py::test_base64_decoder_discards_short_payloads -v`

Expected: `ModuleNotFoundError` for decoder modules.

- [ ] **Step 3: Implement decoder base and package exports**

Create `worker/src/malscan_worker/deobfuscation/decoders/base.py`:

```python
"""Abstract decoder contract for deobfuscation decoders."""

from abc import ABC, abstractmethod

from malscan_worker.deobfuscation.models import CandidateString


class DecoderBase(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique decoder name."""

    @abstractmethod
    def extract_candidates(self, content: bytes, limit: int = 50) -> list[CandidateString]:
        """Scan `content`, decode matching patterns, and return candidates."""
```

Create `worker/src/malscan_worker/deobfuscation/decoders/__init__.py`:

```python
"""Decoder implementations for deobfuscation engine."""

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.decoders.base64_decoder import Base64Decoder
from malscan_worker.deobfuscation.decoders.hex_decoder import HexDecoder

__all__ = ["DecoderBase", "Base64Decoder", "HexDecoder"]
```

- [ ] **Step 4: Implement Base64 and Hex decoders**

Create `worker/src/malscan_worker/deobfuscation/decoders/base64_decoder.py`:

```python
"""Base64 decoder for extracting text-like payloads."""

import base64
import re

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.models import CandidateString, Provenance

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{20,}={0,2})(?![A-Za-z0-9+/=_-])")
_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class Base64Decoder(DecoderBase):
    @property
    def name(self) -> str:
        return "base64"

    def extract_candidates(self, content: bytes, limit: int = 50) -> list[CandidateString]:
        text = content.decode("latin-1", errors="ignore")
        out: list[CandidateString] = []
        seen: set[str] = set()

        for match in _B64_RE.finditer(text):
            if len(out) >= limit:
                break

            blob = match.group(1)
            decoded = self._decode_blob(blob)
            if decoded is None or len(decoded) < 4:
                continue
            if decoded in seen:
                continue

            confidence = self._score(decoded)
            if confidence < 0.3:
                continue

            seen.add(decoded)
            out.append(
                CandidateString(
                    decoded=decoded,
                    encoding=self.name,
                    confidence=confidence,
                    provenance=Provenance(
                        offset=match.start(1),
                        length=len(blob),
                        raw_snippet=blob[:200],
                        decoder_chain=[self.name],
                    ),
                    tags=self._tags(decoded),
                )
            )

        return out

    def _decode_blob(self, blob: str) -> str | None:
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        except Exception:
            return None

        text = raw.decode("utf-8", errors="ignore").strip("\x00\r\n\t ")
        return text or None

    def _score(self, decoded: str) -> float:
        if _URL_RE.search(decoded) or _DOMAIN_RE.search(decoded) or _IP_RE.search(decoded):
            return 0.95
        printable = sum(ch.isprintable() for ch in decoded) / max(len(decoded), 1)
        if printable >= 0.9:
            return 0.8
        if printable >= 0.6:
            return 0.4
        return 0.2

    def _tags(self, decoded: str) -> list[str]:
        tags: list[str] = []
        if _URL_RE.search(decoded):
            tags.append("url")
        if _DOMAIN_RE.search(decoded):
            tags.append("domain")
        if _IP_RE.search(decoded):
            tags.append("ip")
        return tags
```

Create `worker/src/malscan_worker/deobfuscation/decoders/hex_decoder.py`:

```python
"""Hex-like string decoder."""

import re

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.models import CandidateString, Provenance

_HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){4,}")
_ZEROX_RE = re.compile(r"(?:0x[0-9A-Fa-f]{2}\s*,?\s*){4,}")
_PERCENT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_RAW_HEX_RE = re.compile(r"\b[0-9A-Fa-f]{8,}\b")
_IOC_RE = re.compile(r"https?://|\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b")


class HexDecoder(DecoderBase):
    @property
    def name(self) -> str:
        return "hex"

    def extract_candidates(self, content: bytes, limit: int = 50) -> list[CandidateString]:
        text = content.decode("latin-1", errors="ignore")
        out: list[CandidateString] = []
        seen: set[str] = set()

        for regex, parser in (
            (_HEX_ESCAPE_RE, self._parse_x_escape),
            (_ZEROX_RE, self._parse_0x),
            (_PERCENT_RE, self._parse_percent),
            (_RAW_HEX_RE, self._parse_raw_hex),
        ):
            for match in regex.finditer(text):
                if len(out) >= limit:
                    return out
                decoded = parser(match.group(0))
                if decoded is None or decoded in seen:
                    continue
                score = 0.9 if _IOC_RE.search(decoded) else 0.7
                if len(decoded) < 4:
                    score = 0.1
                if score < 0.3:
                    continue
                seen.add(decoded)
                out.append(
                    CandidateString(
                        decoded=decoded,
                        encoding=self.name,
                        confidence=score,
                        provenance=Provenance(
                            offset=match.start(0),
                            length=len(match.group(0)),
                            raw_snippet=match.group(0)[:200],
                            decoder_chain=[self.name],
                        ),
                        tags=["url"] if "http" in decoded else [],
                    )
                )

        return out

    def _parse_x_escape(self, raw: str) -> str | None:
        pieces = re.findall(r"\\x([0-9A-Fa-f]{2})", raw)
        return self._decode_hex_pairs(pieces)

    def _parse_0x(self, raw: str) -> str | None:
        pieces = re.findall(r"0x([0-9A-Fa-f]{2})", raw)
        return self._decode_hex_pairs(pieces)

    def _parse_percent(self, raw: str) -> str | None:
        pieces = re.findall(r"%([0-9A-Fa-f]{2})", raw)
        return self._decode_hex_pairs(pieces)

    def _parse_raw_hex(self, raw: str) -> str | None:
        if len(raw) % 2 != 0:
            return None
        pieces = [raw[i : i + 2] for i in range(0, len(raw), 2)]
        return self._decode_hex_pairs(pieces)

    def _decode_hex_pairs(self, pairs: list[str]) -> str | None:
        if not pairs:
            return None
        try:
            decoded = bytes(int(p, 16) for p in pairs).decode("utf-8", errors="ignore").strip()
        except Exception:
            return None
        return decoded or None
```

- [ ] **Step 5: Run tests to verify pass**

Run: `cd worker && poetry run pytest tests/test_deobfuscation_engine.py::test_base64_decoder_extracts_url_candidate tests/test_deobfuscation_engine.py::test_hex_decoder_extracts_hex_escape_url tests/test_deobfuscation_engine.py::test_base64_decoder_discards_short_payloads -v`

Expected: `3 passed`

- [ ] **Step 6: Commit**

```bash
git add worker/src/malscan_worker/deobfuscation/decoders/__init__.py worker/src/malscan_worker/deobfuscation/decoders/base.py worker/src/malscan_worker/deobfuscation/decoders/base64_decoder.py worker/src/malscan_worker/deobfuscation/decoders/hex_decoder.py worker/tests/test_deobfuscation_engine.py
git commit -m "feat: add base64 and hex deobfuscation decoders"
```

---

## Task 3: PowerShell, JS, URL reassembly decoders (TDD)

**Files:**
- Create: `worker/src/malscan_worker/deobfuscation/decoders/powershell_decoder.py`
- Create: `worker/src/malscan_worker/deobfuscation/decoders/js_decoder.py`
- Create: `worker/src/malscan_worker/deobfuscation/decoders/url_reassembly.py`
- Modify: `worker/src/malscan_worker/deobfuscation/decoders/__init__.py`
- Modify: `worker/tests/test_deobfuscation_engine.py`

- [ ] **Step 1: Add failing tests for PowerShell/JS/URL reassembly**

Append to `worker/tests/test_deobfuscation_engine.py`:

```python
from malscan_worker.deobfuscation.decoders.js_decoder import JsDecoder
from malscan_worker.deobfuscation.decoders.powershell_decoder import PowerShellDecoder
from malscan_worker.deobfuscation.decoders.url_reassembly import UrlReassemblyDecoder


def test_powershell_decoder_extracts_encoded_command():
    content = b"powershell -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA=="
    decoder = PowerShellDecoder()

    out = decoder.extract_candidates(content, limit=10)

    assert any("Invoke-Expression" in c.decoded for c in out)
    assert all(c.confidence >= 0.9 for c in out)


def test_js_decoder_extracts_from_char_code_url():
    content = b"String.fromCharCode(104,116,116,112,58,47,47,101,118,105,108,46,99,111,109)"
    decoder = JsDecoder()

    out = decoder.extract_candidates(content, limit=10)

    assert any(c.decoded == "http://evil.com" for c in out)


def test_url_reassembly_decoder_handles_caret_obfuscation():
    content = b"h^t^t^p^:^/^/^e^v^i^l^.^c^o^m"
    decoder = UrlReassemblyDecoder()

    out = decoder.extract_candidates(content, limit=10)

    assert any(c.decoded == "http://evil.com" for c in out)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd worker && poetry run pytest tests/test_deobfuscation_engine.py::test_powershell_decoder_extracts_encoded_command tests/test_deobfuscation_engine.py::test_js_decoder_extracts_from_char_code_url tests/test_deobfuscation_engine.py::test_url_reassembly_decoder_handles_caret_obfuscation -v`

Expected: `ModuleNotFoundError` for new decoder modules.

- [ ] **Step 3: Implement PowerShell decoder**

Create `worker/src/malscan_worker/deobfuscation/decoders/powershell_decoder.py`:

```python
"""PowerShell encoded command decoder."""

import base64
import re

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.models import CandidateString, Provenance

_PS_ENC_RE = re.compile(r"-(?:enc|encodedcommand|e)\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE)
_FROM_B64_RE = re.compile(
    r"(?:\[Convert\]|\[System\.Convert\])::FromBase64String\(\s*['\"]([A-Za-z0-9+/=]{20,})['\"]\s*\)",
    re.IGNORECASE,
)


class PowerShellDecoder(DecoderBase):
    @property
    def name(self) -> str:
        return "powershell"

    def extract_candidates(self, content: bytes, limit: int = 50) -> list[CandidateString]:
        text = content.decode("latin-1", errors="ignore")
        out: list[CandidateString] = []

        for regex in (_PS_ENC_RE, _FROM_B64_RE):
            for match in regex.finditer(text):
                if len(out) >= limit:
                    return out

                blob = match.group(1)
                decoded = self._decode_ps_blob(blob)
                if decoded is None:
                    continue

                out.append(
                    CandidateString(
                        decoded=decoded,
                        encoding=self.name,
                        confidence=0.95,
                        provenance=Provenance(
                            offset=match.start(1),
                            length=len(blob),
                            raw_snippet=blob[:200],
                            decoder_chain=[self.name],
                        ),
                        tags=["powershell", "command"],
                    )
                )

        return out

    def _decode_ps_blob(self, blob: str) -> str | None:
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded)
        except Exception:
            return None

        for enc in ("utf-16le", "utf-8"):
            try:
                decoded = raw.decode(enc, errors="ignore").replace("\x00", "").strip()
                if decoded:
                    return decoded
            except Exception:
                continue
        return None
```

- [ ] **Step 4: Implement JS decoder and URL reassembly decoder**

Create `worker/src/malscan_worker/deobfuscation/decoders/js_decoder.py`:

```python
"""JavaScript string obfuscation decoder."""

import base64
import re

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.models import CandidateString, Provenance

_FROM_CHAR_CODE_RE = re.compile(r"String\.fromCharCode\(([^)]{5,})\)", re.IGNORECASE)
_CONCAT_RE = re.compile(r"(?:['\"][^'\"]*['\"]\s*\+\s*){2,}['\"][^'\"]*['\"]")
_ATOB_RE = re.compile(r"atob\(\s*['\"]([A-Za-z0-9+/=]{12,})['\"]\s*\)", re.IGNORECASE)
_HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){4,}")


class JsDecoder(DecoderBase):
    @property
    def name(self) -> str:
        return "js"

    def extract_candidates(self, content: bytes, limit: int = 50) -> list[CandidateString]:
        text = content.decode("latin-1", errors="ignore")
        out: list[CandidateString] = []

        out.extend(self._extract_from_char_code(text, limit))
        if len(out) >= limit:
            return out[:limit]
        out.extend(self._extract_concat(text, limit - len(out)))
        if len(out) >= limit:
            return out[:limit]
        out.extend(self._extract_atob(text, limit - len(out)))
        if len(out) >= limit:
            return out[:limit]
        out.extend(self._extract_hex_escapes(text, limit - len(out)))

        return out[:limit]

    def _extract_from_char_code(self, text: str, limit: int) -> list[CandidateString]:
        out: list[CandidateString] = []
        for match in _FROM_CHAR_CODE_RE.finditer(text):
            if len(out) >= limit:
                break
            nums = [n.strip() for n in match.group(1).split(",")]
            try:
                chars = [chr(int(n)) for n in nums if n]
            except ValueError:
                continue
            decoded = "".join(chars)
            if not decoded:
                continue
            out.append(
                CandidateString(
                    decoded=decoded,
                    encoding=self.name,
                    confidence=0.85,
                    provenance=Provenance(
                        offset=match.start(0),
                        length=len(match.group(0)),
                        raw_snippet=match.group(0)[:200],
                        decoder_chain=[self.name],
                    ),
                    tags=["script"],
                )
            )
        return out

    def _extract_concat(self, text: str, limit: int) -> list[CandidateString]:
        out: list[CandidateString] = []
        for match in _CONCAT_RE.finditer(text):
            if len(out) >= limit:
                break
            parts = re.findall(r"['\"]([^'\"]*)['\"]", match.group(0))
            decoded = "".join(parts)
            if not decoded:
                continue
            out.append(
                CandidateString(
                    decoded=decoded,
                    encoding=self.name,
                    confidence=0.8,
                    provenance=Provenance(
                        offset=match.start(0),
                        length=len(match.group(0)),
                        raw_snippet=match.group(0)[:200],
                        decoder_chain=[self.name],
                    ),
                    tags=["script"],
                )
            )
        return out

    def _extract_atob(self, text: str, limit: int) -> list[CandidateString]:
        out: list[CandidateString] = []
        for match in _ATOB_RE.finditer(text):
            if len(out) >= limit:
                break
            blob = match.group(1)
            padded = blob + "=" * (-len(blob) % 4)
            try:
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            except Exception:
                continue
            if not decoded:
                continue
            out.append(
                CandidateString(
                    decoded=decoded,
                    encoding=self.name,
                    confidence=0.9,
                    provenance=Provenance(
                        offset=match.start(1),
                        length=len(blob),
                        raw_snippet=blob[:200],
                        decoder_chain=[self.name],
                    ),
                    tags=["script"],
                )
            )
        return out

    def _extract_hex_escapes(self, text: str, limit: int) -> list[CandidateString]:
        out: list[CandidateString] = []
        for match in _HEX_ESCAPE_RE.finditer(text):
            if len(out) >= limit:
                break
            pairs = re.findall(r"\\x([0-9A-Fa-f]{2})", match.group(0))
            try:
                decoded = bytes(int(p, 16) for p in pairs).decode("utf-8", errors="ignore")
            except Exception:
                continue
            if not decoded:
                continue
            out.append(
                CandidateString(
                    decoded=decoded,
                    encoding=self.name,
                    confidence=0.8,
                    provenance=Provenance(
                        offset=match.start(0),
                        length=len(match.group(0)),
                        raw_snippet=match.group(0)[:200],
                        decoder_chain=[self.name],
                    ),
                    tags=["script"],
                )
            )
        return out
```

Create `worker/src/malscan_worker/deobfuscation/decoders/url_reassembly.py`:

```python
"""Reassemble segmented or transformed URL/domain strings."""

import re

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.models import CandidateString, Provenance

_URL_RE = re.compile(r"https?://[a-zA-Z0-9._\-/]+", re.IGNORECASE)


class UrlReassemblyDecoder(DecoderBase):
    @property
    def name(self) -> str:
        return "url_reassembly"

    def extract_candidates(self, content: bytes, limit: int = 50) -> list[CandidateString]:
        text = content.decode("latin-1", errors="ignore")
        out: list[CandidateString] = []

        variants = [
            text.replace("^", ""),
            re.sub(r"\s+", "", text),
        ]

        # Also try reverse scan for common reversed URL pattern.
        if "//:ptth" in text:
            variants.append(text[::-1])

        for variant in variants:
            for match in _URL_RE.finditer(variant):
                if len(out) >= limit:
                    return out
                decoded = match.group(0)
                out.append(
                    CandidateString(
                        decoded=decoded,
                        encoding=self.name,
                        confidence=0.9,
                        provenance=Provenance(
                            offset=max(text.find(decoded[:6]), 0),
                            length=len(decoded),
                            raw_snippet=decoded[:200],
                            decoder_chain=[self.name],
                        ),
                        tags=["url"],
                    )
                )

        return out
```

Update `worker/src/malscan_worker/deobfuscation/decoders/__init__.py`:

```python
from malscan_worker.deobfuscation.decoders.js_decoder import JsDecoder
from malscan_worker.deobfuscation.decoders.powershell_decoder import PowerShellDecoder
from malscan_worker.deobfuscation.decoders.url_reassembly import UrlReassemblyDecoder

__all__ = [
    "DecoderBase",
    "Base64Decoder",
    "HexDecoder",
    "JsDecoder",
    "PowerShellDecoder",
    "UrlReassemblyDecoder",
]
```

- [ ] **Step 5: Run tests to verify pass**

Run: `cd worker && poetry run pytest tests/test_deobfuscation_engine.py::test_powershell_decoder_extracts_encoded_command tests/test_deobfuscation_engine.py::test_js_decoder_extracts_from_char_code_url tests/test_deobfuscation_engine.py::test_url_reassembly_decoder_handles_caret_obfuscation -v`

Expected: `3 passed`

- [ ] **Step 6: Commit**

```bash
git add worker/src/malscan_worker/deobfuscation/decoders/__init__.py worker/src/malscan_worker/deobfuscation/decoders/powershell_decoder.py worker/src/malscan_worker/deobfuscation/decoders/js_decoder.py worker/src/malscan_worker/deobfuscation/decoders/url_reassembly.py worker/tests/test_deobfuscation_engine.py
git commit -m "feat: add powershell js and url reassembly decoders"
```

---

## Task 4: XOR decoder (TDD)

**Files:**
- Create: `worker/src/malscan_worker/deobfuscation/decoders/xor_decoder.py`
- Modify: `worker/src/malscan_worker/deobfuscation/decoders/__init__.py`
- Modify: `worker/tests/test_deobfuscation_engine.py`

- [ ] **Step 1: Add failing tests for XOR decoder**

Append to `worker/tests/test_deobfuscation_engine.py`:

```python
from malscan_worker.deobfuscation.decoders.xor_decoder import XorDecoder


def test_xor_decoder_recovers_url_from_single_byte_xor():
    plain = b"http://evil.com"
    encoded = bytes(b ^ 0x41 for b in plain)
    decoder = XorDecoder()

    out = decoder.extract_candidates(encoded, limit=10)

    assert any(c.decoded == "http://evil.com" for c in out)
    assert any(c.confidence >= 0.6 for c in out)


def test_xor_decoder_discards_non_printable_results():
    decoder = XorDecoder()
    content = bytes(range(1, 64))

    out = decoder.extract_candidates(content, limit=10)

    assert out == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd worker && poetry run pytest tests/test_deobfuscation_engine.py::test_xor_decoder_recovers_url_from_single_byte_xor tests/test_deobfuscation_engine.py::test_xor_decoder_discards_non_printable_results -v`

Expected: `ModuleNotFoundError` for `xor_decoder`.

- [ ] **Step 3: Implement XOR decoder**

Create `worker/src/malscan_worker/deobfuscation/decoders/xor_decoder.py`:

```python
"""Single-byte XOR decoder with entropy and printable filters."""

import math
import re
from collections import Counter

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.models import CandidateString, Provenance

_IOC_RE = re.compile(r"https?://|\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b")


class XorDecoder(DecoderBase):
    @property
    def name(self) -> str:
        return "xor"

    def extract_candidates(self, content: bytes, limit: int = 50) -> list[CandidateString]:
        out: list[CandidateString] = []

        for blob in re.split(rb"[\x00\r\n\t ]+", content):
            if len(blob) < 16 or len(blob) > 4096:
                continue
            entropy = self._entropy(blob)
            if not (4.5 <= entropy <= 7.5):
                continue

            keys = self._candidate_keys(blob)
            for key in keys:
                if len(out) >= limit:
                    return out
                decoded_bytes = bytes(b ^ key for b in blob)
                printable_ratio = self._printable_ratio(decoded_bytes)
                if printable_ratio < 0.8:
                    continue
                decoded = decoded_bytes.decode("utf-8", errors="ignore").strip()
                if not decoded:
                    continue

                confidence = 0.85 if _IOC_RE.search(decoded) else 0.6
                out.append(
                    CandidateString(
                        decoded=decoded,
                        encoding=self.name,
                        confidence=confidence,
                        provenance=Provenance(
                            offset=max(content.find(blob), 0),
                            length=len(blob),
                            raw_snippet=blob[:200].decode("latin-1", errors="ignore"),
                            decoder_chain=[self.name],
                        ),
                        tags=["url"] if "http" in decoded else [],
                    )
                )

        return out

    def _candidate_keys(self, blob: bytes) -> list[int]:
        common = list(range(0x00, 0x10)) + [0x20, 0x41, 0xFF]
        most_common = Counter(blob).most_common(1)[0][0]
        if most_common not in common:
            common.append(most_common)
        return common

    def _printable_ratio(self, data: bytes) -> float:
        printable = sum(32 <= b < 127 for b in data)
        return printable / max(len(data), 1)

    def _entropy(self, data: bytes) -> float:
        counts = Counter(data)
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())
```

Update `worker/src/malscan_worker/deobfuscation/decoders/__init__.py`:

```python
from malscan_worker.deobfuscation.decoders.xor_decoder import XorDecoder

__all__ = [
    "DecoderBase",
    "Base64Decoder",
    "HexDecoder",
    "JsDecoder",
    "PowerShellDecoder",
    "UrlReassemblyDecoder",
    "XorDecoder",
]
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cd worker && poetry run pytest tests/test_deobfuscation_engine.py::test_xor_decoder_recovers_url_from_single_byte_xor tests/test_deobfuscation_engine.py::test_xor_decoder_discards_non_printable_results -v`

Expected: `2 passed`

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/deobfuscation/decoders/__init__.py worker/src/malscan_worker/deobfuscation/decoders/xor_decoder.py worker/tests/test_deobfuscation_engine.py
git commit -m "feat: add single-byte xor decoder with entropy filtering"
```

---

## Task 5: Engine orchestration and IOC extraction (TDD)

**Files:**
- Create: `worker/src/malscan_worker/deobfuscation/engine.py`
- Modify: `worker/tests/test_deobfuscation_engine.py`

- [ ] **Step 1: Add failing tests for engine orchestration**

Append to `worker/tests/test_deobfuscation_engine.py`:

```python
from malscan_worker.deobfuscation.engine import DeobfuscationEngine
from malscan_worker.deobfuscation.safety import SafetyLimits


def test_engine_extracts_iocs_from_mixed_input():
    content = (
        b"payload aHR0cDovL2V2aWwuY29tL3BheWxvYWQuZXhl "
        b"powershell -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA=="
    )
    engine = DeobfuscationEngine(SafetyLimits(max_total_candidates=100))

    result = engine.process(content)

    assert result.stats.total_candidates >= 1
    assert "http://evil.com/payload.exe" in result.extracted_iocs.urls
    assert any("Invoke-Expression" in cmd for cmd in result.extracted_iocs.commands)


def test_engine_respects_global_candidate_cap():
    blob = b"aHR0cDovL2V2aWwuY29tL3BheWxvYWQuZXhl " * 20
    engine = DeobfuscationEngine(SafetyLimits(max_total_candidates=3, max_candidates_per_decoder=50))

    result = engine.process(blob)

    assert result.stats.total_candidates <= 3
    assert result.stats.truncated is True


def test_engine_applies_confidence_threshold():
    engine = DeobfuscationEngine(SafetyLimits(min_confidence_threshold=0.9))
    content = b"\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48"

    result = engine.process(content)

    assert all(c.confidence >= 0.9 for c in result.candidates)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd worker && poetry run pytest tests/test_deobfuscation_engine.py::test_engine_extracts_iocs_from_mixed_input tests/test_deobfuscation_engine.py::test_engine_respects_global_candidate_cap tests/test_deobfuscation_engine.py::test_engine_applies_confidence_threshold -v`

Expected: `ImportError` because `engine.py` does not exist.

- [ ] **Step 3: Implement deobfuscation engine**

Create `worker/src/malscan_worker/deobfuscation/engine.py`:

```python
"""Deobfuscation engine that orchestrates decoders and extracts IOCs."""

import re
import time

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.decoders.base64_decoder import Base64Decoder
from malscan_worker.deobfuscation.decoders.hex_decoder import HexDecoder
from malscan_worker.deobfuscation.decoders.js_decoder import JsDecoder
from malscan_worker.deobfuscation.decoders.powershell_decoder import PowerShellDecoder
from malscan_worker.deobfuscation.decoders.url_reassembly import UrlReassemblyDecoder
from malscan_worker.deobfuscation.decoders.xor_decoder import XorDecoder
from malscan_worker.deobfuscation.models import CandidateString, DeobfuscationResult, ExtractedIOCs, ResourceStats
from malscan_worker.deobfuscation.safety import SafetyGuard, SafetyLimits

_URL_RE = re.compile(r"https?://[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+[^\s\"'<>]*", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"(?<![a-zA-Z0-9.-])(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}(?![a-zA-Z0-9.-])", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
_CMD_PATTERNS = [
    re.compile(r"powershell", re.IGNORECASE),
    re.compile(r"cmd\.exe", re.IGNORECASE),
    re.compile(r"Invoke-Expression|IEX\s*\(", re.IGNORECASE),
    re.compile(r"DownloadString|DownloadFile|Net\.WebClient", re.IGNORECASE),
    re.compile(r"certutil|bitsadmin|mshta|regsvr32|rundll32", re.IGNORECASE),
]
_COMMON_DOMAINS = {"microsoft.com", "windows.com", "google.com", "example.com", "localhost", "w3.org"}


class DeobfuscationEngine:
    """Run all decoders once and aggregate candidates/IOCs."""

    def __init__(self, limits: SafetyLimits | None = None, decoders: list[DecoderBase] | None = None):
        self.limits = limits or SafetyLimits()
        self.decoders = decoders or [
            PowerShellDecoder(),
            Base64Decoder(),
            HexDecoder(),
            XorDecoder(),
            JsDecoder(),
            UrlReassemblyDecoder(),
        ]

    def process(self, content: bytes) -> DeobfuscationResult:
        guard = SafetyGuard(self.limits)
        start = time.monotonic()
        candidates: list[CandidateString] = []
        decoders_applied: list[str] = []

        for decoder in self.decoders:
            if guard.should_stop():
                break

            try:
                batch = decoder.extract_candidates(content, limit=self.limits.max_candidates_per_decoder)
            except Exception:
                decoders_applied.append(decoder.name)
                continue

            for candidate in batch:
                if guard.should_stop():
                    break
                if candidate.confidence < self.limits.min_confidence_threshold:
                    continue
                if guard.accept_candidate(candidate):
                    candidates.append(candidate)

            decoders_applied.append(decoder.name)

        iocs = self._extract_iocs(candidates)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        return DeobfuscationResult(
            candidates=candidates,
            extracted_iocs=iocs,
            stats=ResourceStats(
                decoders_applied=decoders_applied,
                total_candidates=len(candidates),
                total_decoded_bytes=guard.total_decoded_bytes,
                wall_time_ms=elapsed_ms,
                truncated=guard.truncated,
                truncation_reason=guard.truncation_reason,
            ),
        )

    def _extract_iocs(self, candidates: list[CandidateString]) -> ExtractedIOCs:
        urls: set[str] = set()
        domains: set[str] = set()
        ips: set[str] = set()
        commands: list[str] = []

        for candidate in candidates:
            decoded = candidate.decoded
            for m in _URL_RE.finditer(decoded):
                urls.add(m.group(0))
            for m in _DOMAIN_RE.finditer(decoded):
                d = m.group(0).lower()
                if d not in _COMMON_DOMAINS and len(d) >= 4:
                    domains.add(d)
            for m in _IP_RE.finditer(decoded):
                ips.add(m.group(0))
            if any(p.search(decoded) for p in _CMD_PATTERNS):
                commands.append(decoded[:1000])

        return ExtractedIOCs(
            urls=sorted(urls)[:100],
            domains=sorted(domains)[:100],
            ips=sorted(ips)[:50],
            commands=commands[:20],
        )
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cd worker && poetry run pytest tests/test_deobfuscation_engine.py -v`

Expected: All tests in `test_deobfuscation_engine.py` pass.

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/deobfuscation/engine.py worker/tests/test_deobfuscation_engine.py
git commit -m "feat: add deobfuscation engine orchestration and IOC extraction"
```

---

## Task 6: New pipeline stage wrapper (TDD)

**Files:**
- Create: `worker/src/malscan_worker/stages/deobfuscation.py`
- Create: `worker/tests/stages/test_deobfuscation.py`
- Modify: `worker/src/malscan_worker/stages/__init__.py`

- [ ] **Step 1: Write failing stage tests**

Create `worker/tests/stages/test_deobfuscation.py`:

```python
"""Tests for DeobfuscationStage."""

from types import SimpleNamespace

import pytest

from malscan_worker.stages.deobfuscation import DeobfuscationStage


def _settings(**overrides):
    base = {
        "deobfuscation_enabled": True,
        "deobfuscation_max_input_size": 10 * 1024 * 1024,
        "deobfuscation_max_candidates": 200,
        "deobfuscation_max_decoded_bytes": 5 * 1024 * 1024,
        "deobfuscation_timeout_ms": 10_000,
        "deobfuscation_min_confidence": 0.3,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.mark.asyncio
async def test_stage_skips_when_disabled(stage_context, mocker):
    mocker.patch("malscan_worker.stages.deobfuscation.get_settings", return_value=_settings(deobfuscation_enabled=False))
    stage = DeobfuscationStage()

    result = await stage.execute(stage_context)

    assert result.status == "skipped"
    assert "disabled" in result.findings["reason"].lower()


@pytest.mark.asyncio
async def test_stage_skips_when_file_too_large(stage_context, mocker):
    mocker.patch("malscan_worker.stages.deobfuscation.get_settings", return_value=_settings(deobfuscation_max_input_size=1))
    stage = DeobfuscationStage()

    result = await stage.execute(stage_context)

    assert result.status == "skipped"
    assert "too large" in result.findings["reason"].lower()


@pytest.mark.asyncio
async def test_stage_returns_candidates(stage_context, mocker):
    mocker.patch("malscan_worker.stages.deobfuscation.get_settings", return_value=_settings())
    stage_context.file_path.write_bytes(b"aHR0cDovL2V2aWwuY29tL3BheWxvYWQuZXhl")
    stage = DeobfuscationStage()

    result = await stage.execute(stage_context)

    assert result.status == "ok"
    assert result.stage_name == "deobfuscation"
    assert result.findings["candidates_found"] >= 1
    assert "extracted_iocs" in result.findings


@pytest.mark.asyncio
async def test_stage_handles_engine_exception(stage_context, mocker):
    mocker.patch("malscan_worker.stages.deobfuscation.get_settings", return_value=_settings())
    mocker.patch(
        "malscan_worker.stages.deobfuscation.DeobfuscationEngine.process",
        side_effect=RuntimeError("boom"),
    )
    stage = DeobfuscationStage()

    result = await stage.execute(stage_context)

    assert result.status == "failed"
    assert "boom" in (result.error or "")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd worker && poetry run pytest tests/stages/test_deobfuscation.py -v`

Expected: `ImportError` because `stages/deobfuscation.py` does not exist.

- [ ] **Step 3: Implement `DeobfuscationStage`**

Create `worker/src/malscan_worker/stages/deobfuscation.py`:

```python
"""Deobfuscation stage for recovering hidden strings and IOCs."""

import asyncio
from datetime import datetime, timezone

import structlog

from malscan_worker.config import get_settings
from malscan_worker.deobfuscation.engine import DeobfuscationEngine
from malscan_worker.deobfuscation.safety import SafetyLimits
from malscan_worker.stages.base import Stage, StageContext, StageResult

log = structlog.get_logger()


class DeobfuscationStage(Stage):
    @property
    def name(self) -> str:
        return "deobfuscation"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)
        settings = get_settings()

        if not settings.deobfuscation_enabled:
            return self._skip(started_at, "Deobfuscation disabled")

        if not ctx.file_path or not ctx.file_path.exists():
            return self._skip(started_at, "File not found")

        size = ctx.file_path.stat().st_size
        if size > settings.deobfuscation_max_input_size:
            return self._skip(started_at, f"File too large ({size} bytes)")

        try:
            content = ctx.file_path.read_bytes()
            limits = SafetyLimits(
                max_input_size=settings.deobfuscation_max_input_size,
                max_total_candidates=settings.deobfuscation_max_candidates,
                max_decoded_bytes_total=settings.deobfuscation_max_decoded_bytes,
                max_wall_time_ms=settings.deobfuscation_timeout_ms,
                min_confidence_threshold=settings.deobfuscation_min_confidence,
            )

            engine = DeobfuscationEngine(limits=limits)
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, engine.process, content)

            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)

            findings = {
                "candidates_found": len(result.candidates),
                "candidates": [
                    {
                        "decoded": c.decoded[:500],
                        "encoding": c.encoding,
                        "confidence": c.confidence,
                        "provenance": {
                            "offset": c.provenance.offset,
                            "length": c.provenance.length,
                            "raw_snippet": c.provenance.raw_snippet[:200],
                            "decoder_chain": c.provenance.decoder_chain,
                        },
                        "tags": c.tags,
                    }
                    for c in result.candidates
                ],
                "extracted_iocs": {
                    "urls": result.extracted_iocs.urls,
                    "domains": result.extracted_iocs.domains,
                    "ips": result.extracted_iocs.ips,
                    "commands": result.extracted_iocs.commands,
                },
                "has_suspicious_deobfuscated_content": bool(
                    result.extracted_iocs.urls
                    or result.extracted_iocs.domains
                    or result.extracted_iocs.ips
                    or result.extracted_iocs.commands
                ),
                "decoders_applied": result.stats.decoders_applied,
                "resource_stats": {
                    "total_candidates": result.stats.total_candidates,
                    "total_decoded_bytes": result.stats.total_decoded_bytes,
                    "wall_time_ms": result.stats.wall_time_ms,
                    "truncated": result.stats.truncated,
                    "truncation_reason": result.stats.truncation_reason,
                },
            }

            return StageResult(
                stage_name=self.name,
                status="ok",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                findings=findings,
                artifacts=[],
                error=None,
            )

        except Exception as exc:
            log.error("deobfuscation_error", job_id=ctx.job_id, error=str(exc), exc_info=True)
            ended_at = datetime.now(timezone.utc)
            return StageResult(
                stage_name=self.name,
                status="failed",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=int((ended_at - started_at).total_seconds() * 1000),
                findings={},
                artifacts=[],
                error=str(exc),
            )

    def _skip(self, started_at: datetime, reason: str) -> StageResult:
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status="skipped",
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings={"reason": reason},
            artifacts=[],
            error=None,
        )
```

- [ ] **Step 4: Export stage class from stage package**

Modify `worker/src/malscan_worker/stages/__init__.py`:

```python
from malscan_worker.stages.deobfuscation import DeobfuscationStage

__all__ = [
    "ArchiveExtractStage",
    "ClamAVStage",
    "DeobfuscationStage",
    "DocumentAnalysisStage",
    "FileTypeStage",
    "IocExtractStage",
    "SandboxStage",
    "YaraStage",
]
```

- [ ] **Step 5: Run tests to verify pass**

Run: `cd worker && poetry run pytest tests/stages/test_deobfuscation.py -v`

Expected: `4 passed`

- [ ] **Step 6: Commit**

```bash
git add worker/src/malscan_worker/stages/deobfuscation.py worker/src/malscan_worker/stages/__init__.py worker/tests/stages/test_deobfuscation.py
git commit -m "feat: add deobfuscation pipeline stage"
```

---

## Task 7: Pipeline, config, and metrics integration (TDD)

**Files:**
- Modify: `worker/src/malscan_worker/pipeline.py`
- Modify: `worker/src/malscan_worker/config.py`
- Modify: `worker/src/malscan_worker/metrics.py`
- Modify: `worker/src/malscan_worker/stages/deobfuscation.py`
- Create: `worker/tests/test_deobfuscation_pipeline_integration.py`

- [ ] **Step 1: Write failing integration tests for merge + scoring**

Create `worker/tests/test_deobfuscation_pipeline_integration.py`:

```python
"""Pipeline integration tests for deobfuscation result merge and scoring."""

from datetime import datetime, timezone

from malscan_worker.pipeline import _build_analysis_result
from malscan_worker.stages.base import StageContext, StageResult


def _result(name: str, findings: dict) -> StageResult:
    now = datetime.now(timezone.utc)
    return StageResult(
        stage_name=name,
        status="ok",
        started_at=now,
        ended_at=now,
        duration_ms=1,
        findings=findings,
        artifacts=[],
        error=None,
    )


def _ctx() -> StageContext:
    return StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="sha",
        sha256="sha",
        original_filename="sample.bin",
        file_path=None,
    )


def test_build_analysis_result_merges_deobfuscated_iocs_and_report_section():
    results = [
        _result("file-type", {"mime_type": "application/octet-stream", "file_size": 10}),
        _result("clamav", {"infected": False, "threat_name": None}),
        _result("yara", {"matches": []}),
        _result("ioc-extract", {"urls": ["http://a.com"], "domains": ["a.com"], "ips": ["1.2.3.4"]}),
        _result(
            "deobfuscation",
            {
                "candidates_found": 2,
                "candidates": [
                    {"decoded": "http://evil.com", "confidence": 0.95, "tags": ["url"]},
                    {"decoded": "Invoke-Expression", "confidence": 0.95, "tags": ["command", "powershell"]},
                ],
                "extracted_iocs": {
                    "urls": ["http://evil.com", "http://a.com"],
                    "domains": ["evil.com"],
                    "ips": ["8.8.8.8"],
                    "commands": ["Invoke-Expression"],
                },
                "decoders_applied": ["base64", "powershell"],
                "resource_stats": {"truncated": False},
                "has_suspicious_deobfuscated_content": True,
            },
        ),
    ]

    report = _build_analysis_result("job-1", "file-1", _ctx(), results, 50)

    assert "http://evil.com" in report["results"]["iocs"]["urls"]
    assert "evil.com" in report["results"]["iocs"]["domains"]
    assert "8.8.8.8" in report["results"]["iocs"]["ips"]
    assert "deobfuscation" in report["results"]
    assert report["verdict"] == "suspicious"


def test_deobfuscation_score_boost_capped_at_25():
    high_conf_candidates = [
        {"decoded": f"http://x{i}.evil.com", "confidence": 0.9, "tags": ["url"]}
        for i in range(20)
    ]
    results = [
        _result("file-type", {"mime_type": "application/octet-stream", "file_size": 10}),
        _result("clamav", {"infected": False, "threat_name": None}),
        _result("yara", {"matches": []}),
        _result("ioc-extract", {"urls": [], "domains": [], "ips": []}),
        _result(
            "deobfuscation",
            {
                "candidates_found": len(high_conf_candidates),
                "candidates": high_conf_candidates,
                "extracted_iocs": {"urls": [], "domains": [], "ips": [], "commands": []},
                "has_suspicious_deobfuscated_content": True,
            },
        ),
    ]

    report = _build_analysis_result("job-1", "file-1", _ctx(), results, 10)

    assert report["score"] == 25
    assert report["verdict"] == "suspicious"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd worker && poetry run pytest tests/test_deobfuscation_pipeline_integration.py -v`

Expected: failures because `pipeline.py` has not integrated deobfuscation merge/scoring yet.

- [ ] **Step 3: Integrate deobfuscation into pipeline and scoring**

Modify `worker/src/malscan_worker/pipeline.py`:

```python
from malscan_worker.stages.deobfuscation import DeobfuscationStage

PARALLEL_STAGES = [
    FileTypeStage(),
    ClamAVStage(),
    YaraStage(),
    IocExtractStage(),
    DeobfuscationStage(),
]

# Build IOC info
ioc_findings = stage_findings.get("ioc-extract", {})
iocs = {
    "urls": ioc_findings.get("urls", []),
    "domains": ioc_findings.get("domains", []),
    "ips": ioc_findings.get("ips", ioc_findings.get("ip_addresses", [])),
    "hashes": {
        "md5": ioc_findings.get("md5", ""),
        "sha1": ioc_findings.get("sha1", ""),
        "sha256": ctx.sha256,
    },
}

# Merge deobfuscated IOCs
deobfus = stage_findings.get("deobfuscation", {})
deobfus_iocs = deobfus.get("extracted_iocs", {})

merged_urls = set(iocs["urls"]) | set(deobfus_iocs.get("urls", []))
merged_domains = set(iocs["domains"]) | set(deobfus_iocs.get("domains", []))
merged_ips = set(iocs["ips"]) | set(deobfus_iocs.get("ips", []))

iocs["urls"] = sorted(merged_urls)[:200]
iocs["domains"] = sorted(merged_domains)[:200]
iocs["ips"] = sorted(merged_ips)[:100]

# Additive risk boost (cap 25)
if deobfus.get("has_suspicious_deobfuscated_content"):
    high_conf_count = sum(1 for c in deobfus.get("candidates", []) if c.get("confidence", 0) >= 0.7)
    boost = 10 + min(high_conf_count * 5, 15)
    boost = min(boost, 25)
    score = min(score + boost, 100)
    if verdict == "clean":
        verdict = "suspicious"

# In return payload
"deobfuscation": {
    "candidates_found": deobfus.get("candidates_found", 0),
    "candidates": deobfus.get("candidates", [])[:50],
    "decoders_applied": deobfus.get("decoders_applied", []),
    "resource_stats": deobfus.get("resource_stats", {}),
    "extracted_iocs": deobfus_iocs,
},
```

- [ ] **Step 4: Add config fields and metrics counters**

Modify `worker/src/malscan_worker/config.py`:

```python
# Stage configuration
stage_timeout_seconds: int = 300
stages_total: int = 6

# Deobfuscation
deobfuscation_enabled: bool = True
deobfuscation_max_input_size: int = 10 * 1024 * 1024
deobfuscation_max_candidates: int = 200
deobfuscation_max_decoded_bytes: int = 5 * 1024 * 1024
deobfuscation_timeout_ms: int = 10_000
deobfuscation_min_confidence: float = 0.3
```

Modify `worker/src/malscan_worker/metrics.py`:

```python
deobfus_candidates_total = Counter(
    "malscan_deobfus_candidates_total",
    "Total deobfuscation candidates by decoder",
    ["decoder"],
)

deobfus_iocs_extracted_total = Counter(
    "malscan_deobfus_iocs_extracted_total",
    "Total IOCs extracted from deobfuscation",
    ["type"],
)

deobfus_truncated_total = Counter(
    "malscan_deobfus_truncated_total",
    "Total times deobfuscation safety limits triggered",
)
```

Modify `worker/src/malscan_worker/stages/deobfuscation.py` to emit metrics after successful engine run:

```python
from malscan_worker.metrics import (
    deobfus_candidates_total,
    deobfus_iocs_extracted_total,
    deobfus_truncated_total,
)

for c in result.candidates:
    deobfus_candidates_total.labels(decoder=c.encoding).inc()
for _ in result.extracted_iocs.urls:
    deobfus_iocs_extracted_total.labels(type="url").inc()
for _ in result.extracted_iocs.domains:
    deobfus_iocs_extracted_total.labels(type="domain").inc()
for _ in result.extracted_iocs.ips:
    deobfus_iocs_extracted_total.labels(type="ip").inc()
for _ in result.extracted_iocs.commands:
    deobfus_iocs_extracted_total.labels(type="command").inc()
if result.stats.truncated:
    deobfus_truncated_total.inc()
```

- [ ] **Step 5: Run tests to verify pass**

Run: `cd worker && poetry run pytest tests/test_deobfuscation_pipeline_integration.py tests/stages/test_deobfuscation.py -v`

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add worker/src/malscan_worker/pipeline.py worker/src/malscan_worker/config.py worker/src/malscan_worker/metrics.py worker/src/malscan_worker/stages/deobfuscation.py worker/tests/test_deobfuscation_pipeline_integration.py
git commit -m "feat: integrate deobfuscation into pipeline scoring config and metrics"
```

---

## Task 8: Recall improvement fixtures and regression test (TDD)

**Files:**
- Create: `worker/tests/fixtures/deobfuscation/base64_url.bin`
- Create: `worker/tests/fixtures/deobfuscation/base64_url.bin.expected.json`
- Create: `worker/tests/fixtures/deobfuscation/ps_enc_command.ps1`
- Create: `worker/tests/fixtures/deobfuscation/ps_enc_command.ps1.expected.json`
- Create: `worker/tests/fixtures/deobfuscation/js_fromcharcode.js`
- Create: `worker/tests/fixtures/deobfuscation/js_fromcharcode.js.expected.json`
- Create: `worker/tests/fixtures/deobfuscation/clean_no_obfuscation.txt`
- Create: `worker/tests/fixtures/deobfuscation/clean_no_obfuscation.txt.expected.json`
- Create: `worker/tests/test_recall_improvement.py`

- [ ] **Step 1: Create fixture corpus and expected outputs**

Create `worker/tests/fixtures/deobfuscation/base64_url.bin`:

```text
blob=aHR0cDovL2V2aWwuY29tL3BheWxvYWQuZXhl
```

Create `worker/tests/fixtures/deobfuscation/base64_url.bin.expected.json`:

```json
{
  "expected_iocs": {
    "urls": ["http://evil.com/payload.exe"],
    "domains": ["evil.com"],
    "ips": [],
    "commands": []
  },
  "obfuscation_type": "base64"
}
```

Create `worker/tests/fixtures/deobfuscation/ps_enc_command.ps1`:

```text
powershell -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==
```

Create `worker/tests/fixtures/deobfuscation/ps_enc_command.ps1.expected.json`:

```json
{
  "expected_iocs": {
    "urls": [],
    "domains": [],
    "ips": [],
    "commands": ["Invoke-Expression"]
  },
  "obfuscation_type": "powershell-enc"
}
```

Create `worker/tests/fixtures/deobfuscation/js_fromcharcode.js`:

```text
var u = String.fromCharCode(104,116,116,112,58,47,47,101,118,105,108,46,99,111,109);
```

Create `worker/tests/fixtures/deobfuscation/js_fromcharcode.js.expected.json`:

```json
{
  "expected_iocs": {
    "urls": ["http://evil.com"],
    "domains": ["evil.com"],
    "ips": [],
    "commands": []
  },
  "obfuscation_type": "js-fromcharcode"
}
```

Create `worker/tests/fixtures/deobfuscation/clean_no_obfuscation.txt`:

```text
This is a clean sample with no obfuscated IOC.
```

Create `worker/tests/fixtures/deobfuscation/clean_no_obfuscation.txt.expected.json`:

```json
{
  "expected_iocs": {
    "urls": [],
    "domains": [],
    "ips": [],
    "commands": []
  },
  "obfuscation_type": "none"
}
```

- [ ] **Step 2: Write failing recall regression test**

Create `worker/tests/test_recall_improvement.py`:

```python
"""Regression test that verifies recall improvement with deobfuscation."""

import json
import re
from pathlib import Path

from malscan_worker.deobfuscation.engine import DeobfuscationEngine
from malscan_worker.deobfuscation.safety import SafetyLimits

FIXTURES = Path(__file__).parent / "fixtures" / "deobfuscation"

URL_PATTERN = re.compile(
    rb'https?://[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+[^\s\x00-\x1f"\'<>]*',
    re.IGNORECASE,
)
DOMAIN_PATTERN = re.compile(
    rb"(?<![a-zA-Z0-9.-])(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}(?![a-zA-Z0-9.-])",
    re.IGNORECASE,
)
IP_PATTERN = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


def _raw_extract(content: bytes) -> set[str]:
    urls = {m.decode("utf-8", errors="ignore") for m in URL_PATTERN.findall(content)}
    domains = {m.decode("utf-8", errors="ignore") for m in DOMAIN_PATTERN.findall(content)}
    ips = {m.decode("utf-8", errors="ignore") for m in IP_PATTERN.findall(content)}
    return urls | domains | ips


def _deobfus_extract(content: bytes) -> set[str]:
    engine = DeobfuscationEngine(
        SafetyLimits(max_total_candidates=200, min_confidence_threshold=0.3)
    )
    result = engine.process(content)
    return set(result.extracted_iocs.urls) | set(result.extracted_iocs.domains) | set(result.extracted_iocs.ips)


def test_recall_improves_with_deobfuscation():
    total_expected = 0
    found_raw = 0
    found_with_deobfus = 0

    for expected_path in FIXTURES.glob("*.expected.json"):
        expected = json.loads(expected_path.read_text())
        sample_path = FIXTURES / expected_path.name.replace(".expected.json", "")
        content = sample_path.read_bytes()

        expected_iocs = set(
            expected["expected_iocs"]["urls"]
            + expected["expected_iocs"]["domains"]
            + expected["expected_iocs"]["ips"]
        )

        total_expected += len(expected_iocs)
        raw = _raw_extract(content)
        found_raw += len(expected_iocs & raw)

        combined = raw | _deobfus_extract(content)
        found_with_deobfus += len(expected_iocs & combined)

    recall_before = found_raw / total_expected if total_expected else 0.0
    recall_after = found_with_deobfus / total_expected if total_expected else 0.0

    assert recall_after > recall_before, (
        f"Expected recall increase, got {recall_before:.2%} -> {recall_after:.2%}"
    )
    assert recall_after >= 0.7
```

- [ ] **Step 3: Run test to verify behavior**

Run: `cd worker && poetry run pytest tests/test_recall_improvement.py -v`

Expected: test passes and shows recall increase.

- [ ] **Step 4: Commit**

```bash
git add worker/tests/fixtures/deobfuscation worker/tests/test_recall_improvement.py
git commit -m "test: add deobfuscation recall regression fixtures and assertions"
```

---

## Task 9: Documentation update and full verification

**Files:**
- Modify: `worker/README.md`

- [ ] **Step 1: Update worker stage documentation**

Modify `worker/README.md` stage section:

```markdown
# MalScan Worker

Malware analysis worker with 8-stage pipeline.

## Stages

Parallel static analysis stages:

1. **file-type** - File type detection using python-magic
2. **clamav** - ClamAV scanning
3. **yara** - YARA rule matching
4. **ioc-extract** - IOC extraction from raw bytes
5. **deobfuscation** - Single-layer string deobfuscation and hidden IOC extraction

Sequential analysis stages:

6. **archive-extract** - Archive unpacking and sub-job submission
7. **document-analysis** - Format-specific document exploit/macro analysis
8. **sandbox** - Sandbox analysis (mock in MVP)
```

- [ ] **Step 2: Run targeted feature test suite**

Run: `cd worker && poetry run pytest tests/test_deobfuscation_engine.py tests/stages/test_deobfuscation.py tests/test_deobfuscation_pipeline_integration.py tests/test_recall_improvement.py -v`

Expected: all selected tests pass.

- [ ] **Step 3: Run broader regression checks**

Run: `cd worker && poetry run pytest -q`

Expected: full suite passes.

Run: `cd worker && poetry run ruff check src tests`

Expected: no lint errors.

- [ ] **Step 4: Commit final integration/docs updates**

```bash
git add worker/README.md
git commit -m "docs: document deobfuscation stage and updated pipeline stages"
```

---

## Spec Coverage Checklist (Self-Review)

1. **Approach A (independent parallel stage):** Covered by Task 6 + Task 7 (`PARALLEL_STAGES` integration).
2. **Single-layer decoding only:** Covered by Tasks 2-5 decoder design (no recursive chaining in engine).
3. **Six decoders required:** Covered by Tasks 2-4 (`base64`, `hex`, `xor`, `powershell`, `js`, `url_reassembly`).
4. **IOC/report/scoring integration:** Covered by Task 7.
5. **Resource protections + FP controls:** Covered by Task 1 (`SafetyGuard`) and Task 5 threshold gating.
6. **Metrics and observability:** Covered by Task 7 metrics counters.
7. **Test plan including recall improvement:** Covered by Tasks 1-5, 7, and 8.

## Placeholder Scan (Self-Review)

- No `TODO`, `TBD`, or deferred implementation markers.
- Every code-change step includes explicit code blocks.
- Every test step includes exact command and expected outcome.

## Type/Interface Consistency (Self-Review)

- `DecoderBase.extract_candidates(content: bytes, limit: int) -> list[CandidateString]` is used consistently in decoders and engine.
- `DeobfuscationEngine.process(content: bytes) -> DeobfuscationResult` is used consistently by stage/tests.
- `StageResult.findings["extracted_iocs"]` keys are consistently `urls/domains/ips/commands` across stage/pipeline/tests.
