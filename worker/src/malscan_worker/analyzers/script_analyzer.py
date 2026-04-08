"""Script analyzer for common Windows script formats."""

from __future__ import annotations

import asyncio
import math
import re
from pathlib import Path
from typing import TYPE_CHECKING, Pattern

from malscan_worker.analyzers.base import (
    AnalyzerIndicator,
    AnalyzerResult,
    FormatAnalyzer,
    JsonValue,
)

if TYPE_CHECKING:
    from malscan_worker.stages.base import StageContext


_MAX_ANALYSIS_BYTES = 1024 * 1024
_PRINTABLE_THRESHOLD = 0.85
_UTF16_BOM_LE = b"\xff\xfe"
_UTF16_BOM_BE = b"\xfe\xff"

_SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}

_SCRIPT_EXTENSIONS = {
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    ".js": "javascript",
    ".jse": "javascript",
    ".vbs": "vbscript",
    ".vbe": "vbscript",
    ".bat": "batch",
    ".cmd": "batch",
    ".hta": "hta",
}

_SCRIPT_MIME_HINTS = {
    "application/x-powershell",
    "application/powershell",
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "text/vbscript",
    "application/vbscript",
    "application/x-msdos-program",
    "application/hta",
    "application/x-hta",
}

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
_HEX_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}){16,}\b")

_PS_HINTS = (
    "powershell",
    "invoke-expression",
    "new-object",
    "write-host",
    "frombase64string",
    "$env:",
)
_JS_HINTS = (
    "function ",
    "var ",
    "const ",
    "let ",
    "activexobject",
    "wscript.",
    "fromcharcode",
)
_VBS_HINTS = (
    "createobject(",
    "wscript.",
    "dim ",
    "end sub",
    "end function",
)
_BATCH_HINTS = (
    "@echo off",
    "set ",
    "if ",
    "goto ",
    "%~",
    "cmd /c",
)
_HTA_HINTS = (
    "<hta:application",
    "<script",
    "vbscript",
    "javascript",
    "</html>",
)

_DOWNLOAD_PATTERNS: list[tuple[str, Pattern[str]]] = [
    ("invoke_webrequest", re.compile(r"\binvoke-webrequest\b|\biwr\b", re.IGNORECASE)),
    ("webclient_download", re.compile(r"download(string|file)", re.IGNORECASE)),
    ("bitsadmin", re.compile(r"\bbitsadmin\b", re.IGNORECASE)),
    ("certutil_download", re.compile(r"\bcertutil\b[^\n]*\b(urlcache|split)\b", re.IGNORECASE)),
    ("curl_or_wget", re.compile(r"\b(curl|wget)\b", re.IGNORECASE)),
]

_EXEC_PATTERNS: list[tuple[str, Pattern[str]]] = [
    ("invoke_expression", re.compile(r"\b(invoke-expression|iex)\b", re.IGNORECASE)),
    ("start_process", re.compile(r"\bstart-process\b", re.IGNORECASE)),
    ("script_host", re.compile(r"\b(wscript|cscript|mshta)\.exe\b|\bmshta\b", re.IGNORECASE)),
    ("cmd_exec", re.compile(r"\bcmd(?:\.exe)?\s+/c\b", re.IGNORECASE)),
    (
        "rundll32_or_regsvr32",
        re.compile(r"\b(rundll32|regsvr32)\.exe\b|\b(rundll32|regsvr32)\b", re.IGNORECASE),
    ),
]

_PROCESS_PATTERNS: list[tuple[str, Pattern[str]]] = [
    (
        "create_process",
        re.compile(r"\b(CreateProcess|Start-Process|Win32_Process)\b", re.IGNORECASE),
    ),
    (
        "process_injection_api",
        re.compile(
            r"\b(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtQueueApcThread|SetThreadContext)\b",
            re.IGNORECASE,
        ),
    ),
]

_REGISTRY_PATTERNS: list[tuple[str, Pattern[str]]] = [
    (
        "registry_modify",
        re.compile(
            r"\b(reg\s+add|set-itemproperty|new-itemproperty|remove-itemproperty)\b", re.IGNORECASE
        ),
    ),
    (
        "autorun_key",
        re.compile(
            r"(hkcu|hklm|hkcr|hku)\\[^\n]*\\(run|runonce|runservices|shell\\open\\command)",
            re.IGNORECASE,
        ),
    ),
]

_FILE_PATTERNS: list[tuple[str, Pattern[str]]] = [
    (
        "file_write_or_copy",
        re.compile(
            r"\b(copy-item|move-item|remove-item|new-item|set-content|out-file|xcopy|copy|move|del)\b",
            re.IGNORECASE,
        ),
    ),
    ("archive_expand", re.compile(r"\b(expand-archive|expand\s+)\b", re.IGNORECASE)),
]

_NETWORK_PATTERNS: list[tuple[str, Pattern[str]]] = [
    ("http_url", _URL_RE),
    ("dns_lookup", re.compile(r"\b(nslookup|resolve-dnsname)\b", re.IGNORECASE)),
    (
        "web_request",
        re.compile(r"\b(invoke-webrequest|invoke-restmethod|webclient)\b", re.IGNORECASE),
    ),
]


class ScriptAnalyzer(FormatAnalyzer):
    """Analyze script-like text files for suspicious behaviors."""

    @property
    def name(self) -> str:
        return "script"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        mime_l = mime.lower().strip()
        extension = file_path.suffix.lower()

        likely_script = False

        if extension in _SCRIPT_EXTENSIONS:
            likely_script = True
        elif mime_l in _SCRIPT_MIME_HINTS:
            likely_script = True

        # Content-sniff fallback for script text in generic containers.
        prefix = magic
        if len(prefix) < 512:
            try:
                with file_path.open("rb") as handle:
                    prefix = handle.read(4096)
            except OSError:
                return False

        decoded = self._decode_text(prefix)
        if decoded is None:
            return False

        if not likely_script:
            likely_script = self._looks_like_script(decoded)

        if not likely_script:
            return False

        if self._printable_ratio(decoded) < _PRINTABLE_THRESHOLD:
            return False

        return True

    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        del ctx
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._analyze_sync, file_path)

    def _analyze_sync(self, file_path: Path) -> AnalyzerResult:
        result = AnalyzerResult(analyzer_name=self.name, format_type="SCRIPT")

        try:
            with file_path.open("rb") as handle:
                raw = handle.read(_MAX_ANALYSIS_BYTES)
        except OSError as exc:
            result.errors.append(f"failed to read script file: {exc}")
            result.features = self._empty_features("unknown", 0)
            return result

        decoded = self._decode_text(raw)
        if decoded is None:
            result.errors.append("script analysis skipped: file is not decodable text")
            result.features = self._empty_features("unknown", 0)
            return result

        printable_ratio = self._printable_ratio(decoded)
        if printable_ratio < _PRINTABLE_THRESHOLD:
            result.errors.append("script analysis skipped: file appears to be binary")
            result.features = self._empty_features("unknown", 0)
            return result

        script_type = self._detect_script_type(file_path, decoded)
        lines = decoded.splitlines()
        line_count = len(lines)

        encoded_strings = self._detect_encoded_strings(decoded)
        network_indicators = self._collect_operation_hits(decoded, _NETWORK_PATTERNS)
        process_operations = self._collect_operation_hits(decoded, _PROCESS_PATTERNS)
        registry_operations = self._collect_operation_hits(decoded, _REGISTRY_PATTERNS)
        file_operations = self._collect_operation_hits(decoded, _FILE_PATTERNS)
        download_operations = self._collect_operation_hits(decoded, _DOWNLOAD_PATTERNS)
        exec_operations = self._collect_operation_hits(decoded, _EXEC_PATTERNS)
        obfuscation_score = self._calculate_obfuscation_score(decoded, encoded_strings)

        features: dict[str, JsonValue] = {
            "script_type": script_type,
            "line_count": line_count,
            "obfuscation_score": obfuscation_score,
            "encoded_strings": self._as_json_list(encoded_strings),
            "network_indicators": self._as_json_list(network_indicators),
            "process_operations": self._as_json_list(process_operations),
            "registry_operations": self._as_json_list(registry_operations),
            "file_operations": self._as_json_list(file_operations),
            "download_operations": self._as_json_list(download_operations),
            "exec_operations": self._as_json_list(exec_operations),
        }

        indicators = self._build_indicators(
            decoded,
            download_operations=download_operations,
            exec_operations=exec_operations,
            process_operations=process_operations,
            registry_operations=registry_operations,
            obfuscation_score=obfuscation_score,
            encoded_strings=encoded_strings,
        )

        result.features = features
        result.indicators = indicators
        result.risk_score = self._calculate_risk_score(indicators)
        result.risk_factors = [str(item.get("type", "")) for item in indicators]
        result.extracted_strings = encoded_strings
        return result

    @staticmethod
    def _empty_features(script_type: str, line_count: int) -> dict[str, JsonValue]:
        return {
            "script_type": script_type,
            "line_count": line_count,
            "obfuscation_score": 0,
            "encoded_strings": ScriptAnalyzer._as_json_list([]),
            "network_indicators": ScriptAnalyzer._as_json_list([]),
            "process_operations": ScriptAnalyzer._as_json_list([]),
            "registry_operations": ScriptAnalyzer._as_json_list([]),
            "file_operations": ScriptAnalyzer._as_json_list([]),
            "download_operations": ScriptAnalyzer._as_json_list([]),
            "exec_operations": ScriptAnalyzer._as_json_list([]),
        }

    @staticmethod
    def _decode_text(raw: bytes) -> str | None:
        if not raw:
            return ""

        if raw.startswith(_UTF16_BOM_LE) or raw.startswith(_UTF16_BOM_BE):
            try:
                return raw.decode("utf-16")
            except UnicodeDecodeError:
                return None

        likely_utf16 = ScriptAnalyzer._sniff_utf16_encoding(raw)
        if likely_utf16 is not None:
            try:
                return raw.decode(likely_utf16)
            except UnicodeDecodeError:
                return None

        for encoding in ("utf-8", "latin-1"):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        return None

    @staticmethod
    def _sniff_utf16_encoding(raw: bytes) -> str | None:
        sample = raw[:512]
        if len(sample) < 4:
            return None

        even_nuls = sum(1 for idx in range(0, len(sample), 2) if sample[idx] == 0)
        odd_nuls = sum(1 for idx in range(1, len(sample), 2) if sample[idx] == 0)
        half = len(sample) // 2
        if half == 0:
            return None

        # Typical ASCII-heavy UTF-16 text has nuls in one lane.
        if odd_nuls / half >= 0.3 and even_nuls / half <= 0.05:
            return "utf-16le"
        if even_nuls / half >= 0.3 and odd_nuls / half <= 0.05:
            return "utf-16be"
        return None

    @staticmethod
    def _printable_ratio(text: str) -> float:
        if not text:
            return 0.0
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
        return printable / len(text)

    def _looks_like_script(self, text: str) -> bool:
        text_l = text.lower()
        groups = (_PS_HINTS, _JS_HINTS, _VBS_HINTS, _BATCH_HINTS, _HTA_HINTS)
        hit_groups = 0
        for hint_group in groups:
            if any(hint in text_l for hint in hint_group):
                hit_groups += 1
        if hit_groups > 0:
            return True
        # Generic command syntax sniffing fallback.
        return bool(re.search(r"\b(set\s+\w+=|if\s+\(|for\s+\(|function\s+\w+)\b", text_l))

    def _detect_script_type(self, file_path: Path, text: str) -> str:
        extension = file_path.suffix.lower()
        if extension in _SCRIPT_EXTENSIONS:
            return _SCRIPT_EXTENSIONS[extension]

        text_l = text.lower()
        if "<hta:application" in text_l or ("<script" in text_l and "</html>" in text_l):
            return "hta"

        scores = {
            "powershell": sum(1 for token in _PS_HINTS if token in text_l),
            "javascript": sum(1 for token in _JS_HINTS if token in text_l),
            "vbscript": sum(1 for token in _VBS_HINTS if token in text_l),
            "batch": sum(1 for token in _BATCH_HINTS if token in text_l),
        }
        script_type = max(scores, key=lambda key: scores[key])
        return script_type if scores[script_type] > 0 else "unknown"

    def _detect_encoded_strings(self, text: str) -> list[str]:
        candidates: set[str] = set()
        for match in _BASE64_RE.findall(text):
            candidates.add(match[:120])
        for match in _HEX_RE.findall(text):
            candidates.add(match[:120])
        for marker in (
            "frombase64string",
            "string.fromcharcode",
            "[convert]::frombase64string",
            "decodebase64",
            "charcodeat",
        ):
            if marker in text.lower():
                candidates.add(marker)
        return sorted(candidates)[:25]

    def _collect_operation_hits(
        self,
        text: str,
        patterns: list[tuple[str, Pattern[str]]],
    ) -> list[str]:
        hits: list[str] = []
        for label, pattern in patterns:
            if pattern.search(text):
                hits.append(label)
        return sorted(set(hits))

    def _build_indicators(
        self,
        text: str,
        *,
        download_operations: list[str],
        exec_operations: list[str],
        process_operations: list[str],
        registry_operations: list[str],
        obfuscation_score: int,
        encoded_strings: list[str],
    ) -> list[AnalyzerIndicator]:
        indicators: list[AnalyzerIndicator] = []
        text_l = text.lower()

        if download_operations and exec_operations:
            indicators.append(
                {
                    "type": "download_and_execute",
                    "severity": "critical",
                    "detail": "Downloader and execution primitives detected together",
                    "evidence": {
                        "download_operations": self._as_json_list(download_operations),
                        "exec_operations": self._as_json_list(exec_operations),
                    },
                }
            )

        if encoded_strings and exec_operations:
            indicators.append(
                {
                    "type": "encoded_command_execution",
                    "severity": "critical",
                    "detail": "Encoded content with execution behavior detected",
                    "evidence": {
                        "encoded_strings": self._as_json_list(encoded_strings[:5]),
                        "exec_operations": self._as_json_list(exec_operations),
                    },
                }
            )

        if "process_injection_api" in process_operations:
            indicators.append(
                {
                    "type": "process_injection",
                    "severity": "critical",
                    "detail": "Process injection API usage detected",
                    "evidence": self._as_json_list(process_operations),
                }
            )

        if "autorun_key" in registry_operations:
            indicators.append(
                {
                    "type": "registry_persistence",
                    "severity": "high",
                    "detail": "Autorun-related registry path modifications detected",
                    "evidence": self._as_json_list(registry_operations),
                }
            )

        if re.search(r"\b(schtasks\s+/create|register-scheduledtask)\b", text_l):
            indicators.append(
                {
                    "type": "scheduled_task",
                    "severity": "high",
                    "detail": "Scheduled task creation behavior detected",
                }
            )

        if re.search(r"\b(sc\s+create|new-service)\b", text_l):
            indicators.append(
                {
                    "type": "service_creation",
                    "severity": "high",
                    "detail": "Windows service creation behavior detected",
                }
            )

        if re.search(
            r"(amsiutils|amsiinitfailed|system\.management\.automation\.amsi|bypass\s+amsi)",
            text_l,
        ):
            indicators.append(
                {
                    "type": "amsi_bypass",
                    "severity": "high",
                    "detail": "AMSI bypass pattern detected",
                }
            )

        if re.search(
            r"(executionpolicy\s+bypass|-ep\s+bypass|set-executionpolicy\s+bypass)", text_l
        ):
            indicators.append(
                {
                    "type": "execution_policy_bypass",
                    "severity": "medium",
                    "detail": "Execution policy bypass pattern detected",
                }
            )

        if obfuscation_score >= 70:
            indicators.append(
                {
                    "type": "heavy_obfuscation",
                    "severity": "medium",
                    "detail": "Strong obfuscation traits detected",
                    "evidence": {"obfuscation_score": obfuscation_score},
                }
            )

        if re.search(
            r"\b(invoke-wmimethod|wmic\s+process\s+call\s+create|get-wmiobject)\b", text_l
        ):
            indicators.append(
                {
                    "type": "wmi_execution",
                    "severity": "medium",
                    "detail": "WMI-based execution behavior detected",
                }
            )

        if re.search(
            r"\b(whoami|hostname|systeminfo|ipconfig|net\s+user|query\s+user|get-childitem\s+env:)\b",
            text_l,
        ):
            indicators.append(
                {
                    "type": "environment_discovery",
                    "severity": "low",
                    "detail": "Environment discovery behavior detected",
                }
            )

        if re.search(r"\b(start-sleep|sleep\s+\d+|timeout\s+/t|ping\s+-n\s+\d+)\b", text_l):
            indicators.append(
                {
                    "type": "sleep_or_delay",
                    "severity": "low",
                    "detail": "Sleep/delay behavior detected",
                }
            )

        return indicators

    def _calculate_obfuscation_score(self, text: str, encoded_strings: list[str]) -> int:
        text_sample = text[:100_000]
        text_l = text_sample.lower()

        score = 0

        # Encoded payload density.
        score += min(len(encoded_strings) * 8, 30)

        # Shannon entropy (high entropy can hint at encoded/compressed blobs).
        entropy = self._estimate_entropy(text_sample)
        if entropy >= 5.2:
            score += 18
        elif entropy >= 4.6:
            score += 10

        # Obfuscation syntax cues.
        obf_markers = (
            "frombase64string",
            "string.fromcharcode",
            "-join",
            "^",
            "`",
            "xor",
            "replace(",
            "[char]",
        )
        marker_hits = sum(1 for marker in obf_markers if marker in text_l)
        score += min(marker_hits * 6, 24)

        # Long-line packing cue.
        lines = text_sample.splitlines()
        if lines:
            max_line = max(len(line) for line in lines)
            if max_line >= 500:
                score += 14
            elif max_line >= 250:
                score += 8

        # Symbol density cue.
        symbol_chars = sum(1 for ch in text_sample if ch in "^`'\"+%$()[]{};,:|&")
        if text_sample:
            symbol_ratio = symbol_chars / len(text_sample)
            if symbol_ratio >= 0.24:
                score += 14
            elif symbol_ratio >= 0.16:
                score += 8

        return max(0, min(100, score))

    @staticmethod
    def _estimate_entropy(text: str) -> float:
        if not text:
            return 0.0

        counts: dict[str, int] = {}
        for ch in text:
            counts[ch] = counts.get(ch, 0) + 1

        total = len(text)
        entropy = 0.0
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        return entropy

    def _calculate_risk_score(self, indicators: list[AnalyzerIndicator]) -> int:
        score = 0
        for indicator in indicators:
            severity = str(indicator.get("severity", ""))
            score += _SEVERITY_WEIGHTS.get(severity, 0)
        return min(score, 100)

    @staticmethod
    def _as_json_list(values: list[str]) -> list[JsonValue]:
        return list(values)
