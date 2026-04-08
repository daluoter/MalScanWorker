"""Windows LNK shortcut analyzer."""

from __future__ import annotations

import asyncio
import base64
import binascii
import importlib
import re
import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, cast

from malscan_worker.analyzers.base import (
    AnalyzerIndicator,
    AnalyzerResult,
    FormatAnalyzer,
    JsonValue,
)

if TYPE_CHECKING:
    from malscan_worker.stages.base import StageContext

try:
    _lnk_file_module = importlib.import_module("LnkParse3.lnk_file")

    _lnk_file_class = cast(Any, getattr(_lnk_file_module, "LnkFile", None))
    if _lnk_file_class is None:
        _lnk_file_class = cast(Any, getattr(_lnk_file_module, "lnk_file", None))
except Exception:
    _lnk_file_class = None


_LNK_MIME_TYPES = {"application/x-ms-shortcut", "application/x-ms-lnk"}
_MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

_SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}

_SCRIPTING_ENGINE_TARGETS = {
    "cmd.exe",
    "powershell.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32",
    "rundll32.exe",
    "regsvr32",
    "regsvr32.exe",
}

_SUSPICIOUS_TARGET_LOCATION_TOKENS = (
    "\\temp\\",
    "\\appdata\\",
    "\\$recycle.bin\\",
    "\\downloads\\",
    "\\users\\public\\",
)

_DOWNLOAD_TOKENS = (
    "invoke-webrequest",
    "iwr ",
    "curl ",
    "wget ",
    "bitsadmin",
    "certutil",
    "downloadstring",
    "urlcache",
    "http://",
    "https://",
)

_SUSPICIOUS_WORKDIR_TOKENS = ("\\appdata\\", "\\temp", "\\programdata", "\\users\\public")

_ENCODED_COMMAND_RE = re.compile(
    r"(?:^|\s)-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]{8,})", re.IGNORECASE
)
_ENVVAR_RE = re.compile(r"%[A-Za-z0-9_]+%|\$env:", re.IGNORECASE)


class LNKAnalyzer(FormatAnalyzer):
    @property
    def name(self) -> str:
        return "lnk"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        del file_path
        if mime.lower() in _LNK_MIME_TYPES:
            return True
        return self._looks_like_lnk_magic(magic)

    async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
        del ctx
        result = AnalyzerResult(analyzer_name=self.name, format_type="LNK")

        try:
            file_size = file_path.stat().st_size
        except OSError as exc:
            result.errors.append(f"failed to stat LNK file: {exc}")
            return result

        if file_size > _MAX_FILE_SIZE_BYTES:
            result.features = {"file_size": file_size}
            result.errors.append("LNK analysis skipped: file exceeds 10MB limit")
            return result

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._analyze_sync, file_path, file_size)

    def _analyze_sync(self, file_path: Path, file_size: int) -> AnalyzerResult:
        result = AnalyzerResult(analyzer_name=self.name, format_type="LNK")
        features = self._empty_features(file_size)

        try:
            raw = file_path.read_bytes()
        except OSError as exc:
            result.features = features
            result.errors.append(f"failed to read LNK file: {exc}")
            return result

        if len(raw) < 76:
            result.errors.append("failed to parse LNK header: truncated shell link header")
        else:
            features.update(self._parse_lnk_header(raw))

        parser_data, parser_errors = self._parse_with_lnkparse3(file_path)
        for error in parser_errors:
            result.errors.append(error)
        if parser_data:
            features.update(parser_data)

        command_chain = self._compose_command_chain(features)
        features["command_chain"] = command_chain

        decoded_command = self._decode_encoded_command(command_chain)
        if decoded_command:
            features["decoded_command"] = decoded_command

        indicators = self._build_indicators(features)
        result.features = features
        result.indicators = indicators
        result.risk_score = self._calculate_risk_score(indicators)
        result.risk_factors = [str(ind.get("type", "")) for ind in indicators if ind.get("type")]
        return result

    @staticmethod
    def _looks_like_lnk_magic(magic: bytes) -> bool:
        if len(magic) < 20:
            return False
        return magic.startswith(b"L\x00\x00\x00") and magic[4:20] == _LNK_CLSID

    def _parse_with_lnkparse3(self, file_path: Path) -> tuple[dict[str, JsonValue], list[str]]:
        if _lnk_file_class is None:
            return {}, ["LnkParse3 not available; using fallback parser"]

        try:
            lnk_obj = self._instantiate_lnk_parser(file_path)
        except Exception as exc:
            return {}, [f"failed to parse LNK with LnkParse3: {exc}"]

        process = getattr(lnk_obj, "process", None)
        if callable(process):
            try:
                process()
            except Exception as exc:
                return {}, [f"failed to process LNK with LnkParse3: {exc}"]

        extracted: dict[str, JsonValue] = {}

        extracted["target_path"] = self._extract_string(
            lnk_obj, "target_path", "path", "local_path"
        )
        extracted["arguments"] = self._extract_string(
            lnk_obj, "arguments", "command_line_arguments"
        )
        extracted["working_dir"] = self._extract_string(lnk_obj, "working_dir", "working_directory")
        extracted["icon_location"] = self._extract_string(lnk_obj, "icon_location", "icon")
        extracted["relative_path"] = self._extract_string(lnk_obj, "relative_path")
        extracted["description"] = self._extract_string(lnk_obj, "description", "name_string")
        extracted["network_path"] = self._extract_string(
            lnk_obj, "network_path", "common_network_relative_link"
        )
        extracted["local_base_path"] = self._extract_string(lnk_obj, "local_base_path")
        extracted["file_size"] = self._extract_int(lnk_obj, "file_size")
        extracted["file_attributes"] = self._extract_int(lnk_obj, "file_attributes")
        extracted["show_command"] = self._extract_int(lnk_obj, "show_command")
        extracted["hot_key"] = self._extract_int(lnk_obj, "hot_key")

        tracker = self._extract_any(lnk_obj, "tracker_data", "tracker")
        if isinstance(tracker, dict):
            extracted["tracker_data"] = self._to_json_value(tracker)
        elif tracker is not None:
            extracted["tracker_data"] = str(tracker)

        timestamps = self._extract_timestamps_from_parser(lnk_obj)
        if timestamps:
            extracted["timestamps"] = timestamps
            extracted["creation_time"] = timestamps.get("created")
            extracted["access_time"] = timestamps.get("accessed")
            extracted["modification_time"] = timestamps.get("modified")

        return extracted, []

    def _instantiate_lnk_parser(self, file_path: Path) -> Any:
        parser_ctor = cast(Callable[..., Any], _lnk_file_class)

        last_error: Exception | None = None
        try:
            return parser_ctor(str(file_path))
        except Exception as exc:
            last_error = exc

        try:
            return parser_ctor(file_path)
        except Exception as exc:
            last_error = exc

        try:
            return parser_ctor(indata=file_path.read_bytes())
        except Exception as exc:
            last_error = exc

        with file_path.open("rb") as handle:
            try:
                return parser_ctor(fhandle=handle)
            except Exception as exc:
                last_error = exc

        if last_error is not None:
            raise last_error
        raise RuntimeError("failed to instantiate LnkParse3 parser")

    def _extract_timestamps_from_parser(self, lnk_obj: Any) -> dict[str, JsonValue]:
        created = self._extract_any(lnk_obj, "creation_time", "created_time")
        accessed = self._extract_any(lnk_obj, "access_time", "last_access_time")
        modified = self._extract_any(lnk_obj, "write_time", "modified_time", "last_write_time")

        timestamps: dict[str, JsonValue] = {}
        for key, raw in (("created", created), ("accessed", accessed), ("modified", modified)):
            normalized = self._normalize_timestamp(raw)
            if normalized is not None:
                timestamps[key] = normalized
        return timestamps

    def _parse_lnk_header(self, raw: bytes) -> dict[str, JsonValue]:
        header_size = struct.unpack_from("<I", raw, 0)[0]
        clsid = raw[4:20]
        file_attributes = struct.unpack_from("<I", raw, 24)[0]
        creation_time = struct.unpack_from("<Q", raw, 28)[0]
        access_time = struct.unpack_from("<Q", raw, 36)[0]
        write_time = struct.unpack_from("<Q", raw, 44)[0]
        file_size = struct.unpack_from("<I", raw, 52)[0]
        show_command = struct.unpack_from("<I", raw, 60)[0]
        hot_key = struct.unpack_from("<H", raw, 64)[0]
        creation_time_iso = self._filetime_to_iso(creation_time)
        access_time_iso = self._filetime_to_iso(access_time)
        modification_time_iso = self._filetime_to_iso(write_time)

        return {
            "header_size": header_size,
            "header_valid": header_size == 0x4C and clsid == _LNK_CLSID,
            "file_attributes": file_attributes,
            "creation_time": creation_time_iso,
            "access_time": access_time_iso,
            "modification_time": modification_time_iso,
            "timestamps": {
                "created": creation_time_iso,
                "accessed": access_time_iso,
                "modified": modification_time_iso,
            },
            "file_size": file_size,
            "show_command": show_command,
            "hot_key": hot_key,
        }

    def _compose_command_chain(self, features: dict[str, JsonValue]) -> str:
        target = str(features.get("target_path") or "").strip()
        arguments = str(features.get("arguments") or "").strip()
        if target and arguments:
            return f"{target} {arguments}".strip()
        return target or arguments

    def _decode_encoded_command(self, command_chain: str) -> str | None:
        normalized_command = self._normalize_caret_obfuscation(command_chain)
        if not normalized_command:
            return None

        match = _ENCODED_COMMAND_RE.search(normalized_command)
        if not match:
            return None

        payload = match.group(1)
        missing_padding = len(payload) % 4
        if missing_padding:
            payload += "=" * (4 - missing_padding)

        try:
            decoded = base64.b64decode(payload, validate=False)
        except binascii.Error:
            return None

        for encoding in ("utf-16le", "utf-8", "latin-1"):
            try:
                text = decoded.decode(encoding, errors="strict").strip("\x00").strip()
            except UnicodeDecodeError:
                continue
            if text:
                return text
        return None

    def _build_indicators(self, features: dict[str, JsonValue]) -> list[AnalyzerIndicator]:
        indicators: list[AnalyzerIndicator] = []

        command_chain = str(features.get("command_chain") or "")
        arguments = str(features.get("arguments") or "")
        normalized_command_chain = self._normalize_caret_obfuscation(command_chain)
        normalized_arguments = self._normalize_caret_obfuscation(arguments)
        command_chain_l = normalized_command_chain.lower()
        target_path = str(features.get("target_path") or "")
        target_path_l = target_path.lower()
        working_dir = str(features.get("working_dir") or "")
        working_dir_l = working_dir.lower()
        network_path = str(features.get("network_path") or "")
        decoded_command = str(features.get("decoded_command") or "")

        if command_chain and any(token in command_chain_l for token in _DOWNLOAD_TOKENS):
            indicators.append(
                {
                    "type": "download_command",
                    "severity": "critical",
                    "detail": "Command chain includes downloader behavior",
                    "evidence": {"command_chain": command_chain},
                }
            )

        if _ENCODED_COMMAND_RE.search(normalized_command_chain):
            evidence: dict[str, JsonValue] = {"command_chain": command_chain}
            if decoded_command:
                evidence["decoded_command"] = decoded_command
            indicators.append(
                {
                    "type": "encoded_command",
                    "severity": "critical",
                    "detail": "Encoded command argument detected",
                    "evidence": evidence,
                }
            )

        if self._is_scripting_engine_with_arguments(target_path, normalized_arguments):
            indicators.append(
                {
                    "type": "cmd_chain",
                    "severity": "critical",
                    "detail": "Scripting engine target invoked with command arguments",
                    "evidence": {"command_chain": command_chain},
                }
            )

        show_command = features.get("show_command")
        hidden_tokens = ("-w hidden", "-windowstyle hidden", "start /min", " /b ")
        if (isinstance(show_command, int) and show_command in {0, 7}) or any(
            token in command_chain_l for token in hidden_tokens
        ):
            indicators.append(
                {
                    "type": "hidden_execution",
                    "severity": "high",
                    "detail": "Shortcut may execute command hidden/minimized",
                    "evidence": {
                        "show_command": show_command,
                        "command_chain": command_chain,
                    },
                }
            )

        if network_path or target_path.startswith("\\\\"):
            indicators.append(
                {
                    "type": "network_target",
                    "severity": "high",
                    "detail": "Shortcut points to network resource",
                    "evidence": {
                        "network_path": network_path,
                        "target_path": target_path,
                    },
                }
            )

        if any(token in target_path_l for token in _SUSPICIOUS_TARGET_LOCATION_TOKENS):
            indicators.append(
                {
                    "type": "suspicious_target",
                    "severity": "high",
                    "detail": "Target path is in a suspicious user-writable location",
                    "evidence": {"target_path": target_path},
                }
            )

        icon_location = str(features.get("icon_location") or "")
        if self._is_icon_mismatch(target_path, icon_location):
            indicators.append(
                {
                    "type": "icon_mismatch",
                    "severity": "medium",
                    "detail": "Icon may disguise true target type",
                    "evidence": {
                        "target_path": target_path,
                        "icon_location": icon_location,
                    },
                }
            )

        if len(arguments) > 500:
            indicators.append(
                {
                    "type": "long_arguments",
                    "severity": "medium",
                    "detail": "Arguments are unusually long",
                    "evidence": {"length": len(arguments)},
                }
            )

        if any(
            _ENVVAR_RE.search(item) for item in (target_path, normalized_arguments, working_dir)
        ):
            indicators.append(
                {
                    "type": "environment_variable_abuse",
                    "severity": "medium",
                    "detail": "Environment variable expansion appears in execution path",
                    "evidence": {
                        "target_path": target_path,
                        "arguments": arguments,
                        "working_dir": working_dir,
                    },
                }
            )

        if any(token in working_dir_l for token in _SUSPICIOUS_WORKDIR_TOKENS):
            indicators.append(
                {
                    "type": "suspicious_working_dir",
                    "severity": "low",
                    "detail": "Working directory is a common malware staging location",
                    "evidence": {"working_dir": working_dir},
                }
            )

        return indicators

    @staticmethod
    def _normalize_caret_obfuscation(value: str) -> str:
        if not value:
            return value
        normalized = re.sub(r"\^(.)", r"\1", value)
        return normalized.replace("^", "")

    @staticmethod
    def _is_scripting_engine_with_arguments(target_path: str, arguments: str) -> bool:
        if not target_path or not arguments.strip():
            return False
        basename = target_path.lower().replace("/", "\\").rsplit("\\", 1)[-1]
        return basename in _SCRIPTING_ENGINE_TARGETS

    def _calculate_risk_score(self, indicators: list[AnalyzerIndicator]) -> int:
        score = 0
        for indicator in indicators:
            score += _SEVERITY_WEIGHTS.get(str(indicator.get("severity", "")), 0)
        return min(score, 100)

    @staticmethod
    def _extract_any(obj: Any, *names: str) -> Any:
        for name in names:
            try:
                if hasattr(obj, name):
                    value = getattr(obj, name)
                    if callable(value):
                        try:
                            value = value()
                        except TypeError:
                            pass
                    if value is not None:
                        return value
            except Exception:
                continue
        return None

    @classmethod
    def _extract_string(cls, obj: Any, *names: str) -> str:
        value = cls._extract_any(obj, *names)
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore").strip()
        return str(value).strip()

    @classmethod
    def _extract_int(cls, obj: Any, *names: str) -> int | None:
        value = cls._extract_any(obj, *names)
        if value is None:
            return None
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError:
                return None
        return None

    @staticmethod
    def _filetime_to_iso(value: int) -> str | None:
        if value <= 0:
            return None
        try:
            timestamp = _FILETIME_EPOCH + timedelta(microseconds=value / 10)
        except OverflowError:
            return None
        return timestamp.isoformat()

    @classmethod
    def _normalize_timestamp(cls, value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            dt = value
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC).isoformat()
        if isinstance(value, int):
            return cls._filetime_to_iso(value)
        if isinstance(value, str):
            text = value.strip()
            return text or None
        return None

    @staticmethod
    def _is_icon_mismatch(target_path: str, icon_location: str) -> bool:
        if not target_path or not icon_location:
            return False
        target_l = target_path.lower()
        icon_l = icon_location.lower()

        executable_like = (
            target_l.endswith(".exe")
            or target_l.endswith(".ps1")
            or target_l.endswith(".bat")
            or target_l.endswith(".cmd")
            or "powershell" in target_l
            or "cmd.exe" in target_l
        )
        deceptive_icon = any(icon_l.endswith(ext) for ext in (".pdf", ".doc", ".docx", ".txt"))
        return executable_like and deceptive_icon

    @staticmethod
    def _to_json_value(value: Any) -> JsonValue:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, dict):
            result: dict[str, JsonValue] = {}
            for key, val in value.items():
                result[str(key)] = LNKAnalyzer._to_json_value(val)
            return result
        if isinstance(value, (list, tuple, set)):
            return [LNKAnalyzer._to_json_value(item) for item in value]
        return str(value)

    @staticmethod
    def _empty_features(file_size: int) -> dict[str, JsonValue]:
        return {
            "target_path": "",
            "arguments": "",
            "working_dir": "",
            "icon_location": "",
            "relative_path": "",
            "description": "",
            "network_path": "",
            "local_base_path": "",
            "timestamps": {
                "created": None,
                "accessed": None,
                "modified": None,
            },
            "creation_time": None,
            "access_time": None,
            "modification_time": None,
            "file_size": file_size,
            "file_attributes": None,
            "show_command": None,
            "hot_key": None,
            "command_chain": "",
            "tracker_data": {},
            "decoded_command": None,
            "header_size": None,
            "header_valid": False,
        }
