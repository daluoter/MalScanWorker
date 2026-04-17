"""Sandbox providers, normalization, and fallback handling."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable, cast
from urllib.parse import urlparse

import aiohttp
import structlog

from malscan_worker.config import Settings, get_settings

log = structlog.get_logger()

_DEFAULT_MOCK_IP = "93.184.216.34"
_DEFAULT_MOCK_DOMAIN = "sandbox.mock.local"
_CIRCUIT_FAILURE_THRESHOLD = 3
_CIRCUIT_RESET_SECONDS = 60.0
_REQUEST_MAX_ATTEMPTS = 3
_DONE_STATUSES = {"reported", "completed", "complete", "finished", "done"}
_FAILED_STATUSES = {"failed", "stopped", "broken", "deleted"}
_CONFIRMED_BEHAVIORS = {"process_injection", "credential_theft", "ransomware"}


def resolve_sandbox_provider_name(settings: Settings | None = None) -> str:
    """Resolve provider name with backward-compatible SANDBOX_MOCK fallback."""
    cfg = settings or get_settings()
    provider = str(getattr(cfg, "sandbox_provider", "") or "").strip().lower()
    if provider in {"mock", "capev2"}:
        return provider
    return "mock" if bool(getattr(cfg, "sandbox_mock", True)) else "capev2"


def build_empty_sandbox_result(
    provider: str | None = None,
    *,
    executed: bool = False,
    is_mock: bool = False,
    verdict_hint: str | None = None,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    """Return a backward-compatible additive sandbox payload."""
    return {
        "executed": executed,
        "provider": provider,
        "task_id": None,
        "is_mock": is_mock,
        "verdict_hint": verdict_hint,
        "behaviors": [],
        "network_connections": [],
        "processes": [],
        "files": [],
        "registry": [],
        "mutexes": [],
        "dns": [],
        "http": [],
        "tcp_udp": [],
        "dropped_files": [],
        "screenshots": [],
        "pcap": {"available": False, "url": None},
        "memory_dump": {"available": False, "url": None},
        "iocs": {"domains": [], "ips": [], "urls": []},
        "errors": list(errors or []),
        "raw_report_ref": None,
    }


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        item = value.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _coerce_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _coerce_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return cast(dict[str, Any], value)
    return {}


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    return _as_text(parsed.hostname)


def _verdict_hint_from_behaviors(behaviors: list[dict[str, Any]]) -> str | None:
    behavior_types = {str(item.get("type") or "").lower() for item in behaviors}
    if behavior_types & _CONFIRMED_BEHAVIORS:
        return "malicious"
    if behavior_types:
        return "suspicious"
    return None


class ProviderUnavailableError(RuntimeError):
    """Raised when a provider cannot be used."""


class ProviderCircuitBreaker:
    """Small in-process circuit breaker for unstable providers."""

    def __init__(
        self,
        *,
        failure_threshold: int = _CIRCUIT_FAILURE_THRESHOLD,
        reset_seconds: float = _CIRCUIT_RESET_SECONDS,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.reset_seconds = reset_seconds
        self.failures = 0
        self.opened_until = 0.0

    def is_open(self) -> bool:
        return self.opened_until > asyncio.get_running_loop().time()

    def record_success(self) -> None:
        self.failures = 0
        self.opened_until = 0.0

    def record_failure(self) -> None:
        now = asyncio.get_running_loop().time()
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.opened_until = now + self.reset_seconds


class MockSandboxProvider:
    """Local mock sandbox provider used for tests and fallback."""

    name = "mock"

    def build_mock_result(
        self,
        *,
        file_path: Path | None,
        sha256: str,
        filename: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        result = build_empty_sandbox_result(
            provider=self.name,
            executed=True,
            is_mock=True,
            verdict_hint="suspicious",
            errors=[reason] if reason else None,
        )
        result["behaviors"] = [
            {"type": "file_write", "path": r"C:\Windows\Temp\sample.dll"},
            {
                "type": "registry_read",
                "key": r"HKLM\Software\Microsoft\Windows\CurrentVersion",
            },
        ]
        result["network_connections"] = [
            {"dst_ip": _DEFAULT_MOCK_IP, "dst_port": 443, "protocol": "tcp"}
        ]
        result["processes"] = [
            {
                "pid": 1000,
                "parent_pid": 4,
                "name": filename,
                "command_line": filename,
            }
        ]
        result["files"] = [{"path": r"C:\Windows\Temp\sample.dll", "action": "write"}]
        result["registry"] = [
            {
                "key": r"HKLM\Software\Microsoft\Windows\CurrentVersion",
                "action": "read",
            }
        ]
        result["mutexes"] = [{"name": f"Global\\mock-{sha256[:8]}"}]
        result["dns"] = [{"query": _DEFAULT_MOCK_DOMAIN, "answers": [_DEFAULT_MOCK_IP]}]
        result["http"] = [
            {
                "url": f"https://{_DEFAULT_MOCK_DOMAIN}/sample",
                "method": "GET",
                "user_agent": "MalScanWorkerMock/1.0",
            }
        ]
        result["tcp_udp"] = list(result["network_connections"])
        result["dropped_files"] = [
            {
                "name": "sample.dll",
                "path": r"C:\Windows\Temp\sample.dll",
                "sha256": sha256,
                "size": file_path.stat().st_size if file_path and file_path.exists() else 0,
                "type": "mock",
            }
        ]
        result["screenshots"] = []
        result["pcap"] = {"available": False, "url": None}
        result["memory_dump"] = {"available": False, "url": None}
        result["iocs"] = {
            "domains": [_DEFAULT_MOCK_DOMAIN],
            "ips": [_DEFAULT_MOCK_IP],
            "urls": [f"https://{_DEFAULT_MOCK_DOMAIN}/sample"],
        }
        return result

    async def analyze_file(
        self,
        *,
        file_path: Path | None,
        sha256: str,
        filename: str,
    ) -> dict[str, Any]:
        await asyncio.sleep(0)
        return self.build_mock_result(file_path=file_path, sha256=sha256, filename=filename)

    async def analyze_url(self, *, url: str) -> dict[str, Any]:
        await asyncio.sleep(0)
        filename = _domain_from_url(url) or "url"
        return self.build_mock_result(file_path=None, sha256="", filename=filename)


class CAPEv2SandboxProvider:
    """CAPEv2 provider using its REST API."""

    name = "capev2"

    def __init__(
        self,
        *,
        base_url: str,
        api_token: str | None,
        timeout_seconds: int,
        poll_interval_seconds: int,
        enable_url_submission: bool,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout_seconds = timeout_seconds
        self.poll_interval_seconds = poll_interval_seconds
        self.enable_url_submission = enable_url_submission

    def _endpoint(self, path: str) -> str:
        if self.base_url.endswith("/apiv2"):
            return f"{self.base_url}{path}"
        return f"{self.base_url}/apiv2{path}"

    def _headers(self) -> dict[str, str]:
        if not self.api_token:
            return {}
        return {"Authorization": f"Token {self.api_token}"}

    async def _request_json(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(1, _REQUEST_MAX_ATTEMPTS + 1):
            try:
                async with session.request(method, url, **kwargs) as response:
                    if response.status >= 400:
                        body = await response.text()
                        raise ProviderUnavailableError(
                            f"CAPEv2 request failed with status {response.status}: {body[:200]}"
                        )
                    payload = await response.json(content_type=None)
                    if isinstance(payload, dict):
                        return payload
                    raise ProviderUnavailableError("CAPEv2 returned a non-object JSON payload")
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if attempt == _REQUEST_MAX_ATTEMPTS:
                    break
                await asyncio.sleep(
                    min(float(2 ** (attempt - 1)), float(self.poll_interval_seconds))
                )
        raise ProviderUnavailableError(str(last_error or "CAPEv2 request failed"))

    async def _probe_download(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> dict[str, Any]:
        try:
            async with session.get(url) as response:
                available = response.status < 400
                content_type = response.headers.get("Content-Type") if available else None
                return {
                    "available": available,
                    "url": url if available else None,
                    "content_type": content_type,
                }
        except Exception:  # noqa: BLE001
            return {"available": False, "url": None, "content_type": None}

    @staticmethod
    def _extract_task_id(payload: dict[str, Any]) -> str:
        task_ids = payload.get("task_ids")
        data = _coerce_dict(payload.get("data"))
        task = _coerce_dict(payload.get("task"))
        candidates = [
            payload.get("task_id"),
            task_ids[0] if isinstance(task_ids, list) and task_ids else None,
            data.get("task_id"),
            task.get("id"),
        ]
        for candidate in candidates:
            if candidate is None:
                continue
            return str(candidate)
        raise ProviderUnavailableError("CAPEv2 response did not include a task id")

    async def submit_file(
        self,
        session: aiohttp.ClientSession,
        file_path: Path,
        filename: str,
    ) -> str:
        if not file_path.exists():
            raise ProviderUnavailableError(f"Sandbox file not found: {file_path}")

        with file_path.open("rb") as handle:
            form = aiohttp.FormData()
            form.add_field(
                "file",
                handle,
                filename=filename,
                content_type="application/octet-stream",
            )
            payload = await self._request_json(
                session,
                "POST",
                self._endpoint("/tasks/create/file/"),
                data=form,
            )
        return self._extract_task_id(payload)

    async def submit_url(self, session: aiohttp.ClientSession, url: str) -> str:
        if not self.enable_url_submission:
            raise ProviderUnavailableError("SANDBOX_ENABLE_URL_SUBMISSION is disabled")
        form = aiohttp.FormData()
        form.add_field("url", url)
        payload = await self._request_json(
            session,
            "POST",
            self._endpoint("/tasks/create/url/"),
            data=form,
        )
        return self._extract_task_id(payload)

    async def poll_task(self, session: aiohttp.ClientSession, task_id: str) -> None:
        deadline = asyncio.get_running_loop().time() + float(self.timeout_seconds)
        while True:
            payload = await self._request_json(
                session,
                "GET",
                self._endpoint(f"/tasks/view/{task_id}/"),
            )
            task = payload.get("task") if isinstance(payload.get("task"), dict) else payload
            status = _as_text(task.get("status") if isinstance(task, dict) else None).lower()
            if status in _DONE_STATUSES:
                return
            if status in _FAILED_STATUSES:
                raise ProviderUnavailableError(f"CAPEv2 task {task_id} failed with status {status}")
            if asyncio.get_running_loop().time() >= deadline:
                raise ProviderUnavailableError(
                    f"CAPEv2 task {task_id} timed out after {self.timeout_seconds}s"
                )
            await asyncio.sleep(float(self.poll_interval_seconds))

    async def fetch_report(self, session: aiohttp.ClientSession, task_id: str) -> dict[str, Any]:
        return await self._request_json(
            session,
            "GET",
            self._endpoint(f"/tasks/report/{task_id}/?format=json"),
        )

    async def fetch_artifact_metadata(
        self,
        session: aiohttp.ClientSession,
        task_id: str,
    ) -> dict[str, Any]:
        screenshots_url = self._endpoint(f"/tasks/screenshots/{task_id}/")
        pcap_url = self._endpoint(f"/pcap/get/{task_id}/")
        screenshots_probe = await self._probe_download(session, screenshots_url)
        pcap_probe = await self._probe_download(session, pcap_url)

        screenshots: list[dict[str, Any]] = []
        if screenshots_probe["available"]:
            screenshots.append(
                {
                    "name": "screenshots",
                    "url": screenshots_url,
                    "content_type": screenshots_probe.get("content_type"),
                }
            )

        return {"screenshots": screenshots, "pcap": pcap_probe}

    def normalize_report(
        self,
        *,
        task_id: str,
        report: dict[str, Any],
        screenshot_refs: list[dict[str, Any]] | None = None,
        pcap_ref: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = build_empty_sandbox_result(
            provider=self.name,
            executed=True,
            is_mock=False,
        )
        result["task_id"] = str(task_id)

        behaviors = self._normalize_behaviors(report)
        tcp_udp = self._normalize_tcp_udp(report)
        files = self._normalize_files(report)
        registry = self._normalize_registry(report)
        mutexes = self._normalize_mutexes(report)
        dns = self._normalize_dns(report)
        http = self._normalize_http(report)
        dropped_files = self._normalize_dropped_files(report, task_id)
        processes = self._normalize_processes(report)
        memory_dump = self._normalize_memory_dump(report)
        iocs = self._normalize_iocs(dns=dns, http=http, tcp_udp=tcp_udp)

        result["behaviors"] = behaviors
        result["network_connections"] = list(tcp_udp)
        result["processes"] = processes
        result["files"] = files
        result["registry"] = registry
        result["mutexes"] = mutexes
        result["dns"] = dns
        result["http"] = http
        result["tcp_udp"] = tcp_udp
        result["dropped_files"] = dropped_files
        result["screenshots"] = list(screenshot_refs or [])
        result["pcap"] = pcap_ref or {"available": False, "url": None}
        result["memory_dump"] = memory_dump
        result["iocs"] = iocs
        result["verdict_hint"] = _verdict_hint_from_behaviors(behaviors)
        result["raw_report_ref"] = self._endpoint(f"/tasks/report/{task_id}/?format=json")
        return result

    def _normalize_behaviors(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for signature in _coerce_list(report.get("signatures")):
            if not isinstance(signature, dict):
                continue
            name = _as_text(signature.get("name")).lower()
            description = _as_text(signature.get("description"))
            full_text = f"{name} {description}".lower()
            behavior_type: str | None = None
            if "inject" in full_text or "process_injection" in full_text:
                behavior_type = "process_injection"
            elif "credential" in full_text:
                behavior_type = "credential_theft"
            elif "ransom" in full_text or "encrypt" in full_text:
                behavior_type = "ransomware"
            if behavior_type is not None:
                normalized.append({"type": behavior_type, "detail": description or name})
        return normalized

    def _normalize_processes(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        processes: list[dict[str, Any]] = []
        behavior = _coerce_dict(report.get("behavior"))
        for process in _coerce_list(behavior.get("processes")):
            if not isinstance(process, dict):
                continue
            processes.append(
                {
                    "pid": process.get("process_id") or process.get("pid"),
                    "parent_pid": process.get("parent_id") or process.get("ppid"),
                    "name": process.get("process_name") or process.get("name"),
                    "command_line": process.get("command_line") or process.get("commandline"),
                }
            )
        return processes

    def _normalize_files(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        behavior = _coerce_dict(report.get("behavior"))
        summary = _coerce_dict(behavior.get("summary"))
        writes = [str(item) for item in _coerce_list(summary.get("write_files")) if _as_text(item)]
        if not writes:
            writes = [str(item) for item in _coerce_list(summary.get("files")) if _as_text(item)]
        return [{"path": item, "action": "write"} for item in _dedupe_strings(writes)]

    def _normalize_registry(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        behavior = _coerce_dict(report.get("behavior"))
        summary = _coerce_dict(behavior.get("summary"))
        keys = [str(item) for item in _coerce_list(summary.get("keys")) if _as_text(item)]
        if not keys:
            keys = [str(item) for item in _coerce_list(summary.get("registry")) if _as_text(item)]
        return [{"key": item, "action": "modify"} for item in _dedupe_strings(keys)]

    def _normalize_mutexes(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        behavior = _coerce_dict(report.get("behavior"))
        summary = _coerce_dict(behavior.get("summary"))
        mutexes = [str(item) for item in _coerce_list(summary.get("mutexes")) if _as_text(item)]
        return [{"name": item} for item in _dedupe_strings(mutexes)]

    def _normalize_dns(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        network = _coerce_dict(report.get("network"))
        records: list[dict[str, Any]] = []
        for entry in _coerce_list(network.get("dns")):
            if not isinstance(entry, dict):
                continue
            answers: list[str] = []
            for answer in _coerce_list(entry.get("answers")):
                if isinstance(answer, dict):
                    value = _as_text(answer.get("data"))
                else:
                    value = _as_text(answer)
                if value:
                    answers.append(value)
            records.append({"query": entry.get("request"), "answers": _dedupe_strings(answers)})
        return records

    def _normalize_http(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        network = _coerce_dict(report.get("network"))
        records: list[dict[str, Any]] = []
        for entry in _coerce_list(network.get("http")):
            if not isinstance(entry, dict):
                continue
            records.append(
                {
                    "url": entry.get("uri") or entry.get("url"),
                    "method": entry.get("method"),
                    "user_agent": entry.get("user-agent") or entry.get("user_agent"),
                }
            )
        return records

    def _normalize_tcp_udp(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        network = _coerce_dict(report.get("network"))
        connections: list[dict[str, Any]] = []
        for protocol in ("tcp", "udp"):
            for entry in _coerce_list(network.get(protocol)):
                if not isinstance(entry, dict):
                    continue
                dst_ip = entry.get("dst") or entry.get("dst_ip") or entry.get("ip")
                dst_port = entry.get("dport") or entry.get("dst_port") or entry.get("port")
                if dst_ip is None or dst_port is None:
                    continue
                connections.append(
                    {
                        "dst_ip": str(dst_ip),
                        "dst_port": int(dst_port),
                        "protocol": protocol,
                    }
                )
        return connections

    def _normalize_dropped_files(
        self,
        report: dict[str, Any],
        task_id: str,
    ) -> list[dict[str, Any]]:
        dropped_files: list[dict[str, Any]] = []
        for entry in _coerce_list(report.get("dropped")):
            if not isinstance(entry, dict):
                continue
            dropped_files.append(
                {
                    "name": entry.get("name") or entry.get("filename"),
                    "path": entry.get("filepath") or entry.get("path"),
                    "size": entry.get("size"),
                    "sha256": entry.get("sha256"),
                    "type": entry.get("type"),
                    "url": self._endpoint(f"/tasks/report/{task_id}/?format=dropped"),
                }
            )
        return dropped_files

    def _normalize_memory_dump(self, report: dict[str, Any]) -> dict[str, Any]:
        memory_entries = _coerce_list(report.get("procmemory"))
        if not memory_entries:
            return {"available": False, "url": None}
        first = memory_entries[0] if isinstance(memory_entries[0], dict) else {}
        return {
            "available": True,
            "url": None,
            "path": first.get("path"),
            "pid": first.get("pid"),
        }

    def _normalize_iocs(
        self,
        *,
        dns: list[dict[str, Any]],
        http: list[dict[str, Any]],
        tcp_udp: list[dict[str, Any]],
    ) -> dict[str, list[str]]:
        domains = _dedupe_strings([_as_text(item.get("query")) for item in dns])
        urls = _dedupe_strings([_as_text(item.get("url")) for item in http])
        ips = _dedupe_strings(
            [_as_text(item.get("dst_ip")) for item in tcp_udp if _as_text(item.get("dst_ip"))]
            + [
                answer
                for entry in dns
                for answer in _coerce_list(entry.get("answers"))
                if _as_text(answer)
            ]
        )
        domains = _dedupe_strings(
            domains + [_domain_from_url(url) for url in urls if _domain_from_url(url)]
        )
        return {"domains": domains, "ips": ips, "urls": urls}

    async def analyze_file(
        self,
        *,
        file_path: Path | None,
        sha256: str,
        filename: str,
    ) -> dict[str, Any]:
        if not self.base_url:
            raise ProviderUnavailableError(
                "SANDBOX_BASE_URL is required when SANDBOX_PROVIDER=capev2"
            )
        if file_path is None:
            raise ProviderUnavailableError(
                "Sandbox file path is required for CAPEv2 file submission"
            )

        timeout = aiohttp.ClientTimeout(total=float(self.timeout_seconds))
        async with aiohttp.ClientSession(timeout=timeout, headers=self._headers()) as session:
            task_id = await self.submit_file(session, file_path, filename)
            await self.poll_task(session, task_id)
            report = await self.fetch_report(session, task_id)
            artifacts = await self.fetch_artifact_metadata(session, task_id)
        return self.normalize_report(
            task_id=task_id,
            report=report,
            screenshot_refs=list(artifacts.get("screenshots") or []),
            pcap_ref=artifacts.get("pcap") if isinstance(artifacts.get("pcap"), dict) else None,
        )

    async def analyze_url(self, *, url: str) -> dict[str, Any]:
        if not self.base_url:
            raise ProviderUnavailableError(
                "SANDBOX_BASE_URL is required when SANDBOX_PROVIDER=capev2"
            )
        timeout = aiohttp.ClientTimeout(total=float(self.timeout_seconds))
        async with aiohttp.ClientSession(timeout=timeout, headers=self._headers()) as session:
            task_id = await self.submit_url(session, url)
            await self.poll_task(session, task_id)
            report = await self.fetch_report(session, task_id)
            artifacts = await self.fetch_artifact_metadata(session, task_id)
        return self.normalize_report(
            task_id=task_id,
            report=report,
            screenshot_refs=list(artifacts.get("screenshots") or []),
            pcap_ref=artifacts.get("pcap") if isinstance(artifacts.get("pcap"), dict) else None,
        )


class SandboxProviderRegistry:
    """Registry of named sandbox providers with fallback handling."""

    _default: SandboxProviderRegistry | None = None

    def __init__(self) -> None:
        self._factories: dict[str, Callable[..., Any]] = {}
        self._circuits: dict[str, ProviderCircuitBreaker] = {}

    def register(self, name: str, factory: Callable[..., Any]) -> None:
        self._factories[name] = factory

    def names(self) -> list[str]:
        return list(self._factories.keys())

    def build(self, name: str, **kwargs: Any) -> Any:
        if name not in self._factories:
            raise ProviderUnavailableError(f"Unknown sandbox provider: {name}")
        return self._factories[name](**kwargs)

    async def analyze_with_fallback(
        self,
        *,
        provider_name: str,
        file_path: Path | None,
        sha256: str,
        filename: str,
        submission_url: str | None,
        provider_kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        mock_provider = cast(MockSandboxProvider, self.build("mock"))
        if provider_name == "mock":
            return await mock_provider.analyze_file(
                file_path=file_path,
                sha256=sha256,
                filename=filename,
            )

        circuit = self._circuits.setdefault(provider_name, ProviderCircuitBreaker())
        if circuit.is_open():
            fallback_reason = f"fallback to mock after {provider_name} circuit opened"
            return mock_provider.build_mock_result(
                file_path=file_path,
                sha256=sha256,
                filename=filename,
                reason=fallback_reason,
            )

        try:
            provider = cast(
                MockSandboxProvider | CAPEv2SandboxProvider,
                self.build(provider_name, **provider_kwargs),
            )
            if submission_url:
                result = await provider.analyze_url(url=submission_url)
            else:
                result = await provider.analyze_file(
                    file_path=file_path,
                    sha256=sha256,
                    filename=filename,
                )
            circuit.record_success()
            return result
        except Exception as exc:  # noqa: BLE001
            circuit.record_failure()
            log.warning(
                "sandbox_provider_fallback_to_mock",
                provider=provider_name,
                error=str(exc),
            )
            return mock_provider.build_mock_result(
                file_path=file_path,
                sha256=sha256,
                filename=filename,
                reason=f"fallback to mock after {provider_name} unavailable: {exc}",
            )

    @classmethod
    def default(cls) -> SandboxProviderRegistry:
        if cls._default is None:
            registry = cls()
            registry.register("mock", lambda **_: MockSandboxProvider())
            registry.register("capev2", lambda **kwargs: CAPEv2SandboxProvider(**kwargs))
            cls._default = registry
        return cls._default


def get_default_sandbox_provider_registry() -> SandboxProviderRegistry:
    """Return the shared sandbox provider registry."""
    return SandboxProviderRegistry.default()
