"""Deobfuscation stage wrapper for preprocessing decoded candidates and IOCs."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Literal, TypedDict

from malscan_worker.config import get_settings
from malscan_worker.deobfuscation.decoders import (
    Base64Decoder,
    HexDecoder,
    JsDecoder,
    PowerShellDecoder,
    UrlReassemblyDecoder,
    XorDecoder,
)
from malscan_worker.deobfuscation.engine import DeobfuscationEngine
from malscan_worker.deobfuscation.models import DeobfuscationCandidate
from malscan_worker.metrics import (
    deobfuscation_candidates_total,
    deobfuscation_iocs_total,
    deobfuscation_truncation_total,
)
from malscan_worker.stages.base import Stage, StageContext, StageResult


class CandidateProvenanceFinding(TypedDict):
    decoder: str
    offset: int
    length: int
    key: str | None
    meta: dict[str, Any]


class DeobfuscationCandidateFinding(TypedDict):
    content: str
    content_encoding: Literal["utf-8", "base64"]
    content_byte_length: int
    serialized_content_byte_length: int
    content_truncated: bool
    confidence: float
    technique: str
    truncated: bool
    tags: list[str]
    provenance: CandidateProvenanceFinding


class DeobfuscationFindings(TypedDict, total=False):
    reason: str
    candidates: list[DeobfuscationCandidateFinding]
    extracted_iocs: dict[str, list[str]]
    techniques_found: list[str]
    total_decoded_bytes: int
    stats: dict[str, Any]


class DeobfuscationStage(Stage):
    """Run deobfuscation engine on file content and return structured findings."""

    @property
    def name(self) -> str:
        return "deobfuscation"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        try:
            if not ctx.file_path or not ctx.file_path.exists():
                return self._result(started_at, "skipped", {"reason": "File not found"})

            settings = get_settings()
            if not getattr(settings, "deobfuscation_enabled", True):
                return self._result(started_at, "skipped", {"reason": "Deobfuscation disabled"})

            max_file_size = int(getattr(settings, "deobfuscation_max_file_size", 10_000_000))
            file_size = ctx.file_path.stat().st_size
            if file_size > max_file_size:
                return self._result(
                    started_at,
                    "skipped",
                    {
                        "reason": f"File too large for deobfuscation ({file_size} bytes)",
                    },
                )

            content = await asyncio.to_thread(ctx.file_path.read_bytes)

            engine = DeobfuscationEngine(
                decoders=[
                    Base64Decoder(
                        min_decoded_length=int(
                            getattr(settings, "deobfuscation_min_base64_length", 8)
                        )
                    ),
                    HexDecoder(min_decoded_length=8),
                    PowerShellDecoder(),
                    JsDecoder(),
                    UrlReassemblyDecoder(),
                    XorDecoder(
                        min_decoded_length=int(
                            getattr(settings, "deobfuscation_xor_min_decoded_length", 8)
                        )
                    ),
                ],
                max_candidates=int(getattr(settings, "deobfuscation_max_candidates", 100)),
                per_decoder_limit=int(getattr(settings, "deobfuscation_per_decoder_limit", 25)),
                confidence_threshold=float(
                    getattr(settings, "deobfuscation_confidence_threshold", 0.5)
                ),
                max_wall_time_seconds=float(
                    getattr(settings, "deobfuscation_max_wall_time_seconds", 2.0)
                ),
            )

            engine_result = await asyncio.to_thread(engine.run, content)

            max_candidate_bytes = int(getattr(settings, "deobfuscation_max_candidate_bytes", 4096))
            if max_candidate_bytes < 0:
                max_candidate_bytes = 0

            candidate_findings = [
                self._candidate_to_dict(candidate, max_candidate_bytes=max_candidate_bytes)
                for candidate in engine_result.candidates
            ]

            findings = {
                "candidates": candidate_findings,
                "extracted_iocs": engine_result.iocs,
                "techniques_found": sorted(
                    {
                        candidate.get("technique", "")
                        for candidate in candidate_findings
                        if candidate.get("technique")
                    }
                ),
                "total_decoded_bytes": sum(
                    len(candidate.content) for candidate in engine_result.candidates
                ),
                "stats": asdict(engine_result.stats),
            }

            deobfuscation_candidates_total.inc(len(candidate_findings))

            extracted_iocs = engine_result.iocs
            deobfuscation_iocs_total.labels(ioc_type="urls").inc(
                len(extracted_iocs.get("urls", []))
            )
            deobfuscation_iocs_total.labels(ioc_type="domains").inc(
                len(extracted_iocs.get("domains", []))
            )
            deobfuscation_iocs_total.labels(ioc_type="ips").inc(len(extracted_iocs.get("ips", [])))

            if engine_result.stats.truncated:
                reason = engine_result.stats.stop_reason or "unknown"
                deobfuscation_truncation_total.labels(reason=reason).inc()

            return self._result(started_at, "ok", findings)

        except Exception as exc:
            return self._result(started_at, "failed", {}, str(exc))

    def _result(
        self,
        started_at: datetime,
        status: str,
        findings: DeobfuscationFindings,
        error: str | None = None,
    ) -> StageResult:
        ended_at = datetime.now(timezone.utc)
        return StageResult(
            stage_name=self.name,
            status=status,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            findings=findings,
            artifacts=[],
            error=error,
        )

    @staticmethod
    def _candidate_to_dict(
        candidate: DeobfuscationCandidate,
        *,
        max_candidate_bytes: int,
    ) -> DeobfuscationCandidateFinding:
        candidate_dict = asdict(candidate)
        original_length = len(candidate.content)
        serialized_bytes = candidate.content[:max_candidate_bytes]
        candidate_dict["content_byte_length"] = original_length
        candidate_dict["serialized_content_byte_length"] = len(serialized_bytes)
        candidate_dict["content_truncated"] = len(serialized_bytes) < original_length

        try:
            candidate_dict["content"] = serialized_bytes.decode("utf-8", errors="strict")
            candidate_dict["content_encoding"] = "utf-8"
        except UnicodeDecodeError:
            candidate_dict["content"] = base64.b64encode(serialized_bytes).decode("ascii")
            candidate_dict["content_encoding"] = "base64"

        return candidate_dict
