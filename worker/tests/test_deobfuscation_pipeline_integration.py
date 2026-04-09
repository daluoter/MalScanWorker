"""Integration-oriented tests for deobfuscation in pipeline result building."""

from datetime import datetime, timezone

import pytest
from malscan_worker.metrics import CONTENT_TYPE_LATEST, metrics_handler
from malscan_worker.pipeline import _build_analysis_result
from malscan_worker.stages.base import StageContext, StageResult


def _stage_result(stage_name: str, findings: dict) -> StageResult:
    now = datetime.now(timezone.utc)
    return StageResult(
        stage_name=stage_name,
        status="ok",
        started_at=now,
        ended_at=now,
        duration_ms=1,
        findings=findings,
        artifacts=[],
    )


def _build_report(results: list[StageResult]) -> dict:
    ctx = StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="key-1",
        sha256="a" * 64,
        original_filename="sample.bin",
        file_path=None,
    )
    return _build_analysis_result("job-1", "file-1", ctx, results, total_ms=100)


def test_deobfuscation_iocs_are_merged_into_report_iocs_with_dedupe() -> None:
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result(
                "ioc-extract",
                {
                    "urls": ["http://a.test", "http://shared.test/path"],
                    "domains": ["a.test", "shared.test"],
                    "ip_addresses": ["1.1.1.1", "2.2.2.2"],
                },
            ),
            _stage_result(
                "deobfuscation",
                {
                    "extracted_iocs": {
                        "urls": ["http://shared.test/path", "http://b.test"],
                        "domains": ["shared.test", "b.test"],
                        "ips": ["2.2.2.2", "3.3.3.3"],
                    }
                },
            ),
        ]
    )

    iocs = report["results"]["iocs"]
    assert iocs["urls"] == ["http://a.test", "http://shared.test/path", "http://b.test"]
    assert iocs["domains"] == ["a.test", "shared.test", "b.test"]
    assert iocs["ips"] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_deobfuscation_report_section_exists() -> None:
    deob_findings = {
        "candidates": [
            {
                "content": "http://evil.test",
                "content_encoding": "utf-8",
                "content_byte_length": 16,
                "confidence": 0.91,
                "technique": "base64",
                "truncated": False,
                "tags": [],
                "provenance": {
                    "decoder": "base64",
                    "offset": 10,
                    "length": 24,
                    "key": None,
                    "meta": {},
                },
            }
        ],
        "extracted_iocs": {
            "urls": ["http://evil.test"],
            "domains": ["evil.test"],
            "ips": [],
            "commands": [],
        },
        "techniques_found": ["base64"],
        "total_decoded_bytes": 16,
        "stats": {"final_candidate_count": 1},
    }
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result("ioc-extract", {"urls": [], "domains": [], "ip_addresses": []}),
            _stage_result("deobfuscation", deob_findings),
        ]
    )

    assert "deobfuscation" in report["results"]
    assert report["results"]["deobfuscation"] == deob_findings


def test_deobfuscation_score_boost_is_additive_caps_at_25_and_flips_clean_to_suspicious() -> None:
    # Clean baseline becomes suspicious with small deobfuscation IOC boost.
    clean_report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result("ioc-extract", {"urls": [], "domains": [], "ip_addresses": []}),
            _stage_result(
                "deobfuscation",
                {
                    "extracted_iocs": {
                        "urls": ["http://a.test"],
                        "domains": ["a.test"],
                        "ips": ["8.8.8.8"],
                    }
                },
            ),
        ]
    )
    assert clean_report["score"] == 3
    assert clean_report["verdict"] == "suspicious"

    # Existing suspicious score gets additive deobfuscation boost, capped at +25.
    suspicious_report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": ["rule1"]}),
            _stage_result("ioc-extract", {"urls": [], "domains": [], "ip_addresses": []}),
            _stage_result(
                "deobfuscation",
                {
                    "extracted_iocs": {
                        "urls": [f"http://u{i}.test" for i in range(20)],
                        "domains": [f"d{i}.test" for i in range(20)],
                        "ips": [f"10.0.0.{i}" for i in range(1, 21)],
                    }
                },
            ),
        ]
    )
    # YARA one match => 60, deob boost => +25 (cap), total 85.
    assert suspicious_report["score"] == 85
    assert suspicious_report["verdict"] == "suspicious"


def test_deobfuscation_score_boost_counts_unique_iocs_only() -> None:
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result("ioc-extract", {"urls": [], "domains": [], "ip_addresses": []}),
            _stage_result(
                "deobfuscation",
                {
                    "extracted_iocs": {
                        "urls": [
                            "http://dup.test/a",
                            "http://dup.test/a",
                            "http://uniq.test/b",
                        ],
                        "domains": ["dup.test", "dup.test"],
                        "ips": ["9.9.9.9", "9.9.9.9"],
                    }
                },
            ),
        ]
    )

    # Unique deob IOCs are 2 URLs + 1 domain + 1 IP => boost 4.
    assert report["score"] == 4
    assert report["verdict"] == "suspicious"


def test_none_ioc_fields_are_treated_as_empty_lists() -> None:
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result(
                "ioc-extract",
                {
                    "urls": None,
                    "domains": None,
                    "ip_addresses": None,
                },
            ),
            _stage_result(
                "deobfuscation",
                {
                    "extracted_iocs": {
                        "urls": None,
                        "domains": None,
                        "ips": None,
                        "ip_addresses": None,
                    }
                },
            ),
        ]
    )

    assert report["score"] == 0
    assert report["verdict"] == "clean"
    assert report["results"]["iocs"]["urls"] == []
    assert report["results"]["iocs"]["domains"] == []
    assert report["results"]["iocs"]["ips"] == []


def test_mixed_ips_and_ip_addresses_fields_are_merged_correctly() -> None:
    report = _build_report(
        [
            _stage_result("file-type", {"mime_type": "application/octet-stream", "file_size": 123}),
            _stage_result("clamav", {"infected": False, "threat_name": None}),
            _stage_result("yara", {"matches": []}),
            _stage_result(
                "ioc-extract",
                {
                    "urls": [],
                    "domains": [],
                    "ips": ["1.1.1.1", "2.2.2.2"],
                },
            ),
            _stage_result(
                "deobfuscation",
                {
                    "extracted_iocs": {
                        "urls": [],
                        "domains": [],
                        "ip_addresses": ["2.2.2.2", "3.3.3.3"],
                    }
                },
            ),
        ]
    )

    assert report["results"]["iocs"]["ips"] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    # Deob score boost is based on unique deob IP values only.
    assert report["score"] == 2
    assert report["verdict"] == "suspicious"


@pytest.mark.asyncio
async def test_metrics_handler_sets_prometheus_content_type_header() -> None:
    response = await metrics_handler(None)  # type: ignore[arg-type]

    assert response.headers["Content-Type"] == CONTENT_TYPE_LATEST
