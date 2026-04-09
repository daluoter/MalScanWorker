"""Helpers for building worker report payloads."""

from datetime import datetime, timezone
from typing import Any

from malscan.scoring.policy import POLICY_VERSION


def build_password_attempts_exhausted_report(job_data: dict[str, Any]) -> dict[str, Any]:
    """Build final report payload when archive password attempts are exhausted."""
    return {
        "job_id": job_data["job_id"],
        "file": {
            "file_id": job_data["file_id"],
            "sha256": job_data.get("sha256", ""),
            "mime": "application/octet-stream",
            "size": 0,
            "original_filename": job_data.get("original_filename", "unknown"),
        },
        "verdict": "unknown",
        "score": 0,
        "risk_level": "clean",
        "risk": {
            "policy_version": POLICY_VERSION,
            "risk_score": 0,
            "risk_level": "clean",
            "legacy_verdict": "unknown",
            "malicious_gate_open": False,
            "high_gate_open": False,
            "independent_source_count": 0,
            "breakdown": {
                "local_score": 0,
                "inherited_score": 0,
                "synergy_bonus": 0,
                "dampener": 0,
                "final_score": 0,
            },
            "evidence": [],
            "top_evidence": [],
            "descendant_summary": {},
        },
        "results": {
            "av_result": {
                "engine": "ClamAV",
                "infected": False,
                "threat_name": None,
            },
            "yara_hits": [],
            "iocs": {
                "urls": [],
                "domains": [],
                "ips": [],
                "hashes": {
                    "md5": "",
                    "sha1": "",
                    "sha256": job_data.get("sha256", ""),
                },
            },
            "sandbox": {
                "executed": False,
                "behaviors": [],
                "network_connections": [],
                "is_mock": True,
            },
            "archive_extract": {
                "archive_type": None,
                "extracted_count": 0,
                "sub_jobs_created": 0,
                "total_extracted_bytes": 0,
                "reason": "Archive extraction failed after 3 incorrect password attempts",
                "extraction_failed": True,
            },
        },
        "timings": {
            "total_ms": 0,
            "stages": [],
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
