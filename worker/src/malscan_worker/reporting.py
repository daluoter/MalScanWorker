"""Helpers for building worker report payloads."""

from datetime import datetime, timezone
from typing import Any

from malscan.scoring.policy import POLICY_VERSION


def build_password_attempts_exhausted_report(job_data: dict[str, Any]) -> dict[str, Any]:
    """Build final report payload when archive password attempts are exhausted."""
    return {
        "report_schema_version": "mswr-report-v2",
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
            "score_trace": {},
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
                "reason": "連續 3 次密碼錯誤，封存檔解壓失敗。",
                "extraction_failed": True,
            },
        },
        "timings": {
            "total_ms": 0,
            "stages": [],
        },
        "explainability": {
            "summary": {
                "headline": "因密碼嘗試次數耗盡，封存內容未被分析。",
                "primary_artifact_id": None,
                "primary_artifact_path": None,
                "top_findings": [],
                "final_verdict_explainer": "此報告僅反映最外層檔案的分析結果。",
            },
            "artifacts": [],
            "findings": [],
            "evidence": [],
            "iocs": [],
            "decoded_strings": [],
            "uncertainties": [],
            "timeline": [],
            "failure_diagnostics": {
                "status": "blocked",
                "headline": "內層封存內容因密碼耗盡而無法分析。",
                "diagnostics": [
                    {
                        "stage": "archive-extract",
                        "code": "password_attempts_exhausted",
                        "category": "blocked",
                        "severity": "high",
                        "likely_effect": "possible_false_negative",
                        "confidence": "high",
                        "message": "連續 3 次密碼錯誤，封存檔解壓失敗。",
                        "recommended_action": "請取得正確密碼後重新提交分析。",
                    }
                ],
                "suspected_miss_stages": [
                    {
                        "stage": "archive-extract",
                        "reason": "內層檔案未曾被解壓，因此未進入分析流程。",
                        "confidence": "high",
                    }
                ],
            },
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
