"""IOC extraction stage using regex patterns."""

import hashlib
import os
import re
import tempfile
from datetime import datetime, timezone

from malscan.config import get_settings

from malscan_worker.stages.base import Stage, StageContext, StageResult
from malscan_worker.utils.submission import InternalJobSubmitter

# IOC patterns
URL_PATTERN = re.compile(
    rb'https?://[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+[^\s\x00-\x1f"\'<>]*',
    re.IGNORECASE,
)

DOMAIN_PATTERN = re.compile(
    rb"(?<![a-zA-Z0-9.-])(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}(?![a-zA-Z0-9.-])",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

_COMMON_DOMAINS = {
    "microsoft.com",
    "windows.com",
    "google.com",
    "example.com",
    "localhost",
    "w3.org",
}


def _is_public_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    first = int(parts[0])
    second = int(parts[1])
    if first == 10:
        return False
    if first == 172 and 16 <= second <= 31:
        return False
    if first == 192 and second == 168:
        return False
    if first == 127:
        return False
    if first == 0 or first >= 224:
        return False
    return True


def extract_raw_iocs(
    content: bytes,
    *,
    max_urls: int = 100,
    max_domains: int = 100,
    max_ips: int = 50,
) -> dict[str, list[str]]:
    urls = list({match.decode("utf-8", errors="ignore") for match in URL_PATTERN.findall(content)})[
        :max_urls
    ]

    url_domains = set()
    for url in urls:
        parts = url.split("/")
        if len(parts) >= 3:
            url_domains.add(parts[2].lower())

    domains = list(
        {
            match.decode("utf-8", errors="ignore").lower()
            for match in DOMAIN_PATTERN.findall(content)
            if match.decode("utf-8", errors="ignore").lower() not in url_domains
        }
    )[:max_domains]
    domains = [d for d in domains if d not in _COMMON_DOMAINS]
    domains = [d for d in domains if len(d) >= 4 and "." in d[1:-1]]

    ips = list({match.decode("utf-8", errors="ignore") for match in IP_PATTERN.findall(content)})[
        :max_ips
    ]
    ips = [ip for ip in ips if _is_public_ip(ip)]

    return {
        "urls": urls,
        "domains": domains,
        "ips": ips,
    }


def extract_raw_ioc_items(
    content: bytes,
    *,
    artifact_ref: str,
    max_urls: int = 100,
    max_domains: int = 100,
    max_ips: int = 50,
) -> list[dict[str, str | int | None]]:
    """Return structured IOC records with stable IDs and offsets."""

    items: list[dict[str, str | int | None]] = []
    seen: set[tuple[str, str]] = set()

    for index, match in enumerate(URL_PATTERN.finditer(content)):
        if index >= max_urls:
            break
        value = match.group().decode("utf-8", errors="ignore")
        key = ("url", value)
        if key in seen:
            continue
        seen.add(key)
        url_index = len([item for item in items if item["type"] == "url"]) + 1
        items.append(
            {
                "ioc_id": f"ioc::{artifact_ref}::url::{url_index}",
                "type": "url",
                "value": value,
                "offset": match.start(),
                "source_stage": "ioc-extract",
                "source_kind": "raw_regex",
            }
        )

    url_domains = {
        item["value"].split("/")[2].lower()
        for item in items
        if item["type"] == "url" and isinstance(item["value"], str) and "/" in item["value"]
    }

    for match in DOMAIN_PATTERN.finditer(content):
        if len([item for item in items if item["type"] == "domain"]) >= max_domains:
            break
        value = match.group().decode("utf-8", errors="ignore").lower()
        if (
            value in _COMMON_DOMAINS
            or value in url_domains
            or len(value) < 4
            or "." not in value[1:-1]
        ):
            continue
        key = ("domain", value)
        if key in seen:
            continue
        seen.add(key)
        domain_index = len([item for item in items if item["type"] == "domain"]) + 1
        items.append(
            {
                "ioc_id": f"ioc::{artifact_ref}::domain::{domain_index}",
                "type": "domain",
                "value": value,
                "offset": match.start(),
                "source_stage": "ioc-extract",
                "source_kind": "raw_regex",
            }
        )

    for match in IP_PATTERN.finditer(content):
        if len([item for item in items if item["type"] == "ip"]) >= max_ips:
            break
        value = match.group().decode("utf-8", errors="ignore")
        if not _is_public_ip(value):
            continue
        key = ("ip", value)
        if key in seen:
            continue
        seen.add(key)
        ip_index = len([item for item in items if item["type"] == "ip"]) + 1
        items.append(
            {
                "ioc_id": f"ioc::{artifact_ref}::ip::{ip_index}",
                "type": "ip",
                "value": value,
                "offset": match.start(),
                "source_stage": "ioc-extract",
                "source_kind": "raw_regex",
            }
        )

    return items


class IocExtractStage(Stage):
    """Extract IOCs (URLs, domains, IPs, hashes) from file."""

    @property
    def name(self) -> str:
        return "ioc-extract"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        try:
            if ctx.file_path is None or not ctx.file_path.exists():
                raise FileNotFoundError(f"File not found: {ctx.file_path}")

            # Read file content
            content = ctx.file_path.read_bytes()

            extracted_iocs = extract_raw_iocs(content)
            urls = extracted_iocs["urls"]
            domains = extracted_iocs["domains"]
            ips = extracted_iocs["ips"]
            artifact_ref = ctx.artifact_id or ctx.root_artifact_id or ctx.job_id
            ioc_items = extract_raw_ioc_items(content, artifact_ref=artifact_ref)

            # Calculate file hashes
            md5_hash = hashlib.md5(content).hexdigest()
            sha1_hash = hashlib.sha1(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()

            # Submission of Extracted URLs as Sub Jobs
            settings = get_settings()
            max_depth = getattr(settings, "max_job_depth", 3)

            extracted_urls = urls[:50]  # Limit to 50 URLs for sub-jobs
            sub_jobs_created = 0

            if ctx.job and ctx.db and ctx.job.depth < max_depth:
                submitter = await InternalJobSubmitter.get_instance()

                for url in extracted_urls:
                    # Create .url file content
                    url_content = f"[InternetShortcut]\nURL={url}\n".encode()
                    url_sha256 = hashlib.sha256(url_content).hexdigest()
                    url_size = len(url_content)

                    # Sanitize URL for filename (very basic)
                    safe_name = "url_" + hashlib.md5(url.encode()).hexdigest()[:8] + ".url"

                    # Write temporarily to pass to submitter
                    fd, temp_path = tempfile.mkstemp(suffix=".url")
                    try:
                        with os.fdopen(fd, "wb") as f:
                            f.write(url_content)

                        # Submit as subjob
                        await submitter.submit_subjob(
                            db=ctx.db,
                            file_path=temp_path,
                            filename=safe_name,
                            content_type="application/internet-shortcut",
                            sha256_hash=url_sha256,
                            file_size=url_size,
                            parent_job=ctx.job,
                        )
                        sub_jobs_created += 1

                    finally:
                        if os.path.exists(temp_path):
                            os.remove(temp_path)

            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)

            return StageResult(
                stage_name=self.name,
                status="ok",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                findings={
                    "urls": urls,
                    "domains": domains,
                    "ips": ips,
                    "hashes": {
                        "md5": md5_hash,
                        "sha1": sha1_hash,
                        "sha256": sha256_hash,
                    },
                    "ioc_items": ioc_items,
                    "sub_jobs_created": sub_jobs_created,
                },
                artifacts=[],
                error=None,
            )

        except Exception as e:
            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)

            return StageResult(
                stage_name=self.name,
                status="failed",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                findings={},
                artifacts=[],
                error=str(e),
            )
