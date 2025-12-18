"""IOC extraction stage using regex patterns."""

import hashlib
import re
from datetime import datetime, timezone

from malscan_worker.stages.base import Stage, StageContext, StageResult

# IOC patterns
URL_PATTERN = re.compile(
    rb'https?://[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+[^\s\x00-\x1f"\'<>]*',
    re.IGNORECASE,
)

DOMAIN_PATTERN = re.compile(
    rb"(?<![a-zA-Z0-9.-])([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}(?![a-zA-Z0-9.-])",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


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

            # Extract URLs
            urls = list(
                {match.decode("utf-8", errors="ignore") for match in URL_PATTERN.findall(content)}
            )[:100]  # Limit to 100

            # Extract domains (excluding URLs)
            url_domains = set()
            for url in urls:
                try:
                    # Extract domain from URL
                    parts = url.split("/")
                    if len(parts) >= 3:
                        url_domains.add(parts[2].lower())
                except Exception:
                    pass

            domains = list(
                {
                    match.decode("utf-8", errors="ignore").lower()
                    for match in DOMAIN_PATTERN.findall(content)
                    if match.decode("utf-8", errors="ignore").lower() not in url_domains
                }
            )[:100]

            # Filter out common non-malicious domains
            common_domains = {
                "microsoft.com",
                "windows.com",
                "google.com",
                "example.com",
                "localhost",
                "w3.org",
            }
            domains = [d for d in domains if d not in common_domains]

            # Filter out short/invalid domains (likely false positives from binary data)
            # Valid domains should have at least 4 chars (e.g., "a.io")
            domains = [d for d in domains if len(d) >= 4 and "." in d[1:-1]]

            # Extract IPs
            ips = list(
                {match.decode("utf-8", errors="ignore") for match in IP_PATTERN.findall(content)}
            )[:50]

            # Filter out private/local IPs
            def is_public_ip(ip: str) -> bool:
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

            ips = [ip for ip in ips if is_public_ip(ip)]

            # Calculate file hashes
            md5_hash = hashlib.md5(content).hexdigest()
            sha1_hash = hashlib.sha1(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()

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
