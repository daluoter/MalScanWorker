"""YARA scanning stage using yara CLI."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from malscan_worker.config import get_settings
from malscan_worker.stages.base import Stage, StageContext, StageResult

settings = get_settings()


class YaraStage(Stage):
    """Scan file with YARA rules using yara CLI."""

    @property
    def name(self) -> str:
        return "yara"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        try:
            if ctx.file_path is None or not ctx.file_path.exists():
                raise FileNotFoundError(f"File not found: {ctx.file_path}")

            rules_path = Path(settings.yara_rules_path)
            if not rules_path.exists():
                # No rules directory - skip
                ended_at = datetime.now(timezone.utc)
                duration_ms = int((ended_at - started_at).total_seconds() * 1000)
                return StageResult(
                    stage_name=self.name,
                    status="ok",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    findings={"matches": []},
                    artifacts=[],
                    error=None,
                )

            # Find all .yar files
            rule_files = list(rules_path.glob("*.yar")) + list(rules_path.glob("*.yara"))
            if not rule_files:
                ended_at = datetime.now(timezone.utc)
                duration_ms = int((ended_at - started_at).total_seconds() * 1000)
                return StageResult(
                    stage_name=self.name,
                    status="ok",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    findings={"matches": []},
                    artifacts=[],
                    error=None,
                )

            matches = []

            # Run yara for each rule file
            for rule_file in rule_files:
                proc = await asyncio.create_subprocess_exec(
                    "yara",
                    "-s",  # Print matching strings
                    "-m",  # Print metadata
                    str(rule_file),
                    str(ctx.file_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, stderr = await proc.communicate()

                if proc.returncode == 0 and stdout:
                    # Parse output
                    # With -m: "rule_name [key=value,key2=value2] file_path"
                    # With -s: followed by "0xoffset:$string_id: matched_data"
                    lines = stdout.decode().strip().split("\n")
                    current_rule = None

                    for line in lines:
                        if not line.startswith("0x"):
                            # Rule name line with metadata
                            # Format: "rule_name [meta1=val1,meta2=val2] /path/to/file"
                            meta_dict: dict[str, str] = {}
                            rule_name = ""

                            # Check if metadata is present (enclosed in [])
                            if "[" in line and "]" in line:
                                bracket_start = line.index("[")
                                bracket_end = line.index("]")
                                rule_name = line[:bracket_start].strip()
                                meta_str = line[bracket_start + 1 : bracket_end]

                                # Parse metadata key=value pairs
                                for meta_item in meta_str.split(","):
                                    if "=" in meta_item:
                                        key, value = meta_item.split("=", 1)
                                        # Remove quotes from value
                                        value = value.strip().strip('"')
                                        meta_dict[key.strip()] = value
                            else:
                                # No metadata, just rule name and file path
                                parts = line.split()
                                if parts:
                                    rule_name = parts[0]

                            if rule_name:
                                current_rule = {
                                    "rule": rule_name,
                                    "namespace": rule_file.stem,
                                    "description": meta_dict.get("description", ""),
                                    "severity": meta_dict.get("severity", "medium"),
                                    "author": meta_dict.get("author", ""),
                                    "tags": list[str](),
                                    "strings": list[str](),
                                }
                                matches.append(current_rule)
                        else:
                            # String match line
                            if current_rule:
                                # Parse "0xoffset:$name: data"
                                parts = line.split(":", 2)
                                if len(parts) >= 2:
                                    string_name = parts[1].strip()
                                    strings_list = cast(list[str], current_rule["strings"])
                                    if string_name not in strings_list:
                                        strings_list.append(string_name)

            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)

            return StageResult(
                stage_name=self.name,
                status="ok",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                findings={"matches": matches},
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
