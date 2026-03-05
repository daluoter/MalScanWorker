"""YARA scanning stage using memory-resident yara-python."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
import yara

from malscan_worker.config import get_settings
from malscan_worker.stages.base import Stage, StageContext, StageResult

settings = get_settings()
log = structlog.get_logger()

# Global variable to hold compiled YARA rules
_compiled_rules = None
_rules_loaded = False


def _load_yara_rules() -> yara.Rules | None:
    """Load and compile all YARA rules from the configured directory.

    This runs synchronously and should be called once during startup.
    """
    global _compiled_rules, _rules_loaded

    if _rules_loaded:
        return _compiled_rules

    rules_path = Path(settings.yara_rules_path)
    if not rules_path.exists():
        log.warning("yara_rules_dir_not_found", path=str(rules_path))
        _rules_loaded = True
        return None

    rule_files = list(rules_path.glob("*.yar")) + list(rules_path.glob("*.yara"))
    if not rule_files:
        log.info("no_yara_rules_found", path=str(rules_path))
        _rules_loaded = True
        return None

    # Prepare filepath dict for yara.compile
    # Format: {'namespace': 'filepath'}
    filepaths = {f.stem: str(f) for f in rule_files}

    try:
        log.info("compiling_yara_rules", count=len(filepaths))
        _compiled_rules = yara.compile(filepaths=filepaths)
        log.info("yara_rules_compiled_successfully")
    except Exception as e:
        log.error("yara_rules_compile_failed", error=str(e))
        # Keep None to fail gracefully
        _compiled_rules = None

    _rules_loaded = True
    return _compiled_rules


class YaraStage(Stage):
    """Scan file with memory-resident YARA rules."""

    @property
    def name(self) -> str:
        return "yara"

    def __init__(self):
        # Trigger compilation on instantiation (which happens once at worker start)
        _load_yara_rules()

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        try:
            if ctx.file_path is None or not ctx.file_path.exists():
                raise FileNotFoundError(f"File not found: {ctx.file_path}")

            rules = _load_yara_rules()

            if not rules:
                # No rules available - skip
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

            # Run yara scan (offload to thread pool to avoid blocking async loop)
            loop = asyncio.get_event_loop()
            yara_matches = await loop.run_in_executor(None, lambda: rules.match(str(ctx.file_path)))

            matches: list[dict[str, Any]] = []

            for match in yara_matches:
                # Extract meta
                meta_dict = match.meta

                # Extract matching strings
                strings_list = []
                for s in match.strings:
                    # s is a tuple: (offset, string_identifier, string_data)
                    string_id = s[1]
                    # decode to string or keep as repr if it's binary
                    if string_id not in strings_list:
                        strings_list.append(string_id)

                matches.append(
                    {
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "description": meta_dict.get("description", ""),
                        "severity": meta_dict.get("severity", "medium"),
                        "author": meta_dict.get("author", ""),
                        "tags": match.tags,
                        "strings": strings_list,
                    }
                )

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
