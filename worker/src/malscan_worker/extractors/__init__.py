# worker/src/malscan_worker/extractors/__init__.py
"""Pluggable archive format handlers."""

from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)
from malscan_worker.extractors.registry import HandlerRegistry, get_default_registry
from malscan_worker.extractors.safety import (
    check_expansion_ratio,
    remove_symlinks,
    safe_extract_path,
)

__all__ = [
    "ExtractedFile",
    "ExtractionLimits",
    "ExtractionResult",
    "FormatHandler",
    "HandlerRegistry",
    "get_default_registry",
    "check_expansion_ratio",
    "remove_symlinks",
    "safe_extract_path",
]
