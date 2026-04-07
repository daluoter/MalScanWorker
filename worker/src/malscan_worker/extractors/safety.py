# worker/src/malscan_worker/extractors/safety.py
"""Shared safety utilities for extraction."""

import os

import structlog

from malscan_worker.extractors.base import ExtractionLimits

logger = structlog.get_logger(__name__)


def safe_extract_path(base_dir: str, member_name: str) -> str | None:
    """Validate that a member path resolves within base_dir.

    Returns the resolved absolute path, or None if path traversal detected.
    """
    if os.path.isabs(member_name):
        return None
    target = os.path.normpath(os.path.join(base_dir, member_name))
    if not target.startswith(os.path.abspath(base_dir) + os.sep):
        return None
    return target


def check_expansion_ratio(
    archive_size: int,
    uncompressed_size: int,
    limits: ExtractionLimits,
) -> str | None:
    """Check if expansion ratio exceeds limit.

    Returns an error message string if ratio exceeded, None if safe.
    """
    if archive_size <= 0:
        return None
    ratio = uncompressed_size / archive_size
    if ratio > limits.max_expansion_ratio:
        return f"Zip bomb: expansion ratio {ratio:.1f}x exceeds limit {limits.max_expansion_ratio}x"
    return None


def remove_symlinks(directory: str) -> int:
    """Remove all symlinks in a directory tree. Returns count removed."""
    removed = 0
    for root, dirs, files in os.walk(directory):
        for name in files + dirs:
            full_path = os.path.join(root, name)
            if os.path.islink(full_path):
                os.remove(full_path)
                logger.warning("symlink_removed", path=full_path)
                removed += 1
    return removed
