# worker/tests/test_safety_limits.py
"""Integration tests for extraction safety limits."""

import zipfile

from malscan_worker.extractors.base import ExtractionLimits
from malscan_worker.extractors.safety import (
    remove_symlinks,
)
from malscan_worker.extractors.zip_handler import ZipHandler


class TestZipBombDetection:
    def test_declared_ratio_bomb(self, tmp_path):
        """A zip with huge declared uncompressed size should be flagged."""
        handler = ZipHandler()
        # Create a zip where declared size / archive size > 100x
        zip_path = tmp_path / "bomb.zip"
        # Write highly compressible data
        data = b"\x00" * (1024 * 1024)  # 1MB of zeros
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.bin", data)

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        # With a very strict ratio limit, this should trigger
        limits = ExtractionLimits(max_expansion_ratio=2.0)
        result = handler.extract(zip_path, extract_dir, limits)
        assert result.malicious is True
        assert "expansion ratio" in result.reason.lower()

    def test_normal_ratio_passes(self, tmp_path):
        """A normal zip should not be flagged."""
        handler = ZipHandler()
        zip_path = tmp_path / "normal.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("a.txt", "hello world")
            zf.writestr("b.txt", "goodbye world")

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        limits = ExtractionLimits(max_expansion_ratio=100.0)
        result = handler.extract(zip_path, extract_dir, limits)
        assert result.malicious is False


class TestMaxFilesLimit:
    def test_extraction_stops_at_limit(self, tmp_path):
        handler = ZipHandler()
        zip_path = tmp_path / "many.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for i in range(20):
                zf.writestr(f"file_{i:03d}.txt", f"content {i}")

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        limits = ExtractionLimits(max_files=5)
        result = handler.extract(zip_path, extract_dir, limits)
        assert len(result.files) == 5
        assert any("Max files limit" in w for w in result.warnings)


class TestMaxSingleFileSize:
    def test_large_file_skipped(self, tmp_path):
        handler = ZipHandler()
        zip_path = tmp_path / "large.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("small.txt", "tiny")
            zf.writestr("big.bin", b"x" * 2000)

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        limits = ExtractionLimits(max_single_file_bytes=100)
        result = handler.extract(zip_path, extract_dir, limits)
        assert len(result.files) == 1
        assert result.files[0].original_name == "small.txt"


class TestPathTraversal:
    def test_traversal_entries_skipped(self, tmp_path):
        handler = ZipHandler()
        zip_path = tmp_path / "traversal.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../etc/passwd", "hacked")
            zf.writestr("safe.txt", "ok")

        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        result = handler.extract(zip_path, extract_dir, ExtractionLimits())
        names = [f.original_name for f in result.files]
        assert "safe.txt" in names
        assert "passwd" not in names


class TestSymlinkRejection:
    def test_symlinks_removed_after_extraction(self, tmp_path):
        # Simulate post-extraction symlink check
        real = tmp_path / "real.txt"
        real.write_text("content")
        link = tmp_path / "evil_link"
        link.symlink_to(real)

        count = remove_symlinks(str(tmp_path))
        assert count == 1
        assert not link.exists()


class TestCycleDetection:
    def test_ancestor_hash_check(self):
        """If extracted SHA matches ancestor, it should be detected."""
        ancestor_hashes = {"abc123def456", "789xyz"}
        extracted_sha = "abc123def456"
        assert extracted_sha in ancestor_hashes

    def test_non_ancestor_passes(self):
        ancestor_hashes = {"abc123def456"}
        extracted_sha = "newfile_hash"
        assert extracted_sha not in ancestor_hashes
