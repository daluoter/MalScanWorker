# worker/tests/test_extractors.py
"""Tests for extractor base types, safety utilities, and handler registry."""


import pytest
from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
)
from malscan_worker.extractors.iso_handler import IsoHandler
from malscan_worker.extractors.registry import HandlerRegistry, get_default_registry
from malscan_worker.extractors.safety import (
    check_expansion_ratio,
    remove_symlinks,
    safe_extract_path,
)
from malscan_worker.extractors.zip_handler import ZipHandler


class TestExtractionLimits:
    def test_defaults(self):
        limits = ExtractionLimits()
        assert limits.max_files == 100
        assert limits.max_extracted_bytes == 500_000_000
        assert limits.max_single_file_bytes == 100_000_000
        assert limits.max_expansion_ratio == 100.0
        assert limits.timeout_seconds == 120

    def test_custom_values(self):
        limits = ExtractionLimits(max_files=10, max_expansion_ratio=50.0)
        assert limits.max_files == 10
        assert limits.max_expansion_ratio == 50.0


class TestExtractedFile:
    def test_creation(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        ef = ExtractedFile(
            path=str(f), original_name="test.txt", size=5, origin_path="archive/test.txt"
        )
        assert ef.original_name == "test.txt"
        assert ef.size == 5
        assert ef.origin_path == "archive/test.txt"


class TestExtractionResult:
    def test_clean_result(self):
        r = ExtractionResult(files=[])
        assert r.malicious is False
        assert r.reason is None
        assert r.warnings == []

    def test_malicious_result(self):
        r = ExtractionResult(files=[], malicious=True, reason="zip bomb")
        assert r.malicious is True
        assert r.reason == "zip bomb"


class TestSafeExtractPath:
    def test_normal_path(self, tmp_path):
        result = safe_extract_path(str(tmp_path), "subdir/file.txt")
        assert result is not None
        assert result.startswith(str(tmp_path))

    def test_path_traversal_dotdot(self, tmp_path):
        result = safe_extract_path(str(tmp_path), "../../etc/passwd")
        assert result is None

    def test_path_traversal_absolute(self, tmp_path):
        result = safe_extract_path(str(tmp_path), "/etc/passwd")
        assert result is None

    def test_path_with_current_dir(self, tmp_path):
        result = safe_extract_path(str(tmp_path), "./normal/file.txt")
        assert result is not None


class TestCheckExpansionRatio:
    def test_safe_ratio(self):
        limits = ExtractionLimits(max_expansion_ratio=100.0)
        assert check_expansion_ratio(1000, 50000, limits) is None

    def test_bomb_ratio(self):
        limits = ExtractionLimits(max_expansion_ratio=100.0)
        result = check_expansion_ratio(1000, 200_000, limits)
        assert result is not None
        assert "expansion ratio" in result.lower()

    def test_zero_archive_size(self):
        limits = ExtractionLimits(max_expansion_ratio=100.0)
        # Zero archive size should not divide by zero
        assert check_expansion_ratio(0, 1000, limits) is None


class TestRemoveSymlinks:
    def test_removes_symlinks(self, tmp_path):
        real_file = tmp_path / "real.txt"
        real_file.write_text("content")
        link = tmp_path / "link.txt"
        link.symlink_to(real_file)
        assert link.is_symlink()

        removed = remove_symlinks(str(tmp_path))
        assert removed == 1
        assert not link.exists()
        assert real_file.exists()

    def test_no_symlinks(self, tmp_path):
        real_file = tmp_path / "real.txt"
        real_file.write_text("content")
        removed = remove_symlinks(str(tmp_path))
        assert removed == 0


class TestHandlerRegistry:
    def test_register_and_detect_zip(self, tmp_path):
        registry = HandlerRegistry()
        registry.register(ZipHandler())

        # Create a minimal zip file
        import zipfile

        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("hello.txt", "hello world")

        handler = registry.detect(zip_path, "application/zip")
        assert handler is not None
        assert handler.name == "zip"

    def test_detect_returns_none_for_unknown(self, tmp_path):
        registry = HandlerRegistry()
        registry.register(ZipHandler())
        txt = tmp_path / "file.txt"
        txt.write_text("just text")
        handler = registry.detect(txt, "text/plain")
        assert handler is None

    def test_default_registry_has_all_handlers(self):
        registry = get_default_registry()
        # Should have 7 handlers: zip, 7z, rar, tar, gzip, bz2, iso
        assert len(registry._handlers) == 7


class TestZipHandler:
    def test_extract_simple_zip(self, tmp_path):
        import zipfile

        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("a.txt", "aaa")
            zf.writestr("b.txt", "bbb")

        handler = ZipHandler()
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        limits = ExtractionLimits()

        result = handler.extract(zip_path, extract_dir, limits)
        assert not result.malicious
        assert len(result.files) == 2
        assert result.archive_type == "zip"
        names = {f.original_name for f in result.files}
        assert names == {"a.txt", "b.txt"}

    def test_zip_path_traversal_skipped(self, tmp_path):
        """Entries with path traversal are silently skipped."""
        import zipfile

        zip_path = tmp_path / "evil.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0")
            zf.writestr("safe.txt", "ok")

        handler = ZipHandler()
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        result = handler.extract(zip_path, extract_dir, ExtractionLimits())
        assert len(result.files) == 1
        assert result.files[0].original_name == "safe.txt"
        assert len(result.warnings) >= 1  # path traversal warning

    def test_zip_max_files_exceeded(self, tmp_path):
        import zipfile

        zip_path = tmp_path / "many.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for i in range(10):
                zf.writestr(f"file_{i}.txt", f"content {i}")

        handler = ZipHandler()
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        limits = ExtractionLimits(max_files=3)
        result = handler.extract(zip_path, extract_dir, limits)
        assert len(result.files) == 3
        assert len(result.warnings) >= 1  # max files warning


class TestIsoHandler:
    def test_iso_stub_raises(self, tmp_path):
        handler = IsoHandler()
        assert handler.name == "iso"

        iso_path = tmp_path / "test.iso"
        iso_path.write_bytes(b"\x00" * 100)
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with pytest.raises(NotImplementedError, match="ISO support planned"):
            handler.extract(iso_path, extract_dir, ExtractionLimits())
