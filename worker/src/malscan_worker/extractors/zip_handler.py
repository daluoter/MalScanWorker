# worker/src/malscan_worker/extractors/zip_handler.py
"""ZIP format handler.

Supports standard ZIP encryption and AES-256 encryption (via pyzipper fallback).
"""

import os
import zipfile
from pathlib import Path

import structlog

from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.extractors.base import (
    ExtractedFile,
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)
from malscan_worker.extractors.safety import check_expansion_ratio, safe_extract_path

logger = structlog.get_logger(__name__)

# Optional AES support via pyzipper
try:
    import pyzipper  # type: ignore[import-untyped]

    _HAS_PYZIPPER = True
except ImportError:
    _HAS_PYZIPPER = False


class ZipHandler(FormatHandler):
    @property
    def name(self) -> str:
        return "zip"

    def can_handle(self, file_path: Path, mime: str, magic: bytes) -> bool:
        if magic[:4] == b"PK\x03\x04":
            return True
        if mime in ("application/zip", "application/x-zip-compressed"):
            return True
        if file_path.suffix.lower() == ".zip":
            return True
        return False

    def extract(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None = None,
    ) -> ExtractionResult:
        try:
            return self._extract_standard(file_path, extract_dir, limits, password)
        except (ArchivePasswordRequiredError, ArchiveWrongPasswordError):
            raise
        except zipfile.BadZipFile as e:
            return ExtractionResult(files=[], warnings=[f"Bad zip file: {e}"], archive_type="zip")
        except NotImplementedError:
            # Standard zipfile can't handle AES — try pyzipper fallback
            return self._try_pyzipper_fallback(file_path, extract_dir, limits, password)
        except Exception as e:
            # Check if this is an AES "compression method not supported" error
            if "compression method" in str(e).lower() and _HAS_PYZIPPER:
                return self._try_pyzipper_fallback(file_path, extract_dir, limits, password)
            logger.error("zip_extraction_error", error=str(e))
            return ExtractionResult(
                files=[], warnings=[f"Extraction error: {e}"], archive_type="zip"
            )

    def _try_pyzipper_fallback(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None,
    ) -> ExtractionResult:
        """Attempt extraction with pyzipper for AES-encrypted zips."""
        if not _HAS_PYZIPPER:
            return ExtractionResult(
                files=[],
                warnings=["AES-encrypted zip requires pyzipper package"],
                archive_type="zip",
            )
        try:
            return self._extract_pyzipper(file_path, extract_dir, limits, password)
        except (ArchivePasswordRequiredError, ArchiveWrongPasswordError):
            raise
        except Exception as e:
            logger.error("zip_pyzipper_extraction_error", error=str(e))
            return ExtractionResult(
                files=[],
                warnings=[f"Extraction error (pyzipper): {e}"],
                archive_type="zip",
            )

    # ------------------------------------------------------------------
    # Standard zipfile extraction
    # ------------------------------------------------------------------

    def _extract_standard(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None,
    ) -> ExtractionResult:
        files: list[ExtractedFile] = []
        warnings: list[str] = []

        with zipfile.ZipFile(str(file_path), "r") as zf:
            # Check for encryption
            for info in zf.infolist():
                if info.flag_bits & 0x1:  # encrypted
                    if not password:
                        raise ArchivePasswordRequiredError("zip")
                    break

            # Pre-check expansion ratio from declared sizes
            archive_size = os.path.getsize(file_path)
            total_uncompressed = sum(i.file_size for i in zf.infolist() if not i.is_dir())
            ratio_warning = check_expansion_ratio(archive_size, total_uncompressed, limits)
            if ratio_warning:
                return ExtractionResult(
                    files=[], malicious=True, reason=ratio_warning, archive_type="zip"
                )

            total_extracted_bytes = 0
            pwd = password.encode() if password else None

            for info in zf.infolist():
                if info.is_dir():
                    continue

                if len(files) >= limits.max_files:
                    warnings.append(f"Max files limit ({limits.max_files}) reached, stopping")
                    break

                target = safe_extract_path(str(extract_dir), info.filename)
                if target is None:
                    warnings.append(f"Path traversal skipped: {info.filename}")
                    continue

                if info.file_size > limits.max_single_file_bytes:
                    warnings.append(
                        f"File too large, skipped: {info.filename} ({info.file_size} bytes)"
                    )
                    continue

                if total_extracted_bytes + info.file_size > limits.max_extracted_bytes:
                    warnings.append("Max total extracted bytes reached, stopping")
                    break

                os.makedirs(os.path.dirname(target), exist_ok=True)
                try:
                    with zf.open(info, pwd=pwd) as src, open(target, "wb") as dst:
                        written = 0
                        while True:
                            chunk = src.read(65536)
                            if not chunk:
                                break
                            written += len(chunk)
                            # Streaming ratio check
                            if (
                                archive_size > 0
                                and written / archive_size > limits.max_expansion_ratio
                            ):
                                os.remove(target)
                                return ExtractionResult(
                                    files=files,
                                    malicious=True,
                                    reason="Zip bomb: expansion ratio exceeded during extraction",
                                    archive_type="zip",
                                )
                            dst.write(chunk)
                except RuntimeError as e:
                    if "password" in str(e).lower() or "Bad password" in str(e):
                        raise ArchiveWrongPasswordError("zip") from e
                    raise

                total_extracted_bytes += written
                files.append(
                    ExtractedFile(
                        path=target,
                        original_name=os.path.basename(info.filename),
                        size=written,
                        origin_path=info.filename,
                    )
                )

        return ExtractionResult(files=files, warnings=warnings, archive_type="zip")

    # ------------------------------------------------------------------
    # pyzipper fallback for AES-encrypted zips
    # ------------------------------------------------------------------

    def _extract_pyzipper(
        self,
        file_path: Path,
        extract_dir: Path,
        limits: ExtractionLimits,
        password: str | None,
    ) -> ExtractionResult:
        if not _HAS_PYZIPPER:
            raise RuntimeError("pyzipper not available")

        files: list[ExtractedFile] = []
        warnings: list[str] = []

        with pyzipper.AESZipFile(str(file_path), "r") as zf:
            # Check for encryption
            for info in zf.infolist():
                if info.flag_bits & 0x1:  # encrypted
                    if not password:
                        raise ArchivePasswordRequiredError("zip")
                    break

            archive_size = os.path.getsize(file_path)
            total_uncompressed = sum(i.file_size for i in zf.infolist() if not i.is_dir())
            ratio_warning = check_expansion_ratio(archive_size, total_uncompressed, limits)
            if ratio_warning:
                return ExtractionResult(
                    files=[], malicious=True, reason=ratio_warning, archive_type="zip"
                )

            total_extracted_bytes = 0
            pwd = password.encode() if password else None
            if pwd:
                zf.setpassword(pwd)

            for info in zf.infolist():
                if info.is_dir():
                    continue

                if len(files) >= limits.max_files:
                    warnings.append(f"Max files limit ({limits.max_files}) reached, stopping")
                    break

                target = safe_extract_path(str(extract_dir), info.filename)
                if target is None:
                    warnings.append(f"Path traversal skipped: {info.filename}")
                    continue

                if info.file_size > limits.max_single_file_bytes:
                    warnings.append(
                        f"File too large, skipped: {info.filename} ({info.file_size} bytes)"
                    )
                    continue

                if total_extracted_bytes + info.file_size > limits.max_extracted_bytes:
                    warnings.append("Max total extracted bytes reached, stopping")
                    break

                os.makedirs(os.path.dirname(target), exist_ok=True)
                try:
                    with zf.open(info, pwd=pwd) as src, open(target, "wb") as dst:
                        written = 0
                        while True:
                            chunk = src.read(65536)
                            if not chunk:
                                break
                            written += len(chunk)
                            if (
                                archive_size > 0
                                and written / archive_size > limits.max_expansion_ratio
                            ):
                                os.remove(target)
                                return ExtractionResult(
                                    files=files,
                                    malicious=True,
                                    reason="Zip bomb: expansion ratio exceeded during extraction",
                                    archive_type="zip",
                                )
                            dst.write(chunk)
                except RuntimeError as e:
                    if "password" in str(e).lower() or "bad password" in str(e).lower():
                        raise ArchiveWrongPasswordError("zip") from e
                    raise

                total_extracted_bytes += written
                files.append(
                    ExtractedFile(
                        path=target,
                        original_name=os.path.basename(info.filename),
                        size=written,
                        origin_path=info.filename,
                    )
                )

        return ExtractionResult(files=files, warnings=warnings, archive_type="zip")
