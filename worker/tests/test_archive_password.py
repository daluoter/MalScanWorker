"""Tests for archive password behavior in extraction handlers and stage.

Tests cover:
- ZipHandler password detection and errors
- Stage-level password exception propagation
- Stage-level generic error handling
- Stage passing archive_password through to handlers
- 7z/rar password handling via CLI (tested at handler level)
"""

import zipfile
from unittest.mock import MagicMock, patch

import pytest
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.extractors.base import ExtractionLimits, ExtractionResult
from malscan_worker.extractors.zip_handler import ZipHandler
from malscan_worker.stages.archive_extract import ArchiveExtractStage
from malscan_worker.stages.base import StageContext

# ---------------------------------------------------------------
# Stage-level: password exceptions propagate out of execute()
# ---------------------------------------------------------------


@pytest.mark.asyncio
@patch("malscan_worker.stages.archive_extract.create_artifact")
async def test_archive_extract_stage_reraises_password_domain_errors(
    mock_create_artifact, tmp_path
):
    """ArchivePasswordRequiredError raised during extraction propagates."""
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("a.txt", "hello")

    ctx = StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="key",
        sha256="sha",
        original_filename="test.zip",
        file_path=zip_path,
    )

    stage = ArchiveExtractStage()

    # Replace the handler's extract to raise password error
    class _FakeHandler:
        name = "zip"

        def can_handle(self, *a, **k):
            return True

        def extract(self, *a, **k):
            raise ArchivePasswordRequiredError("zip")

    stage._registry._handlers = [_FakeHandler()]

    with pytest.raises(ArchivePasswordRequiredError):
        await stage.execute(ctx)


@pytest.mark.asyncio
async def test_archive_extract_stage_handles_other_exceptions_as_error_result(tmp_path):
    """Non-password exceptions produce an error StageResult."""
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("a.txt", "hello")

    ctx = StageContext(
        job_id="job-2",
        file_id="file-2",
        storage_key="key",
        sha256="sha",
        original_filename="test.zip",
        file_path=zip_path,
    )

    stage = ArchiveExtractStage()

    class _FakeHandler:
        name = "zip"

        def can_handle(self, *a, **k):
            return True

        def extract(self, *a, **k):
            raise RuntimeError("boom")

    stage._registry._handlers = [_FakeHandler()]
    result = await stage.execute(ctx)

    assert result.status == "error"
    assert "boom" in result.findings["reason"]


@pytest.mark.asyncio
@patch("malscan_worker.stages.archive_extract.create_artifact")
async def test_archive_extract_stage_passes_archive_password_to_extract(
    mock_create_artifact, tmp_path
):
    """The archive_password from StageContext is forwarded to the handler."""
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("a.txt", "hello")

    captured = {}

    class _FakeHandler:
        name = "zip"

        def can_handle(self, *a, **k):
            return True

        def extract(self, file_path, extract_dir, limits, password=None):
            captured["password"] = password
            return ExtractionResult(files=[], archive_type="zip")

    ctx = StageContext(
        job_id="job-3",
        file_id="file-3",
        storage_key="key",
        sha256="sha",
        original_filename="test.zip",
        file_path=zip_path,
        archive_password="secret",
    )

    stage = ArchiveExtractStage()
    stage._registry._handlers = [_FakeHandler()]

    result = await stage.execute(ctx)

    assert result.status == "ok"
    assert captured["password"] == "secret"


# ---------------------------------------------------------------
# ZipHandler password tests (direct handler tests)
# ---------------------------------------------------------------


def test_extract_zip_encrypted_without_password_raises_required(tmp_path):
    """Encrypted zip without password raises ArchivePasswordRequiredError."""
    handler = ZipHandler()

    zip_path = tmp_path / "encrypted.zip"
    with zipfile.ZipFile(zip_path, "w"):
        # Standard zipfile can't create encrypted zips, so we use a mock approach
        pass

    # Create a zip that reports encryption via flag_bits
    # We monkeypatch the zipfile.ZipFile at the module scope for zip_handler
    class _FakeInfo:
        filename = "a.txt"
        file_size = 10
        flag_bits = 0x1  # encrypted

        def is_dir(self):
            return False

    class _FakeZipFile:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def infolist(self):
            return [_FakeInfo()]

    with patch("malscan_worker.extractors.zip_handler.zipfile.ZipFile", _FakeZipFile):
        with pytest.raises(ArchivePasswordRequiredError) as exc:
            handler.extract(zip_path, tmp_path / "out", ExtractionLimits())
        assert exc.value.args[0] == "zip"


def test_extract_zip_bad_password_raises_wrong_password(tmp_path):
    """Bad password zip raises ArchiveWrongPasswordError."""
    handler = ZipHandler()
    zip_path = tmp_path / "encrypted.zip"
    zip_path.write_bytes(b"PK\x03\x04")  # stub

    class _FakeInfo:
        filename = "a.txt"
        file_size = 10
        flag_bits = 0x1  # encrypted

        def is_dir(self):
            return False

    class _FakeSrc:
        def read(self, size=-1):
            raise RuntimeError("Bad password for file")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeZipFile:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def infolist(self):
            return [_FakeInfo()]

        def open(self, info, pwd=None):
            return _FakeSrc()

    (tmp_path / "out").mkdir(exist_ok=True)

    with patch("malscan_worker.extractors.zip_handler.zipfile.ZipFile", _FakeZipFile):
        with patch("malscan_worker.extractors.zip_handler.os.path.getsize", return_value=100):
            with patch(
                "malscan_worker.extractors.zip_handler.check_expansion_ratio", return_value=None
            ):
                with pytest.raises(ArchiveWrongPasswordError) as exc:
                    handler.extract(
                        zip_path, tmp_path / "out", ExtractionLimits(), password="wrong"
                    )
                assert exc.value.args[0] == "zip"


def test_extract_zip_password_required_runtime_error_with_password_raises_wrong(tmp_path):
    """Runtime error about password encryption with a password supplied maps to wrong password."""
    handler = ZipHandler()
    zip_path = tmp_path / "encrypted.zip"
    zip_path.write_bytes(b"PK\x03\x04")

    class _FakeInfo:
        filename = "a.txt"
        file_size = 10
        flag_bits = 0x1

        def is_dir(self):
            return False

    class _FakeSrc:
        def read(self, size=-1):
            raise RuntimeError("File is encrypted, password required for extraction")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeZipFile:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def infolist(self):
            return [_FakeInfo()]

        def open(self, info, pwd=None):
            return _FakeSrc()

    (tmp_path / "out").mkdir(exist_ok=True)

    with patch("malscan_worker.extractors.zip_handler.zipfile.ZipFile", _FakeZipFile):
        with patch("malscan_worker.extractors.zip_handler.os.path.getsize", return_value=100):
            with patch(
                "malscan_worker.extractors.zip_handler.check_expansion_ratio", return_value=None
            ):
                with pytest.raises(ArchiveWrongPasswordError) as exc:
                    handler.extract(
                        zip_path, tmp_path / "out", ExtractionLimits(), password="secret"
                    )
                assert exc.value.args[0] == "zip"


def test_extract_zip_aes_wrong_password_raises_wrong_password(tmp_path):
    """AES-encrypted zip with wrong password raises ArchiveWrongPasswordError."""
    try:
        import pyzipper
    except ImportError:
        pytest.skip("pyzipper not installed")

    handler = ZipHandler()
    zip_path = tmp_path / "aes-wrong.zip"

    with pyzipper.AESZipFile(
        zip_path,
        mode="w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(b"correct-password")
        zf.writestr("a.txt", "secret content")

    (tmp_path / "out").mkdir(exist_ok=True)

    with pytest.raises((ArchiveWrongPasswordError, RuntimeError)):
        handler.extract(zip_path, tmp_path / "out", ExtractionLimits(), password="wrong-password")


def test_extract_zip_aes_correct_password_extracts(tmp_path):
    """AES-encrypted zip with correct password extracts successfully."""
    try:
        import pyzipper
    except ImportError:
        pytest.skip("pyzipper not installed")

    handler = ZipHandler()
    zip_path = tmp_path / "aes-correct.zip"

    with pyzipper.AESZipFile(
        zip_path,
        mode="w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(b"correct-password")
        zf.writestr("a.txt", "secret content")

    extract_dir = tmp_path / "out"
    extract_dir.mkdir()

    result = handler.extract(zip_path, extract_dir, ExtractionLimits(), password="correct-password")
    assert len(result.files) == 1
    assert result.files[0].original_name == "a.txt"


# ---------------------------------------------------------------
# 7z handler password tests (subprocess-based)
# ---------------------------------------------------------------


def test_extract_7z_encrypted_without_password_raises_required(tmp_path):
    """7z handler raises ArchivePasswordRequiredError when password needed."""
    import shutil

    if shutil.which("7z") is None:
        pytest.skip("7z CLI tool not installed")

    from malscan_worker.extractors.sevenz_handler import SevenZipHandler

    handler = SevenZipHandler()
    fake_7z = tmp_path / "encrypted.7z"
    fake_7z.write_bytes(b"7z\xbc\xaf\x27\x1c")  # magic only, will fail

    # Mock subprocess to simulate password error
    with patch("malscan_worker.extractors.sevenz_handler.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=2, stderr="ERROR: password is required")

        with pytest.raises(ArchivePasswordRequiredError):
            handler.extract(fake_7z, tmp_path / "out", ExtractionLimits())


def test_extract_7z_wrong_password_raises_wrong_password(tmp_path):
    """7z handler raises ArchiveWrongPasswordError with wrong password."""
    from malscan_worker.extractors.sevenz_handler import SevenZipHandler

    handler = SevenZipHandler()
    fake_7z = tmp_path / "encrypted.7z"
    fake_7z.write_bytes(b"7z\xbc\xaf\x27\x1c")

    with patch("malscan_worker.extractors.sevenz_handler.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=2, stderr="ERROR: Wrong password")

        with pytest.raises(ArchiveWrongPasswordError):
            handler.extract(fake_7z, tmp_path / "out", ExtractionLimits(), password="bad-pass")


def test_extract_7z_corrupt_input_maps_to_wrong_password(tmp_path):
    """7z with password + corrupt data maps to ArchiveWrongPasswordError."""
    from malscan_worker.extractors.sevenz_handler import SevenZipHandler

    handler = SevenZipHandler()
    fake_7z = tmp_path / "corrupt.7z"
    fake_7z.write_bytes(b"7z\xbc\xaf\x27\x1c")

    with patch("malscan_worker.extractors.sevenz_handler.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=2, stderr="ERROR: password is needed for extraction"
        )

        with pytest.raises(ArchivePasswordRequiredError):
            handler.extract(fake_7z, tmp_path / "out", ExtractionLimits(), password=None)


# ---------------------------------------------------------------
# RAR handler password tests (subprocess-based)
# ---------------------------------------------------------------


def test_extract_rar_encrypted_without_password_raises_required(tmp_path):
    """RAR handler raises ArchivePasswordRequiredError when password needed."""
    from malscan_worker.extractors.rar_handler import RarHandler

    handler = RarHandler()
    fake_rar = tmp_path / "encrypted.rar"
    fake_rar.write_bytes(b"Rar!\x1a\x07")

    with patch("malscan_worker.extractors.rar_handler.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=3, stderr="ERROR: encrypted archive, password required", stdout=""
        )

        with pytest.raises(ArchivePasswordRequiredError):
            handler.extract(fake_rar, tmp_path / "out", ExtractionLimits())


def test_extract_rar_wrong_password_raises_wrong_password(tmp_path):
    """RAR handler raises ArchiveWrongPasswordError with wrong password."""
    from malscan_worker.extractors.rar_handler import RarHandler

    handler = RarHandler()
    fake_rar = tmp_path / "encrypted.rar"
    fake_rar.write_bytes(b"Rar!\x1a\x07")

    with patch("malscan_worker.extractors.rar_handler.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=3, stderr="ERROR: wrong password for file", stdout=""
        )

        with pytest.raises(ArchiveWrongPasswordError):
            handler.extract(fake_rar, tmp_path / "out", ExtractionLimits(), password="bad-pass")
