"""Tests for archive password behavior in archive extraction."""

from pathlib import Path

import pytest
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.stages.archive_extract import ArchiveExtractStage
from malscan_worker.stages.base import StageContext


class _FakeZipInfo:
    def __init__(self, filename: str, file_size: int, encrypted: bool = False):
        self.filename = filename
        self.file_size = file_size
        self.flag_bits = 0x1 if encrypted else 0x0

    def is_dir(self) -> bool:
        return False


class _FakeZipFile:
    def __init__(self, infos, extract_error: Exception | None = None):
        self._infos = infos
        self._extract_error = extract_error

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def infolist(self):
        return self._infos

    def extract(self, info, path=None, pwd=None):
        if self._extract_error is not None:
            raise self._extract_error
        return str(Path(path) / info.filename)


class _Fake7zInfo:
    def __init__(self, filename: str):
        self.filename = filename


class _Fake7zFile:
    def __init__(
        self,
        file_path: str,
        mode: str = "r",
        password: str | None = None,
        *,
        needs_password: bool = False,
        extract_error: Exception | None = None,
    ):
        self._password = password
        self._needs_password = needs_password
        self._extract_error = extract_error

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def getnames(self):
        return ["a.txt"]

    def needs_password(self):
        return self._needs_password

    def extractall(self, path: str):
        if self._extract_error is not None:
            raise self._extract_error
        out = Path(path)
        out.mkdir(parents=True, exist_ok=True)
        (out / "a.txt").write_bytes(b"hello")


class _FakeRarInfo:
    def __init__(self, filename: str, file_size: int, needs_password: bool = False):
        self.filename = filename
        self.file_size = file_size
        self._needs_password = needs_password

    def is_dir(self) -> bool:
        return False

    def needs_password(self) -> bool:
        return self._needs_password


class _FakeRarFile:
    def __init__(self, infos, extract_error: Exception | None = None):
        self._infos = infos
        self._extract_error = extract_error
        self.extract_calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def infolist(self):
        return self._infos

    def extract(self, info, path=None, pwd=None):
        self.extract_calls.append({"filename": info.filename, "path": path, "pwd": pwd})
        if self._extract_error is not None:
            raise self._extract_error
        out = Path(path)
        out.mkdir(parents=True, exist_ok=True)
        (out / info.filename).write_bytes(b"rar")


@pytest.mark.asyncio
async def test_archive_extract_stage_reraises_password_domain_errors(tmp_path):
    zip_path = tmp_path / "test.zip"
    zip_path.write_bytes(b"PK\x03\x04")

    ctx = StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="key",
        sha256="sha",
        original_filename="test.zip",
        file_path=zip_path,
    )

    stage = ArchiveExtractStage()
    stage._detect_format = lambda _ctx: "zip"
    stage._extract = lambda **_kwargs: (_ for _ in ()).throw(ArchivePasswordRequiredError("zip"))

    with pytest.raises(ArchivePasswordRequiredError):
        await stage.execute(ctx)


@pytest.mark.asyncio
async def test_archive_extract_stage_handles_other_exceptions_as_failed_result(tmp_path):
    zip_path = tmp_path / "test.zip"
    zip_path.write_bytes(b"PK\x03\x04")

    ctx = StageContext(
        job_id="job-2",
        file_id="file-2",
        storage_key="key",
        sha256="sha",
        original_filename="test.zip",
        file_path=zip_path,
    )

    stage = ArchiveExtractStage()
    stage._detect_format = lambda _ctx: "zip"
    stage._extract = lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("boom"))

    result = await stage.execute(ctx)

    assert result.status == "failed"
    assert "Extraction failed: boom" in result.findings["error"]


@pytest.mark.asyncio
async def test_archive_extract_stage_passes_archive_password_to_extract(tmp_path):
    zip_path = tmp_path / "test.zip"
    zip_path.write_bytes(b"PK\x03\x04")

    captured = {}

    def _fake_extract(**kwargs):
        captured.update(kwargs)
        return {"files": []}

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
    stage._detect_format = lambda _ctx: "zip"
    stage._extract = _fake_extract

    result = await stage.execute(ctx)

    assert result.status == "ok"
    assert captured["archive_password"] == "secret"


def test_extract_zip_encrypted_without_password_raises_required(monkeypatch, tmp_path):
    stage = ArchiveExtractStage()
    fake_infos = [_FakeZipInfo(filename="a.txt", file_size=10, encrypted=True)]

    monkeypatch.setattr(
        "malscan_worker.stages.archive_extract.zipfile.ZipFile",
        lambda *_args, **_kwargs: _FakeZipFile(fake_infos),
    )

    with pytest.raises(ArchivePasswordRequiredError) as exc:
        stage._extract_zip(
            file_path=tmp_path / "archive.zip",
            extract_dir=tmp_path / "out",
            max_files=10,
            max_total_size=1024,
            max_single_size=1024,
            max_expansion_ratio=10,
            archive_password=None,
        )

    assert exc.value.args[0] == "zip"


def test_extract_zip_bad_password_raises_wrong_password(monkeypatch, tmp_path):
    stage = ArchiveExtractStage()
    fake_infos = [_FakeZipInfo(filename="a.txt", file_size=10, encrypted=True)]

    monkeypatch.setattr(
        "malscan_worker.stages.archive_extract.zipfile.ZipFile",
        lambda *_args, **_kwargs: _FakeZipFile(
            fake_infos,
            extract_error=RuntimeError("Bad password for file"),
        ),
    )

    with pytest.raises(ArchiveWrongPasswordError) as exc:
        stage._extract_zip(
            file_path=tmp_path / "archive.zip",
            extract_dir=tmp_path / "out",
            max_files=10,
            max_total_size=1024,
            max_single_size=1024,
            max_expansion_ratio=10,
            archive_password="secret",
        )

    assert exc.value.args[0] == "zip"


def test_extract_zip_password_required_runtime_error_raises_required(monkeypatch, tmp_path):
    stage = ArchiveExtractStage()
    fake_infos = [_FakeZipInfo(filename="a.txt", file_size=10, encrypted=True)]

    monkeypatch.setattr(
        "malscan_worker.stages.archive_extract.zipfile.ZipFile",
        lambda *_args, **_kwargs: _FakeZipFile(
            fake_infos,
            extract_error=RuntimeError("File is encrypted, password required for extraction"),
        ),
    )

    with pytest.raises(ArchivePasswordRequiredError) as exc:
        stage._extract_zip(
            file_path=tmp_path / "archive.zip",
            extract_dir=tmp_path / "out",
            max_files=10,
            max_total_size=1024,
            max_single_size=1024,
            max_expansion_ratio=10,
            archive_password="secret",
        )

    assert exc.value.args[0] == "zip"


def test_extract_7z_encrypted_without_password_raises_required(monkeypatch, tmp_path):
    stage = ArchiveExtractStage()

    class _FakePy7zr:
        pass

    fake_py7zr = _FakePy7zr()
    fake_py7zr.SevenZipFile = lambda file_path, mode="r", password=None: _Fake7zFile(
        file_path,
        mode,
        password,
        needs_password=True,
    )

    monkeypatch.setattr("malscan_worker.stages.archive_extract.HAS_PY7ZR", True)
    monkeypatch.setattr("malscan_worker.stages.archive_extract.py7zr", fake_py7zr)

    with pytest.raises(ArchivePasswordRequiredError) as exc:
        stage._extract_7z(
            file_path=tmp_path / "archive.7z",
            extract_dir=tmp_path / "out",
            max_files=10,
            max_total_size=1024,
            max_single_size=1024,
            max_expansion_ratio=10,
            archive_password=None,
        )

    assert exc.value.args[0] == "7z"


def test_extract_7z_wrong_password_raises_wrong_password(monkeypatch, tmp_path):
    stage = ArchiveExtractStage()

    class _FakePy7zrError(Exception):
        pass

    class _FakePy7zr:
        PasswordRequired = _FakePy7zrError

    fake_py7zr = _FakePy7zr()
    fake_py7zr.SevenZipFile = lambda file_path, mode="r", password=None: _Fake7zFile(
        file_path,
        mode,
        password,
        needs_password=False,
        extract_error=_FakePy7zrError("Wrong password"),
    )

    monkeypatch.setattr("malscan_worker.stages.archive_extract.HAS_PY7ZR", True)
    monkeypatch.setattr("malscan_worker.stages.archive_extract.py7zr", fake_py7zr)

    with pytest.raises(ArchiveWrongPasswordError) as exc:
        stage._extract_7z(
            file_path=tmp_path / "archive.7z",
            extract_dir=tmp_path / "out",
            max_files=10,
            max_total_size=1024,
            max_single_size=1024,
            max_expansion_ratio=10,
            archive_password="bad-pass",
        )

    assert exc.value.args[0] == "7z"


def test_extract_rar_encrypted_without_password_raises_required(monkeypatch, tmp_path):
    stage = ArchiveExtractStage()
    fake_infos = [_FakeRarInfo(filename="a.txt", file_size=10, needs_password=True)]

    class _FakeRarModule:
        class RarWrongPasswordError(Exception):
            pass

    fake_rar_module = _FakeRarModule()
    fake_rar_module.RarWrongPassword = _FakeRarModule.RarWrongPasswordError
    fake_rar_module.RarFile = lambda *_args, **_kwargs: _FakeRarFile(fake_infos)

    monkeypatch.setattr("malscan_worker.stages.archive_extract.HAS_RARFILE", True)
    monkeypatch.setattr("malscan_worker.stages.archive_extract.rarfile", fake_rar_module)

    with pytest.raises(ArchivePasswordRequiredError) as exc:
        stage._extract_rar(
            file_path=tmp_path / "archive.rar",
            extract_dir=tmp_path / "out",
            max_files=10,
            max_total_size=1024,
            max_single_size=1024,
            max_expansion_ratio=10,
            archive_password=None,
        )

    assert exc.value.args[0] == "rar"


def test_extract_rar_wrong_password_raises_wrong_password(monkeypatch, tmp_path):
    stage = ArchiveExtractStage()
    fake_infos = [_FakeRarInfo(filename="a.txt", file_size=10, needs_password=True)]

    class _FakeRarWrongPasswordError(Exception):
        pass

    class _FakeRarModule:
        pass

    fake_rar_module = _FakeRarModule()
    fake_rar_module.RarWrongPassword = _FakeRarWrongPasswordError
    fake_rar_module.RarFile = lambda *_args, **_kwargs: _FakeRarFile(
        fake_infos,
        extract_error=_FakeRarWrongPasswordError("bad password"),
    )

    monkeypatch.setattr("malscan_worker.stages.archive_extract.HAS_RARFILE", True)
    monkeypatch.setattr("malscan_worker.stages.archive_extract.rarfile", fake_rar_module)

    with pytest.raises(ArchiveWrongPasswordError) as exc:
        stage._extract_rar(
            file_path=tmp_path / "archive.rar",
            extract_dir=tmp_path / "out",
            max_files=10,
            max_total_size=1024,
            max_single_size=1024,
            max_expansion_ratio=10,
            archive_password="bad-pass",
        )

    assert exc.value.args[0] == "rar"
