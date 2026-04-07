"""Stage definitions."""

from malscan_worker.stages.archive_extract import ArchiveExtractStage
from malscan_worker.stages.clamav import ClamAVStage
from malscan_worker.stages.document_analysis import DocumentAnalysisStage
from malscan_worker.stages.filetype import FileTypeStage
from malscan_worker.stages.ioc_extract import IocExtractStage
from malscan_worker.stages.sandbox import SandboxStage
from malscan_worker.stages.yara_scan import YaraStage

__all__ = [
    "ArchiveExtractStage",
    "ClamAVStage",
    "DocumentAnalysisStage",
    "FileTypeStage",
    "IocExtractStage",
    "SandboxStage",
    "YaraStage",
]
