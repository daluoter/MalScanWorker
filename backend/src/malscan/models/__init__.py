"""Models package."""

from malscan.models.artifact import Artifact
from malscan.models.base import Base
from malscan.models.file import File
from malscan.models.job import Job, JobStatus

__all__ = ["Base", "File", "Job", "JobStatus", "Artifact"]
