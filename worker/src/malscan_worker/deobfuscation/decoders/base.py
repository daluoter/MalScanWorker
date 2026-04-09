"""Base contract for deobfuscation decoders."""

from __future__ import annotations

from abc import ABC, abstractmethod

from malscan_worker.deobfuscation.models import DeobfuscationCandidate


class DecoderBase(ABC):
    """Abstract decoder that extracts candidates from raw bytes."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable decoder name used in provenance."""

    @abstractmethod
    def extract_candidates(
        self,
        content: bytes,
        limit: int,
    ) -> list[DeobfuscationCandidate]:
        """Return candidates discovered in input bytes."""
