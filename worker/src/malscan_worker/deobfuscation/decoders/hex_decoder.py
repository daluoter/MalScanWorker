"""Hex-escape decoder for extracting deobfuscation candidates."""

from __future__ import annotations

import re

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.models import CandidateProvenance, DeobfuscationCandidate

_HEX_ESCAPE_SEQUENCE_RE = re.compile(rb"(?:\\x[0-9a-fA-F]{2})+")
_HEX_ESCAPE_UNIT_RE = re.compile(rb"\\x([0-9a-fA-F]{2})")


class HexDecoder(DecoderBase):
    """Extract and decode contiguous C-style hex escape sequences."""

    @property
    def name(self) -> str:
        return "hex_escape"

    def __init__(self, min_decoded_length: int = 8) -> None:
        self._min_decoded_length = min_decoded_length

    def extract_candidates(
        self,
        content: bytes,
        limit: int,
    ) -> list[DeobfuscationCandidate]:
        if limit <= 0:
            return []

        candidates: list[DeobfuscationCandidate] = []
        for match in _HEX_ESCAPE_SEQUENCE_RE.finditer(content):
            decoded = bytes(
                int(unit.group(1).decode("ascii"), 16)
                for unit in _HEX_ESCAPE_UNIT_RE.finditer(match.group(0))
            )
            if len(decoded) < self._min_decoded_length:
                continue

            candidates.append(
                DeobfuscationCandidate(
                    content=decoded,
                    confidence=self._estimate_confidence(decoded),
                    provenance=CandidateProvenance(
                        decoder=self.name,
                        offset=match.start(),
                        length=len(match.group(0)),
                    ),
                )
            )
            if len(candidates) >= limit:
                break
        return candidates

    @staticmethod
    def _estimate_confidence(decoded: bytes) -> float:
        if not decoded:
            return 0.5

        lowered = decoded.lower()
        if any(token in lowered for token in (b"http://", b"https://", b"://", b"www.")):
            return 0.9

        printable_count = sum(1 for byte in decoded if byte in (9, 10, 13) or 32 <= byte <= 126)
        printable_ratio = printable_count / len(decoded)

        if printable_ratio >= 0.9 and any(char in decoded for char in (b".", b"/", b"@", b" ")):
            return 0.75
        return 0.6
