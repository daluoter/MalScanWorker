"""JavaScript String.fromCharCode decoder."""

from __future__ import annotations

import re

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.models import CandidateProvenance, DeobfuscationCandidate

_FROM_CHAR_CODE_RE = re.compile(
    rb"String\s*\.\s*fromCharCode\s*\(([^)]{1,4096})\)",
    re.IGNORECASE,
)


class JsDecoder(DecoderBase):
    """Extract string payloads produced by String.fromCharCode."""

    @property
    def name(self) -> str:
        return "js"

    def extract_candidates(
        self,
        content: bytes,
        limit: int,
    ) -> list[DeobfuscationCandidate]:
        if limit <= 0:
            return []

        candidates: list[DeobfuscationCandidate] = []
        for match in _FROM_CHAR_CODE_RE.finditer(content):
            numbers_blob = match.group(1)
            codepoints = self._parse_charcode_args(numbers_blob)
            if codepoints is None:
                continue

            decoded = bytes(codepoints)
            if len(decoded) < 4:
                continue

            candidates.append(
                DeobfuscationCandidate(
                    content=decoded,
                    confidence=0.85,
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
    def _parse_charcode_args(numbers_blob: bytes) -> list[int] | None:
        if not numbers_blob.strip():
            return None

        codepoints: list[int] = []
        for raw_token in numbers_blob.split(b","):
            token = raw_token.strip()
            if not token or not token.isdigit():
                return None

            codepoint = int(token)
            if codepoint > 255:
                return None

            codepoints.append(codepoint)

        return codepoints if codepoints else None
