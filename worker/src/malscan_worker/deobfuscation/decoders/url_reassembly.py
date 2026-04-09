"""Decoder for simple URL reassembly from obfuscated separators."""

from __future__ import annotations

import re

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.models import CandidateProvenance, DeobfuscationCandidate

_CARET_URL_RE = re.compile(rb"[A-Za-z0-9:/?&._%+\-=~^]{8,}")


class UrlReassemblyDecoder(DecoderBase):
    """Reassemble URLs split with shell obfuscation characters."""

    @property
    def name(self) -> str:
        return "url_reassembly"

    def extract_candidates(
        self,
        content: bytes,
        limit: int,
    ) -> list[DeobfuscationCandidate]:
        if limit <= 0:
            return []

        candidates: list[DeobfuscationCandidate] = []
        for match in _CARET_URL_RE.finditer(content):
            token = match.group(0)
            if b"^" not in token:
                continue

            rebuilt = token.replace(b"^", b"")
            lowered = rebuilt.lower()
            if not (lowered.startswith(b"http://") or lowered.startswith(b"https://")):
                continue
            if b"." not in rebuilt:
                continue

            candidates.append(
                DeobfuscationCandidate(
                    content=rebuilt,
                    confidence=0.8,
                    provenance=CandidateProvenance(
                        decoder=self.name,
                        offset=match.start(),
                        length=len(token),
                        meta={"obfuscation": "caret"},
                    ),
                )
            )
            if len(candidates) >= limit:
                break

        return candidates
