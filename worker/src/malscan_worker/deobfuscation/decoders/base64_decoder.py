"""Base64 decoder for extracting deobfuscation candidates."""

from __future__ import annotations

import base64
import binascii
import re

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.models import CandidateProvenance, DeobfuscationCandidate

_BASE64_TOKEN_RE = re.compile(
    rb"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{4,}={0,2}(?![A-Za-z0-9+/=_-])"
)


class Base64Decoder(DecoderBase):
    """Extract and decode base64-like byte tokens."""

    @property
    def name(self) -> str:
        return "base64"

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
        for match in _BASE64_TOKEN_RE.finditer(content):
            token = match.group(0)
            decoded = self._decode_token(token)
            if decoded is None or len(decoded) < self._min_decoded_length:
                continue

            candidates.append(
                DeobfuscationCandidate(
                    content=decoded,
                    confidence=self._estimate_confidence(decoded),
                    provenance=CandidateProvenance(
                        decoder=self.name,
                        offset=match.start(),
                        length=len(token),
                    ),
                )
            )
            if len(candidates) >= limit:
                break
        return candidates

    @staticmethod
    def _decode_token(token: bytes) -> bytes | None:
        has_base64_markers = any(char in token for char in (b"+", b"/", b"=", b"-", b"_"))

        normalized = token.replace(b"-", b"+").replace(b"_", b"/")
        remainder = len(normalized) % 4
        if remainder == 1:
            return None

        padding = remainder
        if padding:
            normalized += b"=" * (4 - padding)

        try:
            decoded = base64.b64decode(normalized, validate=True)
        except (ValueError, binascii.Error):
            return None

        if has_base64_markers or Base64Decoder._looks_textual_candidate(decoded):
            return decoded
        return None

    @staticmethod
    def _looks_textual_candidate(decoded: bytes) -> bool:
        if not decoded:
            return False

        printable_count = sum(1 for byte in decoded if byte in (9, 10, 13) or 32 <= byte <= 126)
        if printable_count / len(decoded) < 0.85:
            return False

        return any(char in decoded for char in (b":", b"/", b".", b"@", b" "))

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
