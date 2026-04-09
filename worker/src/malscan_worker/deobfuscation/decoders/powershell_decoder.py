"""PowerShell -enc/-encodedCommand decoder."""

from __future__ import annotations

import base64
import binascii
import re

from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.models import CandidateProvenance, DeobfuscationCandidate

_ENCODED_ARG_RE = re.compile(
    rb"(?:^|[\s\"'])-(?:e|enc|encodedcommand)\s+(?:([\"'])([A-Za-z0-9+/=_-]{8,})\1|([A-Za-z0-9+/=_-]{8,}))",
    re.IGNORECASE,
)


class PowerShellDecoder(DecoderBase):
    """Extract and decode PowerShell encoded command payloads."""

    @property
    def name(self) -> str:
        return "powershell"

    def extract_candidates(
        self,
        content: bytes,
        limit: int,
    ) -> list[DeobfuscationCandidate]:
        if limit <= 0:
            return []

        candidates: list[DeobfuscationCandidate] = []
        for match in _ENCODED_ARG_RE.finditer(content):
            token_group = 2 if match.group(2) is not None else 3
            token = match.group(token_group)
            decoded = self._decode_encoded_command(token)
            if decoded is None:
                continue
            if not self._looks_like_script_text(decoded):
                continue

            confidence = 0.95 if b"invoke-expression" in decoded.lower() else 0.75
            candidates.append(
                DeobfuscationCandidate(
                    content=decoded,
                    confidence=confidence,
                    provenance=CandidateProvenance(
                        decoder=self.name,
                        offset=match.start(token_group),
                        length=len(token),
                    ),
                )
            )
            if len(candidates) >= limit:
                break

        return candidates

    @staticmethod
    def _decode_encoded_command(token: bytes) -> bytes | None:
        normalized = token.replace(b"-", b"+").replace(b"_", b"/")
        remainder = len(normalized) % 4
        if remainder == 1:
            return None
        if remainder:
            normalized += b"=" * (4 - remainder)

        try:
            decoded_bytes = base64.b64decode(normalized, validate=True)
        except (ValueError, binascii.Error):
            return None

        for encoding in ("utf-16le", "utf-8", "latin-1"):
            try:
                decoded_text = decoded_bytes.decode(encoding)
                return decoded_text.encode("utf-8")
            except UnicodeDecodeError:
                continue
        return None

    @staticmethod
    def _looks_like_script_text(decoded: bytes) -> bool:
        if len(decoded) < 4:
            return False

        printable_count = sum(1 for byte in decoded if byte in (9, 10, 13) or 32 <= byte <= 126)
        if printable_count / len(decoded) < 0.85:
            return False

        lowered = decoded.lower()
        signal_tokens = (
            b"invoke",
            b"iex",
            b"powershell",
            b"new-object",
            b"download",
            b"http",
            b"write-",
            b"start-",
            b"set-",
            b"get-",
            b"$",
            b";",
        )
        return any(token in lowered for token in signal_tokens)
