"""Tests for deobfuscation core models and safety guard."""

from __future__ import annotations

import base64
from dataclasses import dataclass

import pytest
from malscan_worker.deobfuscation.decoders.base import DecoderBase
from malscan_worker.deobfuscation.decoders.base64_decoder import Base64Decoder
from malscan_worker.deobfuscation.decoders.hex_decoder import HexDecoder
from malscan_worker.deobfuscation.decoders.js_decoder import JsDecoder
from malscan_worker.deobfuscation.decoders.powershell_decoder import PowerShellDecoder
from malscan_worker.deobfuscation.decoders.url_reassembly import UrlReassemblyDecoder
from malscan_worker.deobfuscation.decoders.xor_decoder import XorDecoder
from malscan_worker.deobfuscation.engine import DeobfuscationEngine
from malscan_worker.deobfuscation.models import (
    CandidateProvenance,
    DeobfuscationCandidate,
)
from malscan_worker.deobfuscation.safety import DeobfuscationSafetyGuard


def test_candidate_and_provenance_defaults() -> None:
    provenance = CandidateProvenance(decoder="base64", offset=12, length=48)

    candidate = DeobfuscationCandidate(content=b"decoded", provenance=provenance)

    assert provenance.decoder == "base64"
    assert provenance.offset == 12
    assert provenance.length == 48
    assert provenance.key is None
    assert provenance.meta == {}

    assert candidate.content == b"decoded"
    assert candidate.provenance is provenance
    assert candidate.confidence == 0.0
    assert candidate.technique == "base64"
    assert candidate.truncated is False
    assert candidate.tags == []


def test_safety_guard_candidate_cap() -> None:
    guard = DeobfuscationSafetyGuard(max_candidates=2, max_wall_time_seconds=60.0)

    assert guard.try_register_candidate() is True
    assert guard.try_register_candidate() is True
    assert guard.try_register_candidate() is False
    assert guard.stop_reason == "candidate_cap"


def test_safety_guard_wall_time_stop() -> None:
    timeline = iter([100.0, 100.25, 101.5])
    guard = DeobfuscationSafetyGuard(
        max_candidates=100,
        max_wall_time_seconds=1.0,
        now_fn=lambda: next(timeline),
    )

    assert guard.should_stop() is False
    assert guard.should_stop() is True
    assert guard.stop_reason == "wall_time"


def test_safety_guard_rejects_invalid_limits() -> None:
    with pytest.raises(ValueError):
        DeobfuscationSafetyGuard(max_candidates=-1, max_wall_time_seconds=1.0)

    with pytest.raises(ValueError):
        DeobfuscationSafetyGuard(max_candidates=1, max_wall_time_seconds=-0.1)

    with pytest.raises(ValueError):
        DeobfuscationSafetyGuard(
            max_candidates=1,
            max_wall_time_seconds=float("inf"),
        )

    with pytest.raises(ValueError):
        DeobfuscationSafetyGuard(
            max_candidates=1,
            max_wall_time_seconds=float("nan"),
        )


def test_safety_guard_wall_time_equality_does_not_stop() -> None:
    timeline = iter([100.0, 101.0, 101.0001])
    guard = DeobfuscationSafetyGuard(
        max_candidates=100,
        max_wall_time_seconds=1.0,
        now_fn=lambda: next(timeline),
    )

    assert guard.should_stop() is False
    assert guard.should_stop() is True
    assert guard.stop_reason == "wall_time"


def test_candidate_explicit_technique_is_preserved() -> None:
    provenance = CandidateProvenance(decoder="xor", offset=0, length=4)

    candidate = DeobfuscationCandidate(
        content=b"decoded",
        provenance=provenance,
        technique="custom-technique",
    )

    assert candidate.technique == "custom-technique"


def test_mutable_defaults_are_isolated_per_instance() -> None:
    first_provenance = CandidateProvenance(decoder="b64", offset=0, length=1)
    second_provenance = CandidateProvenance(decoder="hex", offset=1, length=2)

    first_candidate = DeobfuscationCandidate(
        content=b"one",
        provenance=first_provenance,
    )
    second_candidate = DeobfuscationCandidate(
        content=b"two",
        provenance=second_provenance,
    )

    first_provenance.meta["k"] = "v"
    first_candidate.tags.append("tag1")

    assert second_provenance.meta == {}
    assert second_candidate.tags == []


def test_base64_url_extraction() -> None:
    decoder = Base64Decoder(min_decoded_length=8)
    token = b"aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXRo"
    content = b"prefix " + token + b" suffix"

    candidates = decoder.extract_candidates(content, limit=10)

    assert len(candidates) == 1
    assert candidates[0].content == b"https://example.com/path"
    assert candidates[0].confidence >= 0.5
    assert candidates[0].provenance.decoder == "base64"
    assert candidates[0].provenance.offset == len(b"prefix ")
    assert candidates[0].provenance.length == len(token)


def test_hex_escape_url_extraction() -> None:
    decoder = HexDecoder(min_decoded_length=8)
    token = b"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x65\\x76\\x69\\x6c\\x2e\\x74\\x65\\x73\\x74"

    candidates = decoder.extract_candidates(token, limit=10)

    assert len(candidates) == 1
    assert candidates[0].content == b"http://evil.test"
    assert candidates[0].confidence >= 0.5
    assert candidates[0].provenance.decoder == "hex_escape"
    assert candidates[0].provenance.offset == 0
    assert candidates[0].provenance.length == len(token)


def test_base64_short_payload_discard() -> None:
    decoder = Base64Decoder(min_decoded_length=8)

    candidates = decoder.extract_candidates(b"payload aGk=", limit=10)

    assert candidates == []


def test_extract_candidates_respects_limit() -> None:
    base64_decoder = Base64Decoder(min_decoded_length=8)
    base64_candidates = base64_decoder.extract_candidates(
        b"aHR0cDovL2EudGVzdA== aHR0cDovL2IudGVzdA==",
        limit=1,
    )

    hex_decoder = HexDecoder(min_decoded_length=8)
    hex_candidates = hex_decoder.extract_candidates(
        b"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x61\\x2e\\x74\\x65\\x73\\x74 "
        b"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x62\\x2e\\x74\\x65\\x73\\x74",
        limit=1,
    )

    assert len(base64_candidates) == 1
    assert len(hex_candidates) == 1


def test_extract_candidates_with_non_positive_limit_returns_empty_list() -> None:
    base64_decoder = Base64Decoder(min_decoded_length=1)
    hex_decoder = HexDecoder(min_decoded_length=1)

    assert base64_decoder.extract_candidates(b"aHR0cDovL2EudGVzdA==", limit=0) == []
    assert base64_decoder.extract_candidates(b"aHR0cDovL2EudGVzdA==", limit=-1) == []

    assert hex_decoder.extract_candidates(b"\\x68\\x69", limit=0) == []
    assert hex_decoder.extract_candidates(b"\\x68\\x69", limit=-1) == []


def test_base64_invalid_tokens_are_rejected() -> None:
    decoder = Base64Decoder(min_decoded_length=1)

    assert decoder.extract_candidates(b"prefix abcde suffix", limit=10) == []
    assert decoder.extract_candidates(b"prefix abcd- suffix", limit=10) == []


def test_base64_urlsafe_token_decoded() -> None:
    decoder = Base64Decoder(min_decoded_length=1)

    candidates = decoder.extract_candidates(b"prefix -_8A suffix", limit=10)

    assert len(candidates) == 1
    assert candidates[0].content == b"\xfb\xff\x00"
    assert candidates[0].provenance.decoder == "base64"


def test_base64_plain_long_word_not_decoded() -> None:
    decoder = Base64Decoder(min_decoded_length=8)

    candidates = decoder.extract_candidates(b"prefix supercalifragilistic suffix", limit=10)

    assert candidates == []


def test_hex_decoder_ignores_malformed_hex_escapes() -> None:
    decoder = HexDecoder(min_decoded_length=1)

    candidates = decoder.extract_candidates(b"prefix \\x4G\\xZZ\\x1\\x suffix", limit=10)

    assert candidates == []


def test_powershell_decoder_extracts_invoke_expression_from_enc() -> None:
    decoder = PowerShellDecoder()
    encoded = base64.b64encode("Invoke-Expression".encode("utf-16le"))
    sample = b"powershell.exe -enc " + encoded

    candidates = decoder.extract_candidates(sample, limit=10)

    assert len(candidates) == 1
    assert candidates[0].content == b"Invoke-Expression"
    assert candidates[0].provenance.decoder == "powershell"
    assert candidates[0].confidence >= 0.9


def test_powershell_decoder_extracts_quoted_encodedcommand_payload() -> None:
    decoder = PowerShellDecoder()
    encoded = base64.b64encode("Write-Host hi".encode("utf-16le"))
    sample = b'powershell -encodedcommand "' + encoded + b'"'

    candidates = decoder.extract_candidates(sample, limit=10)

    assert len(candidates) == 1
    assert candidates[0].content == b"Write-Host hi"
    assert candidates[0].provenance.decoder == "powershell"


def test_powershell_decoder_extracts_single_quoted_encodedcommand_payload() -> None:
    decoder = PowerShellDecoder()
    encoded = base64.b64encode("Write-Host hi".encode("utf-16le"))
    sample = b"powershell -encodedcommand '" + encoded + b"'"

    candidates = decoder.extract_candidates(sample, limit=10)

    assert len(candidates) == 1
    assert candidates[0].content == b"Write-Host hi"
    assert candidates[0].provenance.decoder == "powershell"


def test_powershell_decoder_rejects_printable_gibberish_payload() -> None:
    decoder = PowerShellDecoder()
    encoded = base64.b64encode("friendly words and numbers 12345".encode("utf-16le"))
    sample = b"powershell -encodedcommand " + encoded

    candidates = decoder.extract_candidates(sample, limit=10)

    assert candidates == []


def test_js_decoder_extracts_url_from_charcode() -> None:
    decoder = JsDecoder()
    sample = (
        b"var u=String.fromCharCode(104,116,116,112,58,47,47,"
        b"101,118,105,108,46,116,101,115,116);"
    )

    candidates = decoder.extract_candidates(sample, limit=10)

    assert len(candidates) == 1
    assert candidates[0].content == b"http://evil.test"
    assert candidates[0].provenance.decoder == "js"


@pytest.mark.parametrize(
    "arg_blob",
    [
        b"65,66,67,68,1000,69",
        b"65,66,67,68,not_a_number,69",
    ],
)
def test_js_decoder_rejects_malformed_numeric_blobs(arg_blob: bytes) -> None:
    decoder = JsDecoder()
    sample = b"String.fromCharCode(" + arg_blob + b")"

    candidates = decoder.extract_candidates(sample, limit=10)

    assert candidates == []


def test_js_decoder_rejects_candidate_when_any_token_is_invalid() -> None:
    decoder = JsDecoder()
    sample = b"String.fromCharCode(104,116,invalid,112,58,47,47,101)"

    candidates = decoder.extract_candidates(sample, limit=10)

    assert candidates == []


def test_url_reassembly_decoder_handles_caret_obfuscation() -> None:
    decoder = UrlReassemblyDecoder()
    sample = b"h^t^t^p^:^/^/^e^v^i^l^.^t^e^s^t"

    candidates = decoder.extract_candidates(sample, limit=10)

    assert len(candidates) == 1
    assert candidates[0].content == b"http://evil.test"
    assert candidates[0].provenance.decoder == "url_reassembly"


def test_xor_decoder_recovers_url_from_single_byte_xor_sample() -> None:
    decoder = XorDecoder()
    key = 0x23
    plain = b"https://example.test/path"
    sample = bytes(byte ^ key for byte in plain)

    candidates = decoder.extract_candidates(sample, limit=10)

    assert len(candidates) == 1
    assert candidates[0].content == plain
    assert candidates[0].confidence >= 0.5
    assert candidates[0].provenance.decoder == "xor"
    assert candidates[0].provenance.key == "0x23"


def test_xor_decoder_discards_non_printable_garbage_sample() -> None:
    decoder = XorDecoder()
    sample = bytes(range(1, 65))

    candidates = decoder.extract_candidates(sample, limit=10)

    assert candidates == []


def test_xor_decoder_empty_content_returns_empty_without_crashing() -> None:
    decoder = XorDecoder(
        min_decoded_length=0,
        min_printable_ratio=0.0,
        min_blob_entropy=0.0,
        max_blob_entropy=8.0,
    )

    assert decoder.extract_candidates(b"", limit=10) == []


def test_xor_decoder_with_non_positive_limit_returns_empty_list() -> None:
    decoder = XorDecoder(min_decoded_length=1)
    sample = b"A" * 32

    assert decoder.extract_candidates(sample, limit=0) == []
    assert decoder.extract_candidates(sample, limit=-1) == []


def test_xor_decoder_rejects_invalid_constructor_config() -> None:
    with pytest.raises(ValueError):
        XorDecoder(min_decoded_length=-1)

    with pytest.raises(ValueError):
        XorDecoder(min_printable_ratio=-0.01)

    with pytest.raises(ValueError):
        XorDecoder(min_printable_ratio=1.01)

    with pytest.raises(ValueError):
        XorDecoder(min_blob_entropy=-0.1)

    with pytest.raises(ValueError):
        XorDecoder(max_blob_entropy=8.1)

    with pytest.raises(ValueError):
        XorDecoder(min_blob_entropy=5.0, max_blob_entropy=4.0)


@dataclass
class _StaticDecoder(DecoderBase):
    _name: str
    _candidates: list[DeobfuscationCandidate]

    @property
    def name(self) -> str:
        return self._name

    def extract_candidates(self, content: bytes, limit: int) -> list[DeobfuscationCandidate]:
        del content
        return self._candidates[: max(0, limit)]


def _candidate(content: bytes, decoder: str, confidence: float = 0.9) -> DeobfuscationCandidate:
    return DeobfuscationCandidate(
        content=content,
        confidence=confidence,
        provenance=CandidateProvenance(decoder=decoder, offset=0, length=len(content)),
    )


def test_engine_mixed_input_extracts_iocs_and_commands() -> None:
    decoder = _StaticDecoder(
        _name="mixed",
        _candidates=[
            _candidate(
                b"contact https://evil.test/p and 8.8.8.8 then cmd.exe /c whoami",
                decoder="mixed",
            )
        ],
    )
    engine = DeobfuscationEngine(
        decoders=[decoder],
        max_candidates=10,
        per_decoder_limit=10,
        confidence_threshold=0.0,
        max_wall_time_seconds=10.0,
    )

    result = engine.run(b"ignored")

    assert result.iocs["urls"] == ["https://evil.test/p"]
    assert result.iocs["domains"] == ["evil.test"]
    assert result.iocs["ips"] == ["8.8.8.8"]
    assert any(command.startswith("cmd.exe /c whoami") for command in result.iocs["commands"])


def test_engine_respects_global_candidate_cap_and_marks_truncation() -> None:
    decoder = _StaticDecoder(
        _name="cap-test",
        _candidates=[
            _candidate(b"one", decoder="cap-test"),
            _candidate(b"two", decoder="cap-test"),
            _candidate(b"three", decoder="cap-test"),
        ],
    )
    engine = DeobfuscationEngine(
        decoders=[decoder],
        max_candidates=2,
        per_decoder_limit=10,
        confidence_threshold=0.0,
        max_wall_time_seconds=10.0,
    )

    result = engine.run(b"ignored")

    assert len(result.candidates) == 2
    assert result.candidates[-1].truncated is True
    assert result.stats.candidate_cap_reached is True
    assert result.stats.truncated is True
    assert result.stats.stop_reason == "candidate_cap"


def test_engine_applies_confidence_threshold() -> None:
    decoder = _StaticDecoder(
        _name="threshold-test",
        _candidates=[
            _candidate(b"low", decoder="threshold-test", confidence=0.2),
            _candidate(b"high", decoder="threshold-test", confidence=0.9),
        ],
    )
    engine = DeobfuscationEngine(
        decoders=[decoder],
        max_candidates=10,
        per_decoder_limit=10,
        confidence_threshold=0.5,
        max_wall_time_seconds=10.0,
    )

    result = engine.run(b"ignored")

    assert [candidate.content for candidate in result.candidates] == [b"high"]
    assert result.stats.filtered_low_confidence_count == 1


@pytest.mark.parametrize(
    "invalid_wall_time",
    [float("nan"), float("inf"), -0.1],
)
def test_engine_rejects_invalid_max_wall_time_seconds(invalid_wall_time: float) -> None:
    with pytest.raises(ValueError):
        DeobfuscationEngine(
            decoders=[],
            max_candidates=10,
            per_decoder_limit=10,
            confidence_threshold=0.0,
            max_wall_time_seconds=invalid_wall_time,
        )


def test_engine_with_zero_max_candidates_returns_empty_and_truncated() -> None:
    decoder = _StaticDecoder(
        _name="zero-cap",
        _candidates=[
            _candidate(b"one", decoder="zero-cap"),
        ],
    )
    engine = DeobfuscationEngine(
        decoders=[decoder],
        max_candidates=0,
        per_decoder_limit=10,
        confidence_threshold=0.0,
        max_wall_time_seconds=10.0,
    )

    result = engine.run(b"ignored")

    assert result.candidates == []
    assert result.stats.raw_candidate_count == 0
    assert result.stats.candidate_cap_reached is True
    assert result.stats.stop_reason == "candidate_cap"
    assert result.stats.truncated is True


def test_engine_dedupes_same_content_to_highest_confidence() -> None:
    decoder = _StaticDecoder(
        _name="dedupe",
        _candidates=[
            _candidate(b"same", decoder="dedupe", confidence=0.2),
            _candidate(b"same", decoder="dedupe", confidence=0.9),
            _candidate(b"other", decoder="dedupe", confidence=0.3),
        ],
    )
    engine = DeobfuscationEngine(
        decoders=[decoder],
        max_candidates=10,
        per_decoder_limit=10,
        confidence_threshold=0.0,
        max_wall_time_seconds=10.0,
    )

    result = engine.run(b"ignored")

    assert [candidate.content for candidate in result.candidates] == [b"same", b"other"]
    assert result.candidates[0].confidence == 0.9


def test_engine_marks_final_emitted_candidate_truncated_after_filtering() -> None:
    decoder = _StaticDecoder(
        _name="truncate-after-filter",
        _candidates=[
            _candidate(b"kept", decoder="truncate-after-filter", confidence=0.9),
            _candidate(b"filtered", decoder="truncate-after-filter", confidence=0.1),
            _candidate(b"over-cap", decoder="truncate-after-filter", confidence=0.95),
        ],
    )
    engine = DeobfuscationEngine(
        decoders=[decoder],
        max_candidates=2,
        per_decoder_limit=10,
        confidence_threshold=0.5,
        max_wall_time_seconds=10.0,
    )

    result = engine.run(b"ignored")

    assert [candidate.content for candidate in result.candidates] == [b"kept"]
    assert result.candidates[-1].truncated is True
    assert result.stats.candidate_cap_reached is True
    assert result.stats.truncated is True


def test_engine_wall_time_stop_sets_wall_time_stats(monkeypatch: pytest.MonkeyPatch) -> None:
    decoder = _StaticDecoder(
        _name="wall-time-stop",
        _candidates=[
            _candidate(b"one", decoder="wall-time-stop"),
            _candidate(b"two", decoder="wall-time-stop"),
        ],
    )
    timeline = iter([100.0, 100.25, 101.5])

    from malscan_worker.deobfuscation import engine as engine_module

    real_guard = engine_module.DeobfuscationSafetyGuard

    def _guard_factory(
        *, max_candidates: int, max_wall_time_seconds: float
    ) -> DeobfuscationSafetyGuard:
        return real_guard(
            max_candidates=max_candidates,
            max_wall_time_seconds=max_wall_time_seconds,
            now_fn=lambda: next(timeline),
        )

    monkeypatch.setattr(engine_module, "DeobfuscationSafetyGuard", _guard_factory)

    engine = DeobfuscationEngine(
        decoders=[decoder],
        max_candidates=10,
        per_decoder_limit=10,
        confidence_threshold=0.0,
        max_wall_time_seconds=1.0,
    )

    result = engine.run(b"ignored")

    assert result.stats.wall_time_reached is True
    assert result.stats.stop_reason == "wall_time"
    assert result.stats.truncated is True
