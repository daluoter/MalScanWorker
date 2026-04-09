"""Regression tests for IOC recall with deobfuscation fixture corpus."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from malscan_worker.deobfuscation.decoders import (
    Base64Decoder,
    HexDecoder,
    JsDecoder,
    PowerShellDecoder,
    UrlReassemblyDecoder,
    XorDecoder,
)
from malscan_worker.deobfuscation.engine import DeobfuscationEngine
from malscan_worker.stages.ioc_extract import extract_raw_iocs


def _extract_deobfuscated_iocs(content: bytes) -> dict[str, set[str]]:
    engine = DeobfuscationEngine(
        decoders=[
            Base64Decoder(min_decoded_length=8),
            HexDecoder(min_decoded_length=8),
            PowerShellDecoder(),
            JsDecoder(),
            UrlReassemblyDecoder(),
            XorDecoder(min_decoded_length=8),
        ],
        max_candidates=100,
        per_decoder_limit=25,
        confidence_threshold=0.0,
        max_wall_time_seconds=10.0,
    )
    engine_result = engine.run(content)
    assert not engine_result.stats.truncated
    iocs = engine_result.iocs
    return {
        "urls": set(iocs.get("urls", [])),
        "domains": set(iocs.get("domains", [])),
        "ips": set(iocs.get("ips", [])),
    }


def _merge_iocs(
    raw_iocs: dict[str, set[str]],
    deob_iocs: dict[str, set[str]],
) -> dict[str, set[str]]:
    return {
        "urls": raw_iocs["urls"] | deob_iocs["urls"],
        "domains": raw_iocs["domains"] | deob_iocs["domains"],
        "ips": raw_iocs["ips"] | deob_iocs["ips"],
    }


def _recall(observed: dict[str, set[str]], truth: dict[str, set[str]]) -> float:
    truth_total = sum(len(values) for values in truth.values())
    if truth_total == 0:
        return 1.0
    true_positives = sum(len(observed[key] & truth[key]) for key in truth)
    return true_positives / truth_total


def _to_set_iocs(payload: dict[str, list[str]]) -> dict[str, set[str]]:
    return {
        "urls": set(payload["urls"]),
        "domains": set(payload["domains"]),
        "ips": set(payload["ips"]),
    }


@pytest.mark.parametrize(
    "fixture_name",
    [
        "base64_url.bin",
        "ps_enc_command.ps1",
        "js_fromcharcode.js",
        "clean_no_obfuscation.txt",
    ],
)
def test_fixture_expected_iocs_are_stable(fixture_name: str) -> None:
    fixture_dir = Path(__file__).parent / "fixtures" / "deobfuscation"
    fixture_path = fixture_dir / fixture_name
    expected_path = fixture_dir / f"{fixture_name}.expected.json"

    content = fixture_path.read_bytes()
    expected = json.loads(expected_path.read_text(encoding="utf-8"))

    raw_iocs = _to_set_iocs(extract_raw_iocs(content))
    combined_iocs = _merge_iocs(raw_iocs, _extract_deobfuscated_iocs(content))

    assert raw_iocs == _to_set_iocs(expected["expected_raw"])
    assert combined_iocs == _to_set_iocs(expected["expected_combined"])

    truth = _to_set_iocs(expected["truth"])
    raw_recall = _recall(raw_iocs, truth)
    combined_recall = _recall(combined_iocs, truth)

    if expected["expect_improvement"]:
        assert combined_recall > raw_recall
    else:
        if expected.get("strict_no_improvement", False):
            assert combined_recall == raw_recall
        else:
            assert combined_recall >= raw_recall


def test_recall_improves_for_raw_plus_deobfuscation_corpus_regression() -> None:
    fixture_dir = Path(__file__).parent / "fixtures" / "deobfuscation"
    expected_files = sorted(fixture_dir.glob("*.expected.json"))
    assert expected_files

    raw_hits = 0
    combined_hits = 0
    truth_total = 0

    for expected_file in expected_files:
        fixture_name = expected_file.name.removesuffix(".expected.json")
        content = (fixture_dir / fixture_name).read_bytes()
        expected = json.loads(expected_file.read_text(encoding="utf-8"))
        truth = _to_set_iocs(expected["truth"])

        raw_iocs = _to_set_iocs(extract_raw_iocs(content))
        combined_iocs = _merge_iocs(raw_iocs, _extract_deobfuscated_iocs(content))

        raw_hits += sum(len(raw_iocs[key] & truth[key]) for key in truth)
        combined_hits += sum(len(combined_iocs[key] & truth[key]) for key in truth)
        truth_total += sum(len(values) for values in truth.values())

    assert truth_total > 0
    assert combined_hits > raw_hits
