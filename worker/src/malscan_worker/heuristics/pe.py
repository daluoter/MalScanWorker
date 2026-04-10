"""PE-specific heuristic synthesis."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from malscan_worker.heuristics.common import evaluate_entropy_regions
from malscan_worker.heuristics.models import HeuristicHit, make_hit

_INJECTION_APIS = frozenset({"createremotethread", "virtualallocex", "writeprocessmemory"})
_SPARSE_IMPORT_DLL_THRESHOLD = 1
_SPARSE_IMPORT_SYMBOL_THRESHOLD = 9
_OVERLAY_ANOMALY_MIN_SIZE = 1024


def build_pe_heuristics(features: Mapping[str, object]) -> list[HeuristicHit]:
    """Build deterministic PE heuristics from extracted features."""

    heuristics: list[HeuristicHit] = []

    sections = _as_mapping_list(features.get("sections"))
    imports = _as_mapping_list(features.get("imports"))
    packer_clues = _as_mapping_list(features.get("packer_clues"))
    overlay = features.get("overlay") if isinstance(features.get("overlay"), Mapping) else {}

    entropy_hits = evaluate_entropy_regions(scope="pe", regions=sections)
    heuristics.extend(entropy_hits)
    high_entropy_regions = _extract_entropy_regions(entropy_hits)
    entropy_cluster_present = bool(high_entropy_regions)

    known_section_names = _normalize_packer_section_names(packer_clues)
    if known_section_names:
        heuristics.append(
            make_hit(
                key="packer.known_section_name",
                category="structure",
                scope="pe",
                role="signal",
                severity="medium",
                confidence=0.78,
                summary="Known packer section names were detected",
                evidence={"section_names": known_section_names},
                tags=("packer", "sections"),
            )
        )

    imported_symbols = _extract_imported_functions(imports)
    sparse_imports = (
        len(imports) <= _SPARSE_IMPORT_DLL_THRESHOLD
        or len(imported_symbols) <= _SPARSE_IMPORT_SYMBOL_THRESHOLD
    )
    if sparse_imports and entropy_cluster_present:
        heuristics.append(
            make_hit(
                key="packer.sparse_imports_high_entropy",
                category="structure",
                scope="pe",
                role="detection",
                severity="medium",
                confidence=0.81,
                summary="Sparse imports combined with high-entropy sections suggest packing",
                evidence={
                    "import_dll_count": len(imports),
                    "import_symbol_count": len(imported_symbols),
                    "entropy_regions": high_entropy_regions,
                },
                tags=("packer", "entropy", "imports"),
            )
        )

    matched_injection_apis = tuple(sorted(imported_symbols & _INJECTION_APIS))
    if len(matched_injection_apis) >= 3:
        heuristics.append(
            make_hit(
                key="api.process_injection_cluster",
                category="behavior",
                scope="pe",
                role="detection",
                severity="high",
                confidence=0.86,
                summary="Process injection API cluster detected in imports",
                evidence={"apis": list(matched_injection_apis)},
                tags=("api", "injection", "imports"),
            )
        )

    overlay_size = overlay.get("size") if isinstance(overlay, Mapping) else None
    overlay_present = bool(overlay.get("present")) if isinstance(overlay, Mapping) else False
    if (
        overlay_present
        and isinstance(overlay_size, int)
        and overlay_size >= _OVERLAY_ANOMALY_MIN_SIZE
    ):
        heuristics.append(
            make_hit(
                key="structure.overlay_anomaly",
                category="structure",
                scope="pe",
                role="signal",
                severity="medium",
                confidence=0.7,
                summary="Large PE overlay data is present",
                evidence={
                    "size": overlay_size,
                    "offset": overlay.get("offset"),
                    "file_size": overlay.get("file_size"),
                },
                tags=("overlay", "structure"),
            )
        )

    return heuristics


def _as_mapping_list(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _extract_imported_functions(imports: Sequence[Mapping[str, object]]) -> set[str]:
    functions: set[str] = set()
    for entry in imports:
        raw_functions = entry.get("functions")
        if not isinstance(raw_functions, Sequence) or isinstance(raw_functions, str | bytes):
            continue
        for function_name in raw_functions:
            if isinstance(function_name, str):
                functions.add(function_name.lower())
    return functions


def _extract_entropy_regions(
    entropy_hits: Sequence[HeuristicHit],
) -> tuple[Mapping[str, object], ...]:
    for hit in entropy_hits:
        if hit.key != "entropy.high_region_cluster":
            continue
        regions = hit.evidence.get("regions")
        if isinstance(regions, tuple):
            return tuple(region for region in regions if isinstance(region, Mapping))
    return ()


def _normalize_packer_section_names(
    packer_clues: Sequence[Mapping[str, object]],
) -> tuple[str, ...]:
    names = {
        str(clue.get("value", "")).strip().lower()
        for clue in packer_clues
        if str(clue.get("type", "")) == "section_name" and str(clue.get("value", "")).strip()
    }
    return tuple(sorted(names))


__all__ = ["build_pe_heuristics"]
