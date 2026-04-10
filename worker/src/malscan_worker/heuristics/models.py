"""Shared heuristic result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None
FrozenJsonValue: TypeAlias = (
    JsonScalar | tuple["FrozenJsonValue", ...] | MappingProxyType[str, "FrozenJsonValue"]
)
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


def _freeze_json(value: JsonValue) -> FrozenJsonValue:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})

    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)

    return value


@dataclass(frozen=True)
class HeuristicHit:
    """Stable structured heuristic finding emitted by analyzers."""

    key: str
    category: str
    scope: str
    role: str
    severity: str
    confidence: float
    summary: str
    evidence: FrozenJsonValue = field(default_factory=lambda: MappingProxyType({}))
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", _freeze_json(self.evidence))


def make_hit(
    *,
    key: str,
    category: str,
    scope: str,
    role: str,
    severity: str,
    confidence: float,
    summary: str,
    evidence: JsonValue = None,
    tags: tuple[str, ...] = (),
) -> HeuristicHit:
    """Build a shared heuristic hit object."""

    return HeuristicHit(
        key=key,
        category=category,
        scope=scope,
        role=role,
        severity=severity,
        confidence=confidence,
        summary=summary,
        evidence={} if evidence is None else evidence,
        tags=tags,
    )
