"""Safety guard primitives for deobfuscation runtime constraints."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Callable, Literal


@dataclass
class DeobfuscationSafetyGuard:
    """Track caps that can stop candidate discovery early."""

    max_candidates: int
    max_wall_time_seconds: float
    now_fn: Callable[[], float] = time.monotonic
    candidate_count: int = 0
    stop_reason: Literal["candidate_cap", "wall_time"] | None = field(default=None, init=False)
    _started_at: float = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.max_candidates < 0:
            raise ValueError("max_candidates must be >= 0")
        if self.max_wall_time_seconds < 0 or not math.isfinite(self.max_wall_time_seconds):
            raise ValueError("max_wall_time_seconds must be finite and >= 0")
        self._started_at = self.now_fn()

    def try_register_candidate(self) -> bool:
        """Register a candidate and return whether processing may continue."""
        if self.should_stop():
            return False

        self.candidate_count += 1
        if self.candidate_count > self.max_candidates:
            self.stop_reason = "candidate_cap"
            return False
        return True

    def should_stop(self) -> bool:
        """Return True once a stop condition is met."""
        if self.stop_reason is not None:
            return True

        elapsed = self.now_fn() - self._started_at
        if elapsed > self.max_wall_time_seconds:
            self.stop_reason = "wall_time"
            return True
        return False
