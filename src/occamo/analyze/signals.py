from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StaticSignals:
    loops: int
    max_loop_depth: int
    recursion: bool
    sort_calls: int
    comprehension: int

    @property
    def risk_score(self) -> float:
        # Simple interpretable score. Tune over time with real repo feedback.
        score = 0.0
        score += self.loops * 0.4
        score += max(0, self.max_loop_depth - 1) * 0.8
        score += self.sort_calls * 0.5
        score += self.comprehension * 0.2
        if self.recursion:
            score += 1.2
        return round(score, 3)
