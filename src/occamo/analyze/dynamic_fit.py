from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from occamo.util.math import simple_curve_fit


@dataclass(frozen=True)
class DynamicEstimate:
    label: str
    confidence: float
    note: str = ""


def estimate(sizes: Iterable[int], times: Iterable[float]) -> DynamicEstimate | None:
    fit = simple_curve_fit(sizes, times)
    if fit.label == "unknown":
        return None
    return DynamicEstimate(label=fit.label, confidence=fit.confidence)
