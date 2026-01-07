from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class FitResult:
    label: str
    confidence: float


def _clean_samples(sizes: Iterable[int], times: Iterable[float]) -> tuple[list[int], list[float]]:
    out_sizes: list[int] = []
    out_times: list[float] = []
    for size, time_value in zip(sizes, times, strict=False):
        try:
            n = int(size)
            t = float(time_value)
        except (TypeError, ValueError):
            continue
        if n <= 0 or t <= 0:
            continue
        out_sizes.append(n)
        out_times.append(t)
    return out_sizes, out_times


def simple_curve_fit(sizes: Iterable[int], times: Iterable[float]) -> FitResult:
    sizes_list, times_list = _clean_samples(sizes, times)
    if len(sizes_list) < 2:
        return FitResult(label="unknown", confidence=0.0)

    candidates = [
        ("O(1) / O(log n) candidate", lambda n: math.log(max(n, 2))),
        ("O(n) candidate", lambda n: float(n)),
        ("O(n log n) candidate", lambda n: n * math.log(max(n, 2))),
        ("O(n^2) candidate", lambda n: float(n * n)),
        ("O(n^3) or worse", lambda n: float(n * n * n)),
    ]

    mean_time = sum(times_list) / len(times_list)
    total = sum((t - mean_time) ** 2 for t in times_list) or 1e-9
    best_label = "unknown"
    best_error = float("inf")
    best_confidence = 0.0

    for label, func in candidates:
        xs = [func(n) for n in sizes_list]
        denom = sum(x * x for x in xs) or 1e-9
        scale = sum(x * t for x, t in zip(xs, times_list, strict=False)) / denom
        preds = [scale * x for x in xs]
        error = sum((t - p) ** 2 for t, p in zip(times_list, preds, strict=False))
        if error < best_error:
            best_error = error
            best_label = label
            r2 = 1.0 - (error / total)
            best_confidence = max(0.0, min(1.0, r2))

    return FitResult(label=best_label, confidence=best_confidence)
