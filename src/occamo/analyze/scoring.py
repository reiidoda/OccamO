from __future__ import annotations

from occamo.analyze.signals import StaticSignals


def hint_from_signals(signals: StaticSignals) -> tuple[str, float]:
    # Convert signals to a human-friendly complexity hint + confidence.
    # This is heuristic, not a proof.
    if signals.recursion and signals.loops >= 1:
        return ("potentially exponential / high", 0.55)
    if signals.max_loop_depth >= 3:
        return ("O(n^3) or worse", 0.7)
    if signals.max_loop_depth == 2:
        return ("O(n^2) candidate", 0.75)
    if signals.sort_calls >= 1 and signals.loops >= 1:
        return ("O(n log n) + loop", 0.6)
    if signals.sort_calls >= 1:
        return ("O(n log n) candidate", 0.7)
    if signals.loops >= 1:
        return ("O(n) candidate", 0.65)
    return ("O(1) / O(log n) candidate", 0.4)
