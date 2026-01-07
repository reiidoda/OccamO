from __future__ import annotations

from pathlib import Path

from occamo.analyze.hot_paths import compute_hotspots
from occamo.analyze.static_ast import analyze_source


def test_hot_paths_by_pattern() -> None:
    src = """
def f(items):
    for item in items:
        _ = item
"""
    path = Path("src/core/app.py")
    findings = analyze_source(path, src)
    hotspots = compute_hotspots(
        findings,
        hot_paths=["src/core/**"],
        hot_functions=[],
        hot_multiplier=2.0,
        profile_path=None,
        profile_top=10,
        trace_summary_path=None,
    )
    assert hotspots
    assert hotspots[0].weight == 2.0


def test_hot_functions_by_name() -> None:
    src = """
def alpha(items):
    for item in items:
        _ = item
"""
    path = Path("src/app.py")
    findings = analyze_source(path, src)
    hotspots = compute_hotspots(
        findings,
        hot_paths=[],
        hot_functions=["alpha"],
        hot_multiplier=1.5,
        profile_path=None,
        profile_top=10,
        trace_summary_path=None,
    )
    assert any(spot.note.startswith("hot path") for spot in hotspots)
