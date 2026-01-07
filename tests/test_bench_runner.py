from __future__ import annotations

from occamo.bench.runner import _compare_results


def test_compare_results_detects_regression() -> None:
    baseline = {"cases": [{"name": "small", "seconds": 1.0}]}
    current = {"cases": [{"name": "small", "seconds": 1.2}]}
    errors = _compare_results(baseline, current, max_regression=0.1)
    assert errors


def test_compare_results_allows_improvement() -> None:
    baseline = {"cases": [{"name": "small", "seconds": 1.0}]}
    current = {"cases": [{"name": "small", "seconds": 0.9}]}
    errors = _compare_results(baseline, current, max_regression=0.1)
    assert not errors
