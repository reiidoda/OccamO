from __future__ import annotations

from pathlib import Path

from occamo.analyze.regression import find_regressions
from occamo.analyze.static_ast import analyze_source


def test_detects_regression_by_hint_and_risk(tmp_path: Path) -> None:
    path = tmp_path / "x.py"
    base_src = "def f(xs):\n    for x in xs:\n        pass\n"
    head_src = "def f(xs):\n    for x in xs:\n        for y in xs:\n            pass\n"

    base_findings = analyze_source(path, base_src)
    head_findings = analyze_source(path, head_src)

    regressions = find_regressions(head_findings, base_findings)
    assert len(regressions) == 1
    reg = regressions[0]
    assert reg.risk_delta > 0
    assert reg.hint_delta is not None and reg.hint_delta > 0


def test_new_function_is_not_regression(tmp_path: Path) -> None:
    path = tmp_path / "y.py"
    base_findings = analyze_source(path, "def g():\n    return 1\n")
    head_findings = analyze_source(path, "def f(xs):\n    for x in xs:\n        pass\n")

    regressions = find_regressions(head_findings, base_findings)
    assert regressions == []
