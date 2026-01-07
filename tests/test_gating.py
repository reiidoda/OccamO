from __future__ import annotations

from pathlib import Path

from occamo.cli import _evaluate_gating
from occamo.report.models import SCHEMA_VERSION, OccamOReport, RegressionFinding


def _report_with_regression() -> OccamOReport:
    return OccamOReport(
        schema_version=SCHEMA_VERSION,
        generated_at="2024-01-01T00:00:00Z",
        repo_root=".",
        changed_only=True,
        base_ref="origin/main",
        regression_mode=True,
        findings=[],
        regressions=[
            RegressionFinding(
                file="src/a.py",
                qualname="f",
                function_id="id-f",
                lineno=3,
                base_risk_score=1.0,
                head_risk_score=2.0,
                base_hint="O(n) candidate",
                head_hint="O(n^2) candidate",
                risk_delta=1.0,
                hint_delta=1,
                regression_severity="high",
                explanation="Loop depth increased 1 -> 2.",
                suggestions=["Reduce nested loops by precomputing lookups or indexing with dict/set."],
                base_signals={
                    "loops": 1,
                    "max_loop_depth": 1,
                    "recursion": False,
                    "sort_calls": 0,
                    "comprehension": 0,
                },
                head_signals={
                    "loops": 2,
                    "max_loop_depth": 2,
                    "recursion": False,
                    "sort_calls": 0,
                    "comprehension": 0,
                },
            )
        ],
    )


def test_gating_fail_on_regressions() -> None:
    report = _report_with_regression()
    exit_code, reasons = _evaluate_gating(
        report,
        True,
        True,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        [],
        [],
        Path("."),
        [],
    )
    assert exit_code == 1
    assert reasons


def test_gating_risk_delta_threshold() -> None:
    report = _report_with_regression()
    exit_code, reasons = _evaluate_gating(
        report,
        True,
        False,
        None,
        None,
        None,
        0.5,
        None,
        None,
        None,
        [],
        [],
        Path("."),
        [],
    )
    assert exit_code == 1
    assert any("max risk_delta" in reason for reason in reasons)


def test_gating_fail_on_severity() -> None:
    report = _report_with_regression()
    exit_code, reasons = _evaluate_gating(
        report,
        True,
        False,
        "low",
        None,
        None,
        None,
        None,
        None,
        None,
        [],
        [],
        Path("."),
        [],
    )
    assert exit_code == 1
    assert any("severity" in reason for reason in reasons)
