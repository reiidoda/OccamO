from __future__ import annotations

from occamo.report.format_comment import to_comment_markdown
from occamo.report.models import SCHEMA_VERSION, FindingReport, OccamOReport, RegressionFinding


def test_comment_prefers_regressions() -> None:
    report = OccamOReport(
        schema_version=SCHEMA_VERSION,
        generated_at="2024-01-01T00:00:00Z",
        repo_root=".",
        changed_only=True,
        base_ref="origin/main",
        regression_mode=True,
        findings=[
            FindingReport(
                file="a.py",
                qualname="f",
                function_id="id-f",
                lineno=1,
                end_lineno=2,
                severity="medium",
                complexity_hint="O(n) candidate",
                confidence=0.6,
                risk_score=1.2,
                signals={},
                body_hash="hash-f",
            )
        ],
        regressions=[
            RegressionFinding(
                file="a.py",
                qualname="f",
                function_id="id-f",
                lineno=1,
                base_risk_score=0.4,
                head_risk_score=1.2,
                base_hint="O(1) / O(log n) candidate",
                head_hint="O(n) candidate",
                risk_delta=0.8,
                hint_delta=1,
                regression_severity="medium",
                explanation="Loop depth increased 0 -> 1.",
                suggestions=["Reduce nested loops by precomputing lookups or indexing with dict/set."],
                base_signals={
                    "loops": 0,
                    "max_loop_depth": 0,
                    "recursion": False,
                    "sort_calls": 0,
                    "comprehension": 0,
                },
                head_signals={
                    "loops": 1,
                    "max_loop_depth": 1,
                    "recursion": False,
                    "sort_calls": 0,
                    "comprehension": 0,
                },
            )
        ],
    )

    text = to_comment_markdown(report, top_n=5)
    assert "<!-- occamo-comment -->" in text
    assert "Regressions" in text
    assert "Risk" in text


def test_comment_handles_empty_findings() -> None:
    report = OccamOReport(
        schema_version=SCHEMA_VERSION,
        generated_at="2024-01-01T00:00:00Z",
        repo_root=".",
        changed_only=True,
        base_ref="origin/main",
        regression_mode=False,
        findings=[],
        regressions=[],
    )

    text = to_comment_markdown(report, top_n=5)
    assert "<!-- occamo-comment -->" in text
    assert "No findings" in text
