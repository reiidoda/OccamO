from __future__ import annotations

from pathlib import Path

from occamo.report.format_json import read_json, write_json
from occamo.report.models import (
    SCHEMA_VERSION,
    ChangeFinding,
    DynamicCheck,
    DynamicRegression,
    FindingReport,
    OccamOReport,
    RegressionFinding,
    ReportStats,
    Suppression,
)


def test_json_roundtrip(tmp_path: Path) -> None:
    report = OccamOReport(
        schema_version=SCHEMA_VERSION,
        generated_at="2024-01-01T00:00:00Z",
        repo_root=str(tmp_path),
        changed_only=False,
        base_ref="origin/main",
        regression_mode=True,
        findings=[
            FindingReport(
                file="src/a.py",
                qualname="f",
                function_id="id-f",
                lineno=3,
                end_lineno=5,
                severity="high",
                complexity_hint="O(n^2) candidate",
                confidence=0.75,
                risk_score=2.4,
                signals={
                    "loops": 2,
                    "max_loop_depth": 2,
                    "recursion": False,
                    "sort_calls": 0,
                    "comprehension": 0,
                },
                body_hash="hash-f",
                explanation="Nested loops detected.",
                suggestions=["Consider pre-indexing or batching to avoid nested iteration."],
                rule_id="",
                rule_name="",
                dynamic=DynamicCheck(
                    label="O(n) candidate",
                    confidence=0.72,
                    status="downgraded",
                    note="",
                ),
            )
        ],
        regressions=[
            RegressionFinding(
                file="src/a.py",
                qualname="f",
                function_id="id-f",
                lineno=3,
                base_risk_score=1.2,
                head_risk_score=2.4,
                base_hint="O(n) candidate",
                head_hint="O(n^2) candidate",
                risk_delta=1.2,
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
                dynamic=DynamicRegression(
                    status="confirmed",
                    ratio=1.35,
                    note="ratio 1.35, base=O(n), head=O(n^2)",
                ),
            )
        ],
        diffs=[
            ChangeFinding(
                file="src/a.py",
                qualname="f",
                function_id="id-f",
                lineno=3,
                change_type="changed",
                trend="worse",
                base_risk_score=1.2,
                head_risk_score=2.4,
                base_hint="O(n) candidate",
                head_hint="O(n^2) candidate",
                risk_delta=1.2,
                hint_delta=1,
                regression_severity="high",
            )
        ],
        suppressions=[
            Suppression(
                file="src/a.py",
                qualname="f",
                function_id="id-f",
                lineno=3,
                end_lineno=5,
                comment_line=1,
                reason="legacy",
                ticket="ABC-123",
                comment="# occamo: ignore reason=\"legacy\" ticket=\"ABC-123\"",
            )
        ],
        stats=ReportStats(
            findings_total=1,
            regressions_total=1,
            severity_counts={"high": 1},
            hint_counts={"O(n^2) candidate": 1},
            max_risk_score=2.4,
            avg_risk_score=2.4,
            max_regression_delta=1.2,
        ),
    )

    path = tmp_path / "occamo.json"
    write_json(report, path)
    loaded = read_json(path)

    assert loaded.schema_version == SCHEMA_VERSION
    assert loaded.findings[0].severity == "high"
    assert loaded.regressions[0].hint_delta == 1
    assert loaded.findings[0].dynamic is not None
    assert loaded.findings[0].dynamic.status == "downgraded"
    assert loaded.regressions[0].dynamic is not None
    assert loaded.regressions[0].dynamic.status == "confirmed"
    assert loaded.diffs
    assert loaded.suppressions
    assert loaded.suppressions[0].reason == "legacy"
    assert loaded.stats is not None
    assert loaded.stats.findings_total == 1
