from __future__ import annotations

from pathlib import Path

from occamo.report.format_trend import update_trend
from occamo.report.models import SCHEMA_VERSION, FindingReport, OccamOReport


def test_trend_update_writes_entry(tmp_path: Path) -> None:
    report = OccamOReport(
        schema_version=SCHEMA_VERSION,
        generated_at="2024-01-01T00:00:00Z",
        repo_root=str(tmp_path),
        changed_only=True,
        base_ref="origin/main",
        regression_mode=False,
        findings=[
            FindingReport(
                file="src/app.py",
                qualname="f",
                function_id="id-f",
                lineno=1,
                end_lineno=2,
                severity="low",
                complexity_hint="O(n) candidate",
                confidence=0.5,
                risk_score=0.9,
                signals={
                    "loops": 1,
                    "max_loop_depth": 1,
                    "recursion": False,
                    "sort_calls": 0,
                    "comprehension": 0,
                },
                body_hash="hash",
            )
        ],
        regressions=[],
    )
    path = tmp_path / "trend.json"
    data = update_trend(report, path)
    assert data["entries"]
    assert data["entries"][0]["max_risk_score"] == 0.9
