from __future__ import annotations

from occamo.cli import _evaluate_finding_gating
from occamo.report.models import SCHEMA_VERSION, FindingReport, OccamOReport


def _report_with_finding() -> OccamOReport:
    return OccamOReport(
        schema_version=SCHEMA_VERSION,
        generated_at="2024-01-01T00:00:00Z",
        repo_root=".",
        changed_only=True,
        base_ref="origin/main",
        regression_mode=False,
        findings=[
            FindingReport(
                file="src/a.py",
                qualname="f",
                function_id="id-f",
                lineno=1,
                end_lineno=2,
                severity="high",
                complexity_hint="O(n^2) candidate",
                confidence=0.8,
                risk_score=2.5,
                signals={},
                body_hash="hash-f",
            )
        ],
        regressions=[],
    )


def test_findings_gating_severity() -> None:
    report = _report_with_finding()
    exit_code, reasons = _evaluate_finding_gating(report, None, "medium", None)
    assert exit_code == 1
    assert any("severity" in reason for reason in reasons)


def test_findings_gating_max_risk() -> None:
    report = _report_with_finding()
    exit_code, reasons = _evaluate_finding_gating(report, None, None, 1.0)
    assert exit_code == 1
    assert any("max risk_score" in reason for reason in reasons)
