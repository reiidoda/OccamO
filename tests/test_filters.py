from __future__ import annotations

from occamo.cli import _filter_findings
from occamo.report.models import FindingReport


def test_filter_findings_by_severity_and_score() -> None:
    findings = [
        FindingReport(
            file="a.py",
            qualname="f",
            function_id="id-f",
            lineno=1,
            end_lineno=2,
            severity="info",
            complexity_hint="O(1) / O(log n) candidate",
            confidence=0.4,
            risk_score=0.2,
            signals={},
            body_hash="hash-f",
        ),
        FindingReport(
            file="b.py",
            qualname="g",
            function_id="id-g",
            lineno=2,
            end_lineno=3,
            severity="high",
            complexity_hint="O(n^2) candidate",
            confidence=0.7,
            risk_score=2.5,
            signals={},
            body_hash="hash-g",
        ),
    ]

    filtered = _filter_findings(findings, 1.0, "medium", None, lambda _p: True)
    assert len(filtered) == 1
    assert filtered[0].qualname == "g"
