from __future__ import annotations

from occamo.report.format_snippets import to_snippets_markdown
from occamo.report.models import SCHEMA_VERSION, FindingReport, OccamOReport


def test_snippets_render_nested_loop() -> None:
    report = OccamOReport(
        schema_version=SCHEMA_VERSION,
        generated_at="2024-01-01T00:00:00Z",
        repo_root=".",
        changed_only=False,
        base_ref="origin/main",
        regression_mode=False,
        findings=[
            FindingReport(
                file="src/app.py",
                qualname="f",
                function_id="id-f",
                lineno=1,
                end_lineno=2,
                severity="high",
                complexity_hint="O(n^2) candidate",
                confidence=0.7,
                risk_score=2.2,
                signals={
                    "loops": 2,
                    "max_loop_depth": 2,
                    "recursion": False,
                    "sort_calls": 0,
                    "comprehension": 0,
                },
                body_hash="hash",
                explanation="Nested loops detected.",
            )
        ],
        regressions=[],
    )
    text = to_snippets_markdown(report, top_n=1)
    assert "quick fix snippets" in text
    assert "Avoid nested loops" in text or "Snippet" in text
    assert "```python" in text
