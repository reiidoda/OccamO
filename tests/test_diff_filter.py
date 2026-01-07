from __future__ import annotations

from pathlib import Path

from occamo.analyze.static_ast import FunctionFinding, StaticSignals
from occamo.cli import _filter_findings_by_changed_lines


def test_filter_findings_by_changed_lines(tmp_path: Path) -> None:
    file_path = tmp_path / "a.py"
    changed = {file_path.resolve(): [(5, 6)]}

    findings = [
        FunctionFinding(
            file="a.py",
            qualname="f",
            lineno=1,
            end_lineno=3,
            signals=StaticSignals(loops=0, max_loop_depth=0, recursion=False, sort_calls=0, comprehension=0),
            complexity_hint="O(1) / O(log n) candidate",
            confidence=0.4,
            body_hash="hash-f",
            function_id="id-f",
        ),
        FunctionFinding(
            file="a.py",
            qualname="g",
            lineno=5,
            end_lineno=7,
            signals=StaticSignals(loops=1, max_loop_depth=1, recursion=False, sort_calls=0, comprehension=0),
            complexity_hint="O(n) candidate",
            confidence=0.6,
            body_hash="hash-g",
            function_id="id-g",
        ),
    ]

    filtered = _filter_findings_by_changed_lines(tmp_path, findings, changed)
    assert [f.qualname for f in filtered] == ["g"]
