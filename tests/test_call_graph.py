from __future__ import annotations

from pathlib import Path

from occamo.analyze.call_graph import build_call_graph
from occamo.analyze.static_ast import analyze_source
from occamo.ir.registry import build_ir_modules


def test_call_graph_adds_loop_notes() -> None:
    src = """
def helper(items):
    for i in items:
        for j in items:
            _ = i, j

def f(items):
    for item in items:
        helper(items)
"""
    path = Path("src/app.py")
    findings = analyze_source(path, src)
    modules = build_ir_modules(Path("."), {str(path): src}, findings)
    summary = build_call_graph(findings, modules, passes=2)
    by_name = {f.qualname: f.function_id for f in findings}
    caller_id = by_name["f"]
    assert caller_id in summary.notes
    assert any("Calls" in note for note in summary.notes[caller_id])
