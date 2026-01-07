from __future__ import annotations

from pathlib import Path

from occamo.analyze.static_ast import analyze_source
from occamo.ir.registry import build_ir_modules
from occamo.rules.base import RuleContext
from occamo.rules.registry import run_rules


def _run_rules(src: str, path: str = "src/app.py"):
    findings = analyze_source(Path(path), src)
    sources = {path: src}
    ir_modules = build_ir_modules(Path("."), sources, findings)
    context = RuleContext(
        repo_root=Path("."),
        sources=sources,
        findings=findings,
        ir_modules=ir_modules,
        rule_config={},
    )
    return run_rules(context)


def test_db_in_loop_rule() -> None:
    src = """
class User:
    objects = None

def f(items):
    for item in items:
        User.objects.filter(id=item)
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "occamo.db-in-loop" for f in findings)


def test_json_in_loop_rule() -> None:
    src = """
import json

def f(items):
    for item in items:
        json.dumps(item)
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "occamo.json-in-loop" for f in findings)


def test_pandas_row_iteration_rule() -> None:
    src = """
def f(df):
    for row in df.iterrows():
        _ = row
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "occamo.pandas-iterrows" for f in findings)


def test_regex_catastrophe_rule() -> None:
    src = """
import re

def f(text):
    return re.compile("(a+)+").search(text)
"""
    findings = _run_rules(src)
    assert any(f.rule_id == "occamo.regex-catastrophic" for f in findings)
