from __future__ import annotations

from pathlib import Path

from occamo.analyze.static_ast import analyze_file


def test_detects_nested_loops(tmp_path: Path) -> None:
    p = tmp_path / "x.py"
    p.write_text(
        """
def f(xs):
    s = 0
    for x in xs:
        for y in xs:
            s += x*y
    return s
""",
        encoding="utf-8",
    )
    findings = analyze_file(p)
    assert findings
    f0 = findings[0]
    assert f0.signals.max_loop_depth == 2


def test_nested_function_body_not_counted_in_parent(tmp_path: Path) -> None:
    p = tmp_path / "x.py"
    p.write_text(
        """
def f(xs):
    def g(ys):
        for y in ys:
            pass
    for x in xs:
        pass
""",
        encoding="utf-8",
    )
    findings = analyze_file(p)
    by_name = {f.qualname: f for f in findings}
    assert "f" in by_name
    assert "f.g" in by_name
    assert by_name["f"].signals.loops == 1
    assert by_name["f"].signals.max_loop_depth == 1


def test_occamo_ignore_comment_skips_function(tmp_path: Path) -> None:
    p = tmp_path / "x.py"
    p.write_text(
        """
# occamo: ignore
def f(xs):
    for x in xs:
        pass

def g(xs):  # occamo: ignore
    for x in xs:
        pass

def h(xs):
    for x in xs:
        pass
""",
        encoding="utf-8",
    )
    findings = analyze_file(p)
    names = {f.qualname for f in findings}
    assert "f" not in names
    assert "g" not in names
    assert "h" in names


def test_async_for_counts_as_loop(tmp_path: Path) -> None:
    p = tmp_path / "x.py"
    p.write_text(
        """
async def f(xs):
    async for x in xs:
        pass
""",
        encoding="utf-8",
    )
    findings = analyze_file(p)
    assert findings
    f0 = findings[0]
    assert f0.signals.loops == 1
    assert f0.signals.max_loop_depth == 1


def test_comprehension_generators_count_as_nested_loops(tmp_path: Path) -> None:
    p = tmp_path / "x.py"
    p.write_text(
        """
def f(xs, ys):
    return [x+y for x in xs for y in ys]
""",
        encoding="utf-8",
    )
    findings = analyze_file(p)
    assert findings
    f0 = findings[0]
    assert f0.signals.loops == 2
    assert f0.signals.max_loop_depth == 2


def test_method_recursion_detected(tmp_path: Path) -> None:
    p = tmp_path / "x.py"
    p.write_text(
        """
class A:
    def f(self, xs):
        return self.f(xs)
""",
        encoding="utf-8",
    )
    findings = analyze_file(p)
    assert findings
    f0 = findings[0]
    assert f0.signals.recursion is True
