from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from occamo.analyze.identity import hash_text, stable_function_id
from occamo.analyze.scoring import hint_from_signals
from occamo.analyze.signals import StaticSignals
from occamo.analyze.suppression_utils import SuppressionMeta, suppression_map
from occamo.report.models import Suppression


@dataclass(frozen=True)
class FunctionFinding:
    file: str
    qualname: str
    lineno: int
    end_lineno: int
    signals: StaticSignals
    complexity_hint: str
    confidence: float
    body_hash: str
    function_id: str


class _Visitor(ast.NodeVisitor):
    def __init__(self, class_names: list[str] | None = None) -> None:
        self.loop_depth = 0
        self.max_loop_depth = 0
        self.loops = 0
        self.sort_calls = 0
        self.comprehension = 0
        self.func_name_stack: list[str] = []
        self.recursion = False
        self._class_names = {name for name in (class_names or []) if name}

    def visit_For(self, node: ast.For) -> None:
        self.loops += 1
        self.loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self.loop_depth)
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        self.loops += 1
        self.loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self.loop_depth)
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.loops += 1
        self.loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self.loop_depth)
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Detect .sort() and sorted(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "sort":
            self.sort_calls += 1
        elif isinstance(node.func, ast.Name) and node.func.id == "sorted":
            self.sort_calls += 1

        # Very simple recursion detection: function calls itself by name in same scope.
        if self.func_name_stack:
            current = self.func_name_stack[-1]
            if isinstance(node.func, ast.Name) and node.func.id == current:
                self.recursion = True
            elif isinstance(node.func, ast.Attribute) and node.func.attr == current:
                if isinstance(node.func.value, ast.Name):
                    base = node.func.value.id
                    if base in {"self", "cls"} or base in self._class_names:
                        self.recursion = True

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self.func_name_stack:
            # Nested defs are analyzed separately; don't inflate parent signals.
            return
        self.func_name_stack.append(node.name)
        self.generic_visit(node)
        self.func_name_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if self.func_name_stack:
            # Nested defs are analyzed separately; don't inflate parent signals.
            return
        self.func_name_stack.append(node.name)
        self.generic_visit(node)
        self.func_name_stack.pop()

    def _visit_comprehension(self, node: ast.AST) -> None:
        self.comprehension += 1
        gen_count = len(getattr(node, "generators", []))
        if gen_count:
            self.loops += gen_count
            self.loop_depth += gen_count
            self.max_loop_depth = max(self.max_loop_depth, self.loop_depth)
        self.generic_visit(node)
        if gen_count:
            self.loop_depth -= gen_count


class _FunctionCollector(ast.NodeVisitor):
    def __init__(
        self,
        path: Path,
        suppressed_lines: dict[int, SuppressionMeta] | None = None,
    ) -> None:
        self._path = path
        self._stack: list[str] = []
        self.findings: list[FunctionFinding] = []
        self.suppressions: list[Suppression] = []
        self._suppressed_lines = suppressed_lines or {}

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._collect(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._collect(node)

    def _collect(self, node: ast.AST) -> None:
        name = getattr(node, "name", "<lambda>")
        self._stack.append(str(name))
        lineno = int(getattr(node, "lineno", 1))
        if lineno in self._suppressed_lines:
            info = self._suppressed_lines[lineno]
            body_hash = _body_hash(node)
            qualname = ".".join(self._stack)
            function_id = stable_function_id(str(self._path), qualname, body_hash)
            self.suppressions.append(
                Suppression(
                    file=str(self._path),
                    qualname=qualname,
                    function_id=function_id,
                    lineno=lineno,
                    end_lineno=int(getattr(node, "end_lineno", lineno)),
                    comment_line=info.comment_line,
                    reason=info.reason,
                    ticket=info.ticket,
                    comment=info.comment,
                )
            )
            self.generic_visit(node)
            self._stack.pop()
            return
        class_names = [self._stack[-2]] if len(self._stack) >= 2 else []
        v = _Visitor(class_names=class_names)
        v.visit(node)
        signals = StaticSignals(
            loops=v.loops,
            max_loop_depth=v.max_loop_depth,
            recursion=v.recursion,
            sort_calls=v.sort_calls,
            comprehension=v.comprehension,
        )
        hint, conf = _hint(signals)
        body_hash = _body_hash(node)
        qualname = ".".join(self._stack)
        function_id = stable_function_id(str(self._path), qualname, body_hash)
        self.findings.append(
            FunctionFinding(
                file=str(self._path),
                qualname=qualname,
                lineno=int(getattr(node, "lineno", 1)),
                end_lineno=int(getattr(node, "end_lineno", getattr(node, "lineno", 1))),
                signals=signals,
                complexity_hint=hint,
                confidence=conf,
                body_hash=body_hash,
                function_id=function_id,
            )
        )
        self.generic_visit(node)
        self._stack.pop()


def _hint(signals: StaticSignals) -> tuple[str, float]:
    return hint_from_signals(signals)


def _normalized_body(node: ast.AST) -> str:
    body = list(getattr(node, "body", []))
    if body:
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant):
            if isinstance(getattr(first.value, "value", None), str):
                body = body[1:]
    module = ast.Module(body=body, type_ignores=[])
    return ast.dump(module, include_attributes=False)


def _body_hash(node: ast.AST) -> str:
    return hash_text(_normalized_body(node))


def _suppressed_def_lines(src: str) -> dict[int, SuppressionMeta]:
    return suppression_map(src)


def analyze_source(path: Path, src: str) -> list[FunctionFinding]:
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return []

    suppressed_lines = _suppressed_def_lines(src)
    collector = _FunctionCollector(path, suppressed_lines=suppressed_lines)
    collector.visit(tree)
    return collector.findings


def collect_suppressions(path: Path, src: str) -> list[Suppression]:
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return []
    suppressed_lines = _suppressed_def_lines(src)
    collector = _FunctionCollector(path, suppressed_lines=suppressed_lines)
    collector.visit(tree)
    return collector.suppressions


def analyze_file(path: Path) -> list[FunctionFinding]:
    try:
        src = path.read_text(encoding="utf-8")
    except Exception:
        return []

    return analyze_source(path, src)
