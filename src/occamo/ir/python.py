from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from occamo.analyze.static_ast import FunctionFinding
from occamo.ir.models import IRCall, IRFunction, IRModule


@dataclass
class _CallContext:
    qualname: str
    class_stack: list[str]


def _attr_chain(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [*(_attr_chain(node.value)), node.attr]
    return []


def _call_name(node: ast.Call, class_stack: list[str]) -> tuple[str | None, str | None, str | None]:
    if isinstance(node.func, ast.Name):
        name = node.func.id
        return name, name, None
    if isinstance(node.func, ast.Attribute):
        chain = _attr_chain(node.func)
        if not chain:
            return None, None, None
        name = chain[-1]
        obj_name = ".".join(chain[:-1]) if len(chain) > 1 else None
        qualname = None
        if chain[0] in {"self", "cls"} and class_stack:
            qualname = f"{class_stack[-1]}.{name}"
        elif chain[0] in class_stack:
            qualname = f"{chain[0]}.{name}"
        return name, qualname, obj_name
    return None, None, None


class _CallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self._name_stack: list[str] = []
        self._class_stack: list[str] = []
        self._func_stack: list[_CallContext] = []
        self._loop_depth = 0
        self.calls: defaultdict[str, list[IRCall]] = defaultdict(list)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._name_stack.append(node.name)
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()
        self._name_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter_function(node)

    def _enter_function(self, node: ast.AST) -> None:
        name = getattr(node, "name", "<lambda>")
        self._name_stack.append(str(name))
        qualname = ".".join(self._name_stack)
        self._func_stack.append(_CallContext(qualname=qualname, class_stack=list(self._class_stack)))
        self.generic_visit(node)
        self._func_stack.pop()
        self._name_stack.pop()

    def visit_For(self, node: ast.For) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if not self._func_stack:
            self.generic_visit(node)
            return
        ctx = self._func_stack[-1]
        name, qualname, obj_name = _call_name(node, ctx.class_stack)
        if name:
            self.calls[ctx.qualname].append(
                IRCall(
                    name=name,
                    qualname=qualname,
                    lineno=int(getattr(node, "lineno", 1)),
                    in_loop_depth=self._loop_depth,
                    object_name=obj_name,
                )
            )
        self.generic_visit(node)


class PythonIRPlugin:
    language = "python"

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() == ".py"

    def build(self, path: Path, src: str, findings: list[FunctionFinding]) -> IRModule | None:
        try:
            tree = ast.parse(src, filename=str(path))
        except SyntaxError:
            return None
        collector = _CallCollector()
        collector.visit(tree)
        call_map = collector.calls
        functions: list[IRFunction] = []
        for finding in findings:
            calls = call_map.get(finding.qualname, [])
            functions.append(
                IRFunction(
                    function_id=finding.function_id,
                    file=str(path),
                    qualname=finding.qualname,
                    lineno=finding.lineno,
                    end_lineno=finding.end_lineno,
                    language=self.language,
                    calls=calls,
                )
            )
        return IRModule(file=str(path), language=self.language, functions=functions)
