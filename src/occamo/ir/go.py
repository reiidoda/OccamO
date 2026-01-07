from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from occamo.analyze.go import (
    _FUNCTION_NODES,
    _LOOP_NODES,
    TS_AVAILABLE,
    _collect_functions,
    _node_text,
    get_parser,
)
from occamo.analyze.static_ast import FunctionFinding
from occamo.ir.models import IRCall, IRFunction, IRModule


def _parser_for_path(path: Path) -> Any | None:
    if not TS_AVAILABLE or get_parser is None:
        return None
    if path.suffix.lower() != ".go":
        return None
    try:
        return get_parser("go")
    except Exception:
        return None


def _selector_parts(node: Any, src: bytes) -> tuple[str | None, str | None]:
    if node.type != "selector_expression":
        return None, None
    obj = node.child_by_field_name("operand") or node.child_by_field_name("object")
    field = node.child_by_field_name("field") or node.child_by_field_name("property")
    obj_name = _node_text(src, obj) if obj is not None else None
    field_name = _node_text(src, field) if field is not None else None
    return obj_name, field_name


def _collect_calls(node: Any, src: bytes, class_names: list[str]) -> list[IRCall]:
    calls: list[IRCall] = []

    def walk(current: Any, loop_depth: int) -> None:
        for child in current.children:
            if child.type in _FUNCTION_NODES and child is not node:
                continue
            next_depth = loop_depth
            if child.type in _LOOP_NODES:
                next_depth = loop_depth + 1
            if child.type == "call_expression":
                func = child.child_by_field_name("function")
                if func is not None:
                    name = None
                    obj_name = None
                    qualname = None
                    if func.type == "identifier":
                        name = _node_text(src, func)
                        qualname = name
                    elif func.type == "selector_expression":
                        obj_name, name = _selector_parts(func, src)
                        if obj_name in class_names:
                            qualname = f"{obj_name}.{name}" if name else None
                    if name:
                        calls.append(
                            IRCall(
                                name=name,
                                qualname=qualname,
                                lineno=int(child.start_point[0]) + 1,
                                in_loop_depth=next_depth,
                                object_name=obj_name,
                            )
                        )
            walk(child, next_depth)

    walk(node, 0)
    return calls


class GoIRPlugin:
    language = "go"

    def supports(self, path: Path) -> bool:
        if not TS_AVAILABLE:
            return False
        return path.suffix.lower() == ".go"

    def build(self, path: Path, src: str, findings: list[FunctionFinding]) -> IRModule | None:
        parser = _parser_for_path(path)
        if parser is None:
            return None
        src_bytes = src.encode("utf-8", errors="replace")
        try:
            tree = parser.parse(src_bytes)
        except Exception:
            return None

        call_map = defaultdict(list)
        for ctx in _collect_functions(tree.root_node, src_bytes, [], []):
            calls = _collect_calls(ctx.node, src_bytes, ctx.class_names)
            call_map[ctx.qualname].extend(calls)

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


__all__ = ["GoIRPlugin"]
