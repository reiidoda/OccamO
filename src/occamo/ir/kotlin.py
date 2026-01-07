from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from occamo.analyze.kotlin import (
    _FUNCTION_NODES,
    _LOOP_NODES,
    TS_AVAILABLE,
    _collect_functions,
    _node_text,
    _split_callee,
    get_parser,
)
from occamo.analyze.static_ast import FunctionFinding
from occamo.ir.models import IRCall, IRFunction, IRModule


def _parser_for_path(path: Path) -> Any | None:
    if not TS_AVAILABLE or get_parser is None:
        return None
    if path.suffix.lower() not in {".kt", ".kts"}:
        return None
    try:
        return get_parser("kotlin")
    except Exception:
        return None


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
                callee = (
                    child.child_by_field_name("callee")
                    or child.child_by_field_name("function")
                    or child.child_by_field_name("name")
                )
                if callee is not None:
                    obj_name, name = _split_callee(_node_text(src, callee))
                    qualname = None
                    if name:
                        if obj_name in {"this"} and class_names:
                            qualname = f"{class_names[-1]}.{name}"
                        elif obj_name in class_names:
                            qualname = f"{obj_name}.{name}"
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


class KotlinIRPlugin:
    language = "kotlin"

    def supports(self, path: Path) -> bool:
        if not TS_AVAILABLE:
            return False
        return path.suffix.lower() in {".kt", ".kts"}

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


__all__ = ["KotlinIRPlugin"]
