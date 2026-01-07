from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from occamo.analyze.identity import hash_text, stable_function_id
from occamo.analyze.js_ts import TS_AVAILABLE, UNAVAILABLE_REASON, get_parser
from occamo.analyze.scoring import hint_from_signals
from occamo.analyze.signals import StaticSignals
from occamo.analyze.static_ast import FunctionFinding
from occamo.analyze.suppression_utils import SuppressionMeta, suppression_map
from occamo.report.models import Suppression

try:
    from tree_sitter import Node  # type: ignore
except Exception:
    Node = object  # type: ignore

UNAVAILABLE_REASON = None if TS_AVAILABLE else (UNAVAILABLE_REASON or "tree_sitter unavailable")


_FUNCTION_NODES = {
    "function_declaration",
    "method_declaration",
}

_LOOP_NODES = {
    "for_statement",
}

_SORT_CALLS = {
    "Sort",
    "Slice",
    "Stable",
    "Ints",
    "Strings",
    "Float64s",
}


@dataclass(frozen=True)
class _FunctionContext:
    qualname: str
    name: str
    node: Node
    class_names: list[str]


def _node_text(src: bytes, node: Node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _child_text(node: Node, field: str, src: bytes) -> str | None:
    child = node.child_by_field_name(field)
    if child is None:
        return None
    return _node_text(src, child)


def _function_name(node: Node, src: bytes) -> str:
    name = _child_text(node, "name", src)
    if name:
        return name
    return "<anonymous>"


def _receiver_type(node: Node, src: bytes) -> str | None:
    receiver = node.child_by_field_name("receiver")
    if receiver is None:
        return None
    for child in receiver.children:
        if child.type in {"type_identifier", "identifier"}:
            return _node_text(src, child)
    for child in receiver.children:
        for grand in child.children:
            if grand.type in {"type_identifier", "identifier"}:
                return _node_text(src, grand)
    return None


def _collect_functions(
    node: Node,
    src: bytes,
    class_stack: list[str],
    func_stack: list[str],
) -> Iterable[_FunctionContext]:
    for child in node.children:
        if child.type in _FUNCTION_NODES:
            name = _function_name(child, src)
            class_names = list(class_stack)
            if child.type == "method_declaration":
                receiver = _receiver_type(child, src)
                if receiver:
                    class_names = [receiver]
            qual_parts = [*class_names, *func_stack, name] if class_names else [*func_stack, name]
            qualname = ".".join(qual_parts) if qual_parts else name
            yield _FunctionContext(qualname=qualname, name=name, node=child, class_names=class_names)
            yield from _collect_functions(child, src, class_stack, [*func_stack, name])
            continue
        yield from _collect_functions(child, src, class_stack, func_stack)


def _iter_children(node: Node) -> Iterable[Node]:
    yield from node.children


def _suppressed_def_lines(src: str) -> dict[int, SuppressionMeta]:
    return suppression_map(src)


def _normalized_body_text(node: Node, src: bytes) -> str:
    body = node.child_by_field_name("body") or node.child_by_field_name("block")
    if body is None:
        return ""
    text = _node_text(src, body)
    return re.sub(r"\s+", " ", text).strip()


def _selector_parts(node: Node, src: bytes) -> tuple[str | None, str | None]:
    if node.type != "selector_expression":
        return None, None
    obj = node.child_by_field_name("operand") or node.child_by_field_name("object")
    field = node.child_by_field_name("field") or node.child_by_field_name("property")
    obj_name = _node_text(src, obj) if obj is not None else None
    field_name = _node_text(src, field) if field is not None else None
    return obj_name, field_name


def _collect_signals(node: Node, src: bytes, function_name: str, class_names: list[str]) -> StaticSignals:
    loops = 0
    max_depth = 0
    sort_calls = 0
    recursion = False

    def walk(current: Node, depth: int) -> None:
        nonlocal loops, max_depth, sort_calls, recursion
        for child in _iter_children(current):
            if child.type in _FUNCTION_NODES and child is not node:
                continue
            next_depth = depth
            if child.type in _LOOP_NODES:
                loops += 1
                next_depth = depth + 1
                max_depth = max(max_depth, next_depth)
            if child.type == "call_expression":
                func = child.child_by_field_name("function")
                if func is not None:
                    if func.type == "identifier":
                        name = _node_text(src, func)
                        if name == function_name:
                            recursion = True
                    elif func.type == "selector_expression":
                        obj_name, member_name = _selector_parts(func, src)
                        if obj_name == "sort" and member_name in _SORT_CALLS:
                            sort_calls += 1
                        if member_name == function_name and obj_name in {"this", *class_names}:
                            recursion = True
            walk(child, next_depth)

    walk(node, 0)
    return StaticSignals(
        loops=loops,
        max_loop_depth=max_depth,
        recursion=recursion,
        sort_calls=sort_calls,
        comprehension=0,
    )


def _parser_for_path(path: Path) -> Any | None:
    if not TS_AVAILABLE or get_parser is None:
        return None
    if path.suffix.lower() != ".go":
        return None
    try:
        return get_parser("go")
    except Exception:
        return None


def analyze_source(path: Path, src: str) -> list[FunctionFinding]:
    parser = _parser_for_path(path)
    if parser is None:
        return []
    src_bytes = src.encode("utf-8", errors="replace")
    try:
        tree = parser.parse(src_bytes)
    except Exception:
        return []

    suppressed_lines = _suppressed_def_lines(src)
    out: list[FunctionFinding] = []
    for ctx in _collect_functions(tree.root_node, src_bytes, [], []):
        start_line = int(ctx.node.start_point[0]) + 1
        if start_line in suppressed_lines:
            continue
        signals = _collect_signals(ctx.node, src_bytes, ctx.name, ctx.class_names)
        hint, confidence = hint_from_signals(signals)
        end_line = int(ctx.node.end_point[0]) + 1
        body_hash = hash_text(_normalized_body_text(ctx.node, src_bytes))
        function_id = stable_function_id(str(path), ctx.qualname, body_hash)
        out.append(
            FunctionFinding(
                file=str(path),
                qualname=ctx.qualname,
                lineno=start_line,
                end_lineno=end_line,
                signals=signals,
                complexity_hint=hint,
                confidence=confidence,
                body_hash=body_hash,
                function_id=function_id,
            )
        )
    return out


def collect_suppressions(path: Path, src: str) -> list[Suppression]:
    parser = _parser_for_path(path)
    if parser is None:
        return []
    src_bytes = src.encode("utf-8", errors="replace")
    try:
        tree = parser.parse(src_bytes)
    except Exception:
        return []
    suppressed_lines = _suppressed_def_lines(src)
    out: list[Suppression] = []
    for ctx in _collect_functions(tree.root_node, src_bytes, [], []):
        start_line = int(ctx.node.start_point[0]) + 1
        info = suppressed_lines.get(start_line)
        if not info:
            continue
        end_line = int(ctx.node.end_point[0]) + 1
        body_hash = hash_text(_normalized_body_text(ctx.node, src_bytes))
        function_id = stable_function_id(str(path), ctx.qualname, body_hash)
        out.append(
            Suppression(
                file=str(path),
                qualname=ctx.qualname,
                function_id=function_id,
                lineno=start_line,
                end_lineno=end_line,
                comment_line=info.comment_line,
                reason=info.reason,
                ticket=info.ticket,
                comment=info.comment,
            )
        )
    return out


__all__ = [
    "TS_AVAILABLE",
    "UNAVAILABLE_REASON",
    "_FUNCTION_NODES",
    "_LOOP_NODES",
    "_collect_functions",
    "_node_text",
    "analyze_source",
    "collect_suppressions",
    "get_parser",
]
