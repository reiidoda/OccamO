from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TypedDict

from occamo.analyze.static_ast import FunctionFinding
from occamo.ir.models import IRCall, IRModule


@dataclass(frozen=True)
class CallEdge:
    caller_id: str
    callee_id: str
    callee_name: str
    lineno: int
    loop_depth: int


@dataclass(frozen=True)
class CallGraphSummary:
    edges: dict[str, list[CallEdge]] = field(default_factory=dict)
    effective_scores: dict[str, float] = field(default_factory=dict)
    notes: dict[str, list[str]] = field(default_factory=dict)


class _FunctionIndex(TypedDict):
    by_qualname: dict[str, str]
    by_name: dict[str, list[str]]


def _weight_for_edge(loop_depth: int) -> float:
    if loop_depth <= 0:
        return 0.2
    depth = min(loop_depth, 3)
    return 1.0 + 0.5 * (depth - 1)


def _function_name(qualname: str) -> str:
    if not qualname:
        return ""
    return qualname.split(".")[-1]


def _index_functions(mod: IRModule) -> _FunctionIndex:
    by_qualname: dict[str, str] = {}
    by_name: dict[str, list[str]] = {}
    for fn in mod.functions:
        by_qualname[fn.qualname] = fn.function_id
        name = _function_name(fn.qualname)
        if name:
            by_name.setdefault(name, []).append(fn.function_id)
    return {"by_qualname": by_qualname, "by_name": by_name}


def _resolve_callee(call: IRCall, index: _FunctionIndex) -> str | None:
    if call.qualname and call.qualname in index["by_qualname"]:
        return index["by_qualname"][call.qualname]
    if call.name in index["by_name"]:
        candidates = index["by_name"][call.name]
        if len(candidates) == 1:
            return candidates[0]
    return None


def build_call_graph(
    findings: Iterable[FunctionFinding],
    ir_modules: Iterable[IRModule],
    hot_weights: dict[str, float] | None = None,
    passes: int = 2,
) -> CallGraphSummary:
    base_scores: dict[str, float] = {
        f.function_id: f.signals.risk_score for f in findings if f.function_id
    }
    edges: dict[str, list[CallEdge]] = {}
    notes: dict[str, list[str]] = {}

    for mod in ir_modules:
        index = _index_functions(mod)
        for fn in mod.functions:
            if not fn.function_id:
                continue
            for call in fn.calls:
                callee_id = _resolve_callee(call, index)
                if not callee_id:
                    continue
                edge = CallEdge(
                    caller_id=fn.function_id,
                    callee_id=callee_id,
                    callee_name=call.qualname or call.name,
                    lineno=call.lineno,
                    loop_depth=call.in_loop_depth,
                )
                edges.setdefault(fn.function_id, []).append(edge)
                callee_risk = base_scores.get(callee_id, 0.0)
                if call.in_loop_depth > 0 and callee_risk >= 1.0:
                    note = f"Calls `{edge.callee_name}` inside a loop (risk {callee_risk:.2f})."
                    notes.setdefault(fn.function_id, [])
                    if len(notes[fn.function_id]) < 2:
                        notes[fn.function_id].append(note)

    effective = dict(base_scores)
    for _ in range(max(1, passes)):
        updated = dict(base_scores)
        for caller_id, caller_edges in edges.items():
            extra = 0.0
            for edge in caller_edges:
                callee_score = effective.get(edge.callee_id, base_scores.get(edge.callee_id, 0.0))
                extra += _weight_for_edge(edge.loop_depth) * callee_score
            updated[caller_id] = base_scores.get(caller_id, 0.0) + extra
        effective = updated

    if hot_weights:
        for fn_id, weight in hot_weights.items():
            if fn_id in effective:
                effective[fn_id] = round(effective[fn_id] * weight, 3)

    return CallGraphSummary(edges=edges, effective_scores=effective, notes=notes)
