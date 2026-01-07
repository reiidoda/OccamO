from __future__ import annotations

from collections.abc import Iterable

from occamo.analyze.static_ast import FunctionFinding
from occamo.report.models import ChangeFinding, RegressionFinding

_HINT_RANK: dict[str, int] = {
    "O(1) / O(log n) candidate": 0,
    "O(n) candidate": 1,
    "O(n log n) candidate": 2,
    "O(n log n) + loop": 3,
    "O(n^2) candidate": 4,
    "O(n^3) or worse": 5,
    "potentially exponential / high": 6,
}


def _hint_delta(head_hint: str, base_hint: str) -> int | None:
    head_rank = _HINT_RANK.get(head_hint)
    base_rank = _HINT_RANK.get(base_hint)
    if head_rank is None or base_rank is None:
        return None
    return head_rank - base_rank


def _signals_dict(finding: FunctionFinding) -> dict[str, int | bool]:
    s = finding.signals
    return {
        "loops": s.loops,
        "max_loop_depth": s.max_loop_depth,
        "recursion": s.recursion,
        "sort_calls": s.sort_calls,
        "comprehension": s.comprehension,
    }


def _risk_score(
    finding: FunctionFinding,
    overrides: dict[str, float] | None = None,
) -> float:
    if overrides and finding.function_id in overrides:
        return overrides[finding.function_id]
    return finding.signals.risk_score


def _regression_severity(
    risk_delta: float,
    warn_risk_delta: float | None,
    fail_risk_delta: float | None,
    hint_delta: int | None,
) -> str:
    if fail_risk_delta is not None and risk_delta >= fail_risk_delta:
        return "high"
    if warn_risk_delta is not None and risk_delta >= warn_risk_delta:
        return "medium"
    if hint_delta is not None and hint_delta >= 2:
        return "medium"
    if risk_delta >= 1.0:
        return "high"
    if risk_delta >= 0.5:
        return "medium"
    return "low"


def _explain_regression(
    base: FunctionFinding,
    head: FunctionFinding,
    hint_delta: int | None,
) -> tuple[str, list[str]]:
    suggestions: list[str] = []
    explanation = ""
    if head.signals.max_loop_depth > base.signals.max_loop_depth:
        explanation = (
            f"Loop depth increased {base.signals.max_loop_depth} -> {head.signals.max_loop_depth}."
        )
        suggestions.append("Reduce nested loops by precomputing lookups or indexing with dict/set.")
    if head.signals.sort_calls > base.signals.sort_calls:
        if not explanation:
            explanation = (
                f"More sort calls detected ({base.signals.sort_calls} -> {head.signals.sort_calls})."
            )
        suggestions.append("Sort once outside loops or use a heap for top-k.")
    if head.signals.recursion and not base.signals.recursion:
        if not explanation:
            explanation = "Recursion introduced."
        suggestions.append("Memoize recursion or convert to iterative DP.")
    if head.signals.loops > base.signals.loops and not explanation:
        explanation = f"Loop count increased {base.signals.loops} -> {head.signals.loops}."
        suggestions.append("Batch work or use vectorized/data-structure-based lookups.")
    if hint_delta is not None and hint_delta > 0 and not explanation:
        explanation = f"Complexity hint regressed ({base.complexity_hint} -> {head.complexity_hint})."
    if not explanation:
        explanation = (
            f"Risk score increased {base.signals.risk_score:.3f} -> {head.signals.risk_score:.3f}."
        )
    return explanation, suggestions


def explain_finding(finding: FunctionFinding) -> tuple[str, list[str]]:
    suggestions: list[str] = []
    explanation = ""
    s = finding.signals
    if s.max_loop_depth >= 3:
        explanation = f"Deeply nested loops detected (depth {s.max_loop_depth})."
        suggestions.append("Reduce nesting by precomputing lookups or indexing with dict/set.")
    elif s.max_loop_depth == 2:
        explanation = "Nested loops detected."
        suggestions.append("Consider pre-indexing or batching to avoid nested iteration.")
    if s.sort_calls and s.loops:
        if not explanation:
            explanation = "Sort calls inside loop detected."
        suggestions.append("Sort once outside loops or use a heap for top-k.")
    elif s.sort_calls and not explanation:
        explanation = f"Sorting calls detected ({s.sort_calls})."
        suggestions.append("Avoid repeated sorting in hot paths.")
    if s.recursion:
        if not explanation:
            explanation = "Recursion detected."
        suggestions.append("Memoize recursion or convert to iterative DP.")
    if s.loops and not explanation:
        explanation = f"Loop count {s.loops} with max depth {s.max_loop_depth}."
        suggestions.append("Batch work or use vectorized/data-structure-based lookups.")
    if not explanation:
        explanation = f"{finding.complexity_hint} based on static signals."
    return explanation, suggestions


def find_regressions(
    head_findings: Iterable[FunctionFinding],
    base_findings: Iterable[FunctionFinding],
    warn_risk_delta: float | None = None,
    fail_risk_delta: float | None = None,
    head_risk_overrides: dict[str, float] | None = None,
    base_risk_overrides: dict[str, float] | None = None,
) -> list[RegressionFinding]:
    base_map, base_id_map, base_body_unique = _build_base_index(base_findings)
    regressions: list[RegressionFinding] = []
    matched_base: set[int] = set()
    for head in head_findings:
        base = _find_base_match(
            head,
            base_map,
            base_id_map,
            base_body_unique,
            matched_base,
        )
        if base is None:
            continue
        head_risk = _risk_score(head, head_risk_overrides)
        base_risk = _risk_score(base, base_risk_overrides)
        risk_delta = round(head_risk - base_risk, 3)
        hint_delta = _hint_delta(head.complexity_hint, base.complexity_hint)
        if risk_delta > 0 or (hint_delta is not None and hint_delta > 0):
            regression_severity = _regression_severity(
                risk_delta, warn_risk_delta, fail_risk_delta, hint_delta
            )
            explanation, suggestions = _explain_regression(base, head, hint_delta)
            regressions.append(
                RegressionFinding(
                    file=head.file,
                    qualname=head.qualname,
                    function_id=head.function_id or base.function_id,
                    lineno=head.lineno,
                    base_risk_score=base_risk,
                    head_risk_score=head_risk,
                    base_hint=base.complexity_hint,
                    head_hint=head.complexity_hint,
                    risk_delta=risk_delta,
                    hint_delta=hint_delta,
                    regression_severity=regression_severity,
                    explanation=explanation,
                    suggestions=suggestions,
                    base_signals=_signals_dict(base),
                    head_signals=_signals_dict(head),
                )
            )

    regressions.sort(
        key=lambda r: (-r.risk_delta, -(r.hint_delta or 0), r.file, r.lineno, r.qualname),
    )
    return regressions


def diff_findings(
    head_findings: Iterable[FunctionFinding],
    base_findings: Iterable[FunctionFinding],
    warn_risk_delta: float | None = None,
    fail_risk_delta: float | None = None,
    head_risk_overrides: dict[str, float] | None = None,
    base_risk_overrides: dict[str, float] | None = None,
) -> list[ChangeFinding]:
    base_list = list(base_findings)
    base_map, base_id_map, base_body_unique = _build_base_index(base_list)
    matched_base: set[int] = set()
    diffs: list[ChangeFinding] = []

    for head in head_findings:
        base = _find_base_match(
            head,
            base_map,
            base_id_map,
            base_body_unique,
            matched_base,
        )
        if base is None:
            diffs.append(
                ChangeFinding(
                    file=head.file,
                    qualname=head.qualname,
                    function_id=head.function_id,
                    lineno=head.lineno,
                    change_type="added",
                    trend="new",
                    base_risk_score=None,
                    head_risk_score=_risk_score(head, head_risk_overrides),
                    base_hint=None,
                    head_hint=head.complexity_hint,
                    risk_delta=None,
                    hint_delta=None,
                    regression_severity=None,
                )
            )
            continue
        head_risk = _risk_score(head, head_risk_overrides)
        base_risk = _risk_score(base, base_risk_overrides)
        risk_delta = round(head_risk - base_risk, 3)
        hint_delta = _hint_delta(head.complexity_hint, base.complexity_hint)
        if risk_delta == 0 and (hint_delta is None or hint_delta == 0):
            continue
        trend = "same"
        if risk_delta > 0 or (hint_delta is not None and hint_delta > 0):
            trend = "worse"
        elif risk_delta < 0 or (hint_delta is not None and hint_delta < 0):
            trend = "better"
        regression_severity = None
        if trend == "worse":
            regression_severity = _regression_severity(
                risk_delta, warn_risk_delta, fail_risk_delta, hint_delta
            )
        diffs.append(
            ChangeFinding(
                file=head.file,
                qualname=head.qualname,
                function_id=head.function_id or base.function_id,
                lineno=head.lineno,
                change_type="changed",
                trend=trend,
                base_risk_score=base_risk,
                head_risk_score=head_risk,
                base_hint=base.complexity_hint,
                head_hint=head.complexity_hint,
                risk_delta=risk_delta,
                hint_delta=hint_delta,
                regression_severity=regression_severity,
            )
        )

    for base in base_list:
        if id(base) in matched_base:
            continue
        diffs.append(
            ChangeFinding(
                file=base.file,
                qualname=base.qualname,
                function_id=base.function_id,
                lineno=base.lineno,
                change_type="removed",
                trend="removed",
                base_risk_score=base.signals.risk_score,
                head_risk_score=None,
                base_hint=base.complexity_hint,
                head_hint=None,
                risk_delta=None,
                hint_delta=None,
                regression_severity=None,
            )
        )

    diffs.sort(key=lambda d: (d.file, d.lineno, d.qualname))
    return diffs


def match_findings(
    head_findings: Iterable[FunctionFinding],
    base_findings: Iterable[FunctionFinding],
) -> dict[str, FunctionFinding]:
    base_map, base_id_map, base_body_unique = _build_base_index(base_findings)
    matched_base: set[int] = set()
    out: dict[str, FunctionFinding] = {}
    for head in head_findings:
        if not head.function_id:
            continue
        base = _find_base_match(
            head,
            base_map,
            base_id_map,
            base_body_unique,
            matched_base,
        )
        if base is None:
            continue
        out[head.function_id] = base
    return out


def _build_base_index(
    base_findings: Iterable[FunctionFinding],
) -> tuple[dict[tuple[str, str], FunctionFinding], dict[str, FunctionFinding], dict[str, FunctionFinding]]:
    base_map: dict[tuple[str, str], FunctionFinding] = {
        (f.file, f.qualname): f for f in base_findings
    }
    base_id_map: dict[str, FunctionFinding] = {
        f.function_id: f for f in base_findings if f.function_id
    }
    base_body_map: dict[str, list[FunctionFinding]] = {}
    for f in base_findings:
        if not f.body_hash:
            continue
        base_body_map.setdefault(f.body_hash, []).append(f)
    base_body_unique = {k: v[0] for k, v in base_body_map.items() if len(v) == 1}
    return base_map, base_id_map, base_body_unique


def _find_base_match(
    head: FunctionFinding,
    base_map: dict[tuple[str, str], FunctionFinding],
    base_id_map: dict[str, FunctionFinding],
    base_body_unique: dict[str, FunctionFinding],
    matched_base: set[int] | None = None,
) -> FunctionFinding | None:
    base = None
    if head.function_id:
        base = base_id_map.get(head.function_id)
    if base is None:
        base = base_map.get((head.file, head.qualname))
    if base is None and head.body_hash:
        candidate = base_body_unique.get(head.body_hash)
        if candidate and (matched_base is None or id(candidate) not in matched_base):
            base = candidate
    if base is None:
        return None
    if matched_base is not None:
        if id(base) in matched_base:
            return None
        matched_base.add(id(base))
    return base
