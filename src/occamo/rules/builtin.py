from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass

from occamo.rules.base import Rule, RuleContext, RuleFinding

_DB_CALLS = {
    "filter",
    "exclude",
    "get",
    "all",
    "select",
    "update",
    "delete",
    "create",
    "execute",
    "query",
    "scalars",
    "fetchone",
    "fetchall",
}

_DB_OBJECT_HINTS = {"objects", "session", "db", "cursor", "queryset", "engine", "conn", "connection"}

_PANDAS_CALLS = {"iterrows", "itertuples", "apply", "append", "to_dict"}


def _object_matches_db_hint(obj_name: str | None) -> bool:
    if not obj_name:
        return False
    lowered = obj_name.lower()
    if any(hint in lowered for hint in _DB_OBJECT_HINTS):
        return True
    if lowered.endswith(".objects"):
        return True
    return False


def _make_finding(
    rule: Rule,
    context: RuleContext,
    file_path: str,
    qualname: str,
    lineno: int,
    message: str,
    suggestions: list[str],
    severity: str | None = None,
    confidence: float = 0.6,
) -> RuleFinding:
    finding = context.finding_for(file_path, qualname) or context.finding_for_line(file_path, lineno)
    if finding:
        return RuleFinding(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=severity or rule.default_severity,
            message=message,
            file=finding.file,
            lineno=lineno,
            end_lineno=finding.end_lineno,
            qualname=finding.qualname,
            function_id=finding.function_id,
            body_hash=finding.body_hash,
            suggestions=suggestions,
            confidence=confidence,
        )
    return RuleFinding(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=severity or rule.default_severity,
        message=message,
        file=file_path,
        lineno=lineno,
        end_lineno=lineno,
        qualname=qualname,
        function_id="",
        body_hash="",
        suggestions=suggestions,
        confidence=confidence,
    )


class DbCallInLoopRule(Rule):
    id = "occamo.db-in-loop"
    name = "Database call inside loop"
    description = "Detects potential N+1 patterns by spotting ORM/SQL calls in loops."
    default_severity = "high"
    stability = "experimental"
    tags = ["performance", "orm", "database"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for module in context.ir_modules:
            if module.language != "python":
                continue
            for fn in module.functions:
                for call in fn.calls:
                    if call.in_loop_depth <= 0:
                        continue
                    if call.name not in _DB_CALLS:
                        continue
                    if not _object_matches_db_hint(call.object_name):
                        continue
                    message = f"Database call `{call.name}()` inside a loop may cause N+1 queries."
                    suggestions = [
                        "Batch queries or prefetch related data before the loop.",
                        "Move queries outside loops or use select_related/prefetch_related.",
                    ]
                    yield _make_finding(
                        self,
                        context,
                        module.file,
                        fn.qualname,
                        call.lineno,
                        message,
                        suggestions,
                    )


class JsonInLoopRule(Rule):
    id = "occamo.json-in-loop"
    name = "JSON serialization inside loop"
    description = "Detects json.dumps/loads in tight loops."
    default_severity = "medium"
    stability = "experimental"
    tags = ["performance", "serialization"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for module in context.ir_modules:
            if module.language != "python":
                continue
            for fn in module.functions:
                for call in fn.calls:
                    if call.in_loop_depth <= 0:
                        continue
                    if call.name not in {"dumps", "loads"}:
                        continue
                    if call.object_name not in {"json"}:
                        continue
                    message = f"JSON `{call.name}()` inside loop can be expensive."
                    suggestions = ["Batch serialization or move it outside the loop."]
                    yield _make_finding(
                        self,
                        context,
                        module.file,
                        fn.qualname,
                        call.lineno,
                        message,
                        suggestions,
                    )


class PandasRowIterationRule(Rule):
    id = "occamo.pandas-iterrows"
    name = "Pandas row iteration in loop"
    description = "Detects row-by-row pandas usage in loops."
    default_severity = "medium"
    stability = "experimental"
    tags = ["performance", "pandas"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for module in context.ir_modules:
            if module.language != "python":
                continue
            for fn in module.functions:
                for call in fn.calls:
                    if call.in_loop_depth <= 0:
                        continue
                    if call.name not in _PANDAS_CALLS:
                        continue
                    message = f"Pandas `{call.name}()` inside loop can be slow."
                    suggestions = [
                        "Prefer vectorized operations instead of row iteration.",
                        "Use DataFrame.apply sparingly or precompute with vectorized ops.",
                    ]
                    yield _make_finding(
                        self,
                        context,
                        module.file,
                        fn.qualname,
                        call.lineno,
                        message,
                        suggestions,
                    )


_REGEX_BAD_PATTERNS = [
    re.compile(r"\([^)]*[*+][^)]*\)[*+]"),
    re.compile(r"\.\*[+*]"),
    re.compile(r"\(\?:[^)]*[*+][^)]*\)[*+]"),
]


def _is_catastrophic_regex(pattern: str) -> bool:
    for rx in _REGEX_BAD_PATTERNS:
        if rx.search(pattern):
            return True
    return False


@dataclass
class _RegexHit:
    lineno: int
    pattern: str


class _RegexVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[_RegexHit] = []

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = None
        obj = None
        if isinstance(func, ast.Attribute):
            name = func.attr
            if isinstance(func.value, ast.Name):
                obj = func.value.id
        elif isinstance(func, ast.Name):
            name = func.id
        if name in {"compile", "search", "match", "findall", "fullmatch"} and obj == "re":
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                pattern = node.args[0].value
                if _is_catastrophic_regex(pattern):
                    self.hits.append(_RegexHit(lineno=int(getattr(node, "lineno", 1)), pattern=pattern))
        self.generic_visit(node)


class RegexCatastropheRule(Rule):
    id = "occamo.regex-catastrophic"
    name = "Potential catastrophic regex"
    description = "Detects regex patterns that may cause catastrophic backtracking."
    default_severity = "high"
    stability = "experimental"
    tags = ["performance", "regex"]

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        for file_path, _src in context.sources.items():
            tree = context.ast_for_path(file_path)
            if tree is None:
                continue
            visitor = _RegexVisitor()
            visitor.visit(tree)
            for hit in visitor.hits:
                message = "Regex pattern may cause catastrophic backtracking."
                suggestions = [
                    "Avoid nested quantifiers or use non-greedy patterns.",
                    "Consider precompiling with safe patterns or using regex timeouts.",
                ]
                finding = context.finding_for_line(file_path, hit.lineno)
                qualname = finding.qualname if finding else "<module>"
                yield _make_finding(
                    self,
                    context,
                    file_path,
                    qualname,
                    hit.lineno,
                    message,
                    suggestions,
                    confidence=0.5,
                )


BUILTIN_RULES: list[Rule] = [
    DbCallInLoopRule(),
    JsonInLoopRule(),
    PandasRowIterationRule(),
    RegexCatastropheRule(),
]
