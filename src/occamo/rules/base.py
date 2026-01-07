from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from occamo.analyze.static_ast import FunctionFinding
from occamo.ir.models import IRModule


@dataclass(frozen=True)
class RuleFinding:
    rule_id: str
    rule_name: str
    severity: str
    message: str
    file: str
    lineno: int
    end_lineno: int
    qualname: str
    function_id: str
    body_hash: str
    suggestions: list[str] = field(default_factory=list)
    confidence: float = 0.6


@dataclass
class RuleContext:
    repo_root: Path
    sources: dict[str, str]
    findings: list[FunctionFinding]
    ir_modules: list[IRModule]
    rule_config: dict[str, dict]

    def __post_init__(self) -> None:
        self._ast_cache: dict[str, ast.AST] = {}
        self._finding_by_key: dict[tuple[str, str], FunctionFinding] = {}
        self._finding_by_file: dict[str, list[FunctionFinding]] = {}
        for finding in self.findings:
            self._finding_by_key[(finding.file, finding.qualname)] = finding
            self._finding_by_file.setdefault(finding.file, []).append(finding)

    def ast_for_path(self, path: str) -> ast.AST | None:
        if path in self._ast_cache:
            return self._ast_cache[path]
        src = self.sources.get(path)
        if src is None:
            return None
        try:
            tree = ast.parse(src, filename=path)
        except SyntaxError:
            return None
        self._ast_cache[path] = tree
        return tree

    def finding_for(self, file_path: str, qualname: str) -> FunctionFinding | None:
        return self._finding_by_key.get((file_path, qualname))

    def finding_for_line(self, file_path: str, lineno: int) -> FunctionFinding | None:
        candidates = self._finding_by_file.get(file_path, [])
        for finding in candidates:
            if finding.lineno <= lineno <= finding.end_lineno:
                return finding
        return None

    def config_for(self, rule_id: str) -> dict:
        return self.rule_config.get(rule_id, {})


class Rule:
    id: str = "occamo.rule"
    name: str = "OccamO Rule"
    description: str = ""
    default_severity: str = "medium"
    stability: str = "experimental"
    tags: list[str] = []

    def apply(self, context: RuleContext) -> Iterable[RuleFinding]:
        raise NotImplementedError
