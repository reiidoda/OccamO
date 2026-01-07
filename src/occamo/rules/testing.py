from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from occamo.analyze.dispatch import analyze_source
from occamo.ir.registry import build_ir_modules
from occamo.rules.base import Rule, RuleContext, RuleFinding


@dataclass(frozen=True)
class RuleFixture:
    src: str
    path: str = "src/app.py"
    rule_config: dict[str, dict] = field(default_factory=dict)


def context_from_fixture(fixture: RuleFixture, repo_root: Path | None = None) -> RuleContext:
    root = repo_root or Path(".")
    path = Path(fixture.path)
    findings = analyze_source(path, fixture.src)
    sources = {fixture.path: fixture.src}
    ir_modules = build_ir_modules(root, sources, findings)
    return RuleContext(
        repo_root=root,
        sources=sources,
        findings=findings,
        ir_modules=ir_modules,
        rule_config=fixture.rule_config,
    )


def run_rule_on_fixture(
    rule: Rule,
    fixture: RuleFixture,
    repo_root: Path | None = None,
) -> list[RuleFinding]:
    context = context_from_fixture(fixture, repo_root=repo_root)
    return list(rule.apply(context))


def run_rule_fixtures(
    rule: Rule,
    fixtures: Iterable[RuleFixture],
    repo_root: Path | None = None,
) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    for fixture in fixtures:
        findings.extend(run_rule_on_fixture(rule, fixture, repo_root=repo_root))
    return findings
