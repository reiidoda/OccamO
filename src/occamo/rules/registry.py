from __future__ import annotations

import importlib
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field

from occamo.rules.base import Rule, RuleContext, RuleFinding
from occamo.rules.builtin import BUILTIN_RULES

log = logging.getLogger(__name__)


@dataclass
class RuleRegistry:
    rules: list[Rule] = field(default_factory=list)

    def register(self, rule: Rule) -> None:
        self.rules.append(rule)

    def load_builtin(self) -> None:
        for rule in BUILTIN_RULES:
            self.register(rule)

    def load_plugins(self, plugin_modules: Iterable[str]) -> None:
        for module_path in plugin_modules:
            module_path = str(module_path).strip()
            if not module_path:
                continue
            try:
                module = importlib.import_module(module_path)
            except Exception as exc:
                log.warning("Failed to load rule plugin %s (%s)", module_path, exc)
                continue
            if hasattr(module, "register"):
                try:
                    module.register(self)
                    continue
                except Exception as exc:
                    log.warning("Rule plugin register() failed for %s (%s)", module_path, exc)
                    continue
            rules = getattr(module, "RULES", None)
            if isinstance(rules, list):
                for rule in rules:
                    if isinstance(rule, Rule):
                        self.register(rule)
            else:
                log.warning("Rule plugin %s has no RULES or register()", module_path)


def run_rules(
    context: RuleContext,
    enabled_rules: list[str] | None = None,
    disabled_rules: list[str] | None = None,
    severity_overrides: dict[str, str] | None = None,
    plugin_modules: list[str] | None = None,
) -> list[RuleFinding]:
    registry = RuleRegistry()
    registry.load_builtin()
    if plugin_modules:
        registry.load_plugins(plugin_modules)

    enabled_set = {r.strip() for r in (enabled_rules or []) if str(r).strip()}
    disabled_set = {r.strip() for r in (disabled_rules or []) if str(r).strip()}
    overrides = severity_overrides or {}

    findings: list[RuleFinding] = []
    for rule in registry.rules:
        if enabled_set and rule.id not in enabled_set:
            continue
        if rule.id in disabled_set:
            continue
        try:
            results = list(rule.apply(context))
        except Exception as exc:
            log.warning("Rule %s failed: %s", rule.id, exc)
            continue
        for finding in results:
            if finding.rule_id in overrides:
                findings.append(
                    RuleFinding(
                        **{
                            **finding.__dict__,
                            "severity": overrides[finding.rule_id],
                        }
                    )
                )
            else:
                findings.append(finding)
    return findings
