# Rule SDK

OccamO rules are simple Python classes that inspect the IR and emit findings.
Rules can be packaged as plugins without forking the core.

## Rule API

Subclass `occamo.rules.base.Rule` and implement `apply()`:

```python
from occamo.rules.base import Rule, RuleFinding

class MyRule(Rule):
    id = "custom.my-rule"
    name = "My Rule"
    description = "Detects expensive calls in loops."
    default_severity = "high"
    stability = "experimental"
    tags = ["performance"]

    def apply(self, context):
        for module in context.ir_modules:
            for fn in module.functions:
                for call in fn.calls:
                    if call.in_loop_depth > 0 and call.name == "expensive":
                        yield RuleFinding(
                            rule_id=self.id,
                            rule_name=self.name,
                            severity=self.default_severity,
                            message="expensive() inside loop",
                            file=fn.file,
                            lineno=call.lineno,
                            end_lineno=fn.end_lineno,
                            qualname=fn.qualname,
                            function_id=fn.function_id,
                            body_hash="",
                            suggestions=["Move expensive() outside the loop or cache results."],
                            confidence=0.7,
                        )
```

## Plugin contract

Create a module that exports either:
- `RULES = [MyRule(), ...]`, or
- `def register(registry): registry.register(MyRule())`

Enable with:

```bash
occamo analyze . --rule-plugin my_rules
```

## Rule configuration

Use `.occamo.yml` to pass rule-specific settings under `rule_config` and read
them via `context.config_for(rule_id)`.

## Test harness

Use `occamo.rules.testing` for fixtures:

```python
from occamo.rules.testing import RuleFixture, run_rule_on_fixture
from my_rules import MyRule

fixture = RuleFixture(
    src="def f(items):\n    for i in items:\n        expensive(i)\n",
    path="src/app.py",
)
findings = run_rule_on_fixture(MyRule(), fixture)
assert any(f.rule_id == "custom.my-rule" for f in findings)
```

This keeps rule tests small and focused on expected findings.
