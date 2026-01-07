# Policy Cookbook

This guide provides example configurations for common CI policies.

## Strict Mode (no regressions)

```yaml
changed_only: true
compare_base: true
new_findings_only: true
gating_preset: strict
```

## Balanced Mode (default CI)

```yaml
changed_only: true
compare_base: true
new_findings_only: true
gating_preset: balanced
```

## Relaxed Mode (exploratory)

```yaml
changed_only: true
compare_base: true
new_findings_only: true
gating_preset: relaxed
```

## Custom thresholds (warn vs fail)

```yaml
warn_regression_risk_delta: 0.3
fail_regression_risk_delta: 0.8
max_regressions: 3
max_high_regressions: 1
```

## Path budgets

```yaml
risk_delta_budgets:
  - pattern: "src/core/**"
    budget: 0.5
  - pattern: "src/handlers/**"
    budget: 1.0
```

## Hot code (no regressions)

```yaml
no_regressions_paths:
  - "src/payments/**"
loop_depth_fail_paths:
  - "src/payments/**"
```

## Noise reduction

```yaml
exclude:
  - "tests"
  - "vendor"
min_function_lines: 6
new_findings_only: true
```

Inline suppression (with audit metadata):

```python
# occamo: ignore reason="legacy path" ticket="PERF-123"
def slow_but_expected(...):
    ...
```
