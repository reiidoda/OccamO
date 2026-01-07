# Architecture Overview

OccamO is a CI-first static analysis tool with optional dynamic verification.
The pipeline is intentionally simple and deterministic.

## High-level pipeline

```
Source files
  -> file selection (include/exclude/ignore)
  -> language parser
  -> AST signals + stable IDs
  -> IR (functions + calls)
  -> rules + call graph
  -> risk scoring + regressions
  -> reports + gating
```

## Key components

- `config/`: load/validate `.occamo.yml` and presets.
- `analyze/entrypoints.py`: file discovery, glob/ignore handling.
- `analyze/static_ast.py`: static signals and stable IDs for Python.
- `analyze/js_ts.py`, `analyze/java.py`, `analyze/kotlin.py`, `analyze/go.py`:
  tree-sitter based analysis for optional languages.
- `ir/`: language-agnostic IR for rules and call graph.
- `rules/`: built-in rules and Rule SDK plugin system.
- `analyze/call_graph.py`: cross-function weighting for expensive helpers.
- `analyze/regression.py`: baseline comparison and regression detection.
- `analyze/dynamic_verify.py`: optional dynamic checks for top hotspots.
- `report/`: JSON, Markdown, HTML, SARIF, PR comments, annotations, and checks.
- `analyze/cache.py`: incremental cache to speed up CI.

## Determinism

Static analysis is deterministic and does not execute repo code. Dynamic
verification is opt-in and runs in a subprocess with timeouts and limits.

## Data flow outputs

Reports include:
- Function hotspots with risk score and complexity hint.
- Regression diffs (before -> after) when baseline compare is enabled.
- Policy/gating results for CI enforcement.
