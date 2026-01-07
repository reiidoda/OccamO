# OccamO report

- Generated: `2024-01-01T00:00:00Z`
- Mode: `changed-only`
- Base ref: `origin/main`
- Baseline compare: `enabled`
- Schema: `v7`
- Suppressions: `1`
- Findings: `2`
- Regressions: `1`
- Findings by severity: `high:1, low:1`

## Regressions vs base

| Severity | Risk Δ | Hint Δ | Dynamic | Base | Head | Location | Why |
|---|---:|---:|---|---|---|---|---|
| high | +1.700 | +3 | confirmed (1.60x) | 0.400 / O(n) candidate | 2.100 / O(n^2) candidate | src/app.py:10 `Widget.render` | Loop depth increased 1 -> 2. |

### Fix suggestions

- src/app.py:10 `Widget.render`: Reduce nested loops by precomputing lookups or indexing with dict/set.; Sort once outside loops or use a heap for top-k.

## Change summary (base -> head)

- Added: `1`  Removed: `0`  Changed: `0`

| Type | Trend | Risk (base -> head) | Hint (base -> head) | Location |
|---|---|---|---|---|
| added | new | n/a | n/a | src/new.py:3 `new_func` |

## Suppressions

| Location | Reason | Ticket | Comment |
|---|---|---|---|
| src/legacy.py:42 `legacy.fn` | legacy path | ABC-123 | occamo: ignore reason="legacy path" ticket="ABC-123" |

## Top hotspots (heuristic)

| Severity | Risk | Confidence | Dynamic | Hint | Location |
|---|---:|---:|---|---|---|
| high | 2.100 | 0.75 | confirmed (O(n^2) candidate) | O(n^2) candidate | src/app.py:10 `Widget.render` |
| low | 0.400 | 0.65 | n/a | O(n) candidate | src/utils.py:5 `helper` |

### Fix suggestions

- src/app.py:10 `Widget.render`: Reduce nesting by precomputing lookups.; Sort once outside loops.

> Notes: OccamO uses static AST heuristics; dynamic verification is optional and best-effort.