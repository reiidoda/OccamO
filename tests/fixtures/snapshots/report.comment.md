<!-- occamo-comment -->
### OccamO summary

- Mode: `changed-only`
- Baseline compare: `enabled`
- Suppressions: `1`
- Regressions: `1`
- Findings: `2`
- Findings by severity: `high:1, low:1`

**Regressions**

| Severity | Risk (base -> head) | Hint (base -> head) | Dynamic | Location | Why |
|---|---|---|---|---|---|
| high | 0.400 -> 2.100 (+1.700) | O(n) candidate -> O(n^2) candidate | confirmed (1.60x) | src/app.py:10 `Widget.render` | Loop depth increased 1 -> 2. |

**Fix ideas**

- src/app.py:10 `Widget.render`: Reduce nested loops by precomputing lookups or indexing with dict/set.; Sort once outside loops or use a heap for top-k.

**Suppressions**

| Location | Reason | Ticket |
|---|---|---|
| src/legacy.py:42 `legacy.fn` | legacy path | ABC-123 |