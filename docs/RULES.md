# Built-in Rules

OccamO ships with a small set of built-in rules. All are currently
`experimental` and may be promoted to `stable` in a future minor release.

Rules run on the IR and are designed to be conservative. Use `exclude`,
`min_function_lines`, and suppressions to reduce noise.

## occamo.db-in-loop (high)

Detects ORM/SQL calls inside loops (possible N+1 queries).

Signals:
- Known query methods (filter/get/select/execute/query/etc).
- ORM-like receiver names (objects/session/db/engine/connection).

Suggestions:
- Batch queries or prefetch related data.
- Move queries outside the loop.

## occamo.json-in-loop (medium)

Detects `json.dumps/loads` inside loops.

Suggestions:
- Batch serialization or move it outside the loop.

## occamo.pandas-iterrows (medium)

Detects row-by-row pandas usage inside loops (`iterrows`, `itertuples`,
`apply`, `append`, `to_dict`).

Suggestions:
- Prefer vectorized operations.
- Avoid row iteration in hot paths.

## occamo.regex-catastrophic (high)

Detects regex patterns prone to catastrophic backtracking.

Suggestions:
- Avoid nested quantifiers.
- Use non-greedy patterns or safe regex forms.

## Suppressing rules

Suppressions apply to the whole function:

```python
# occamo: ignore reason="legacy path" ticket="PERF-123"
def slow_but_expected(...):
    ...
```

Suppressions are recorded in the report for auditability.
