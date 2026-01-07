# OccamO quick fix snippets

These are manual copy-paste templates; adjust to your code.

## src/app.py:10 `Widget.render`
- Context: Loop depth increased 1 -> 2.
- Snippet: Avoid nested loops
```python
# Pre-index to avoid nested loops
index = {item.id: item for item in items}
for row in rows:
    item = index.get(row.id)
    if item is not None:
        # ...
        pass
```
- Snippet: Move sort out of loop
```python
# Sort once outside the loop
rows_sorted = sorted(rows, key=lambda r: r.key)
for row in rows_sorted:
    # ...
    pass
```
