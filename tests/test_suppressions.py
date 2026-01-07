from __future__ import annotations

from pathlib import Path

from occamo.analyze.static_ast import collect_suppressions


def test_collect_suppressions_reason_ticket() -> None:
    src = "\n".join(
        [
            '# occamo: ignore reason="legacy" ticket="ABC-123"',
            "def foo():",
            "    return 1",
        ]
    )
    suppressions = collect_suppressions(Path("app.py"), src)
    assert len(suppressions) == 1
    sup = suppressions[0]
    assert sup.qualname == "foo"
    assert sup.reason == "legacy"
    assert sup.ticket == "ABC-123"
    assert sup.comment_line == 1
