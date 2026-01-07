from __future__ import annotations

import re
from dataclasses import dataclass

_IGNORE_RE = re.compile(r"\boccamo:\s*ignore\b", re.IGNORECASE)
_META_RE = re.compile(r"\b(reason|ticket)\s*=\s*(\"[^\"]*\"|'[^']*')", re.IGNORECASE)


@dataclass(frozen=True)
class SuppressionMeta:
    comment_line: int
    reason: str
    ticket: str
    comment: str


def parse_suppression_comment(line: str, line_no: int) -> SuppressionMeta | None:
    if not _IGNORE_RE.search(line):
        return None
    reason = ""
    ticket = ""
    for match in _META_RE.finditer(line):
        key = match.group(1).lower()
        value = match.group(2)[1:-1]
        if key == "reason":
            reason = value
        elif key == "ticket":
            ticket = value
    return SuppressionMeta(
        comment_line=line_no,
        reason=reason,
        ticket=ticket,
        comment=line.strip(),
    )


def suppression_map(src: str) -> dict[int, SuppressionMeta]:
    lines = src.splitlines()
    suppressed: dict[int, SuppressionMeta] = {}
    for idx, line in enumerate(lines, start=1):
        meta = parse_suppression_comment(line, idx)
        if not meta:
            continue
        suppressed[idx] = meta
        for next_idx in range(idx + 1, len(lines) + 1):
            if lines[next_idx - 1].strip() == "":
                continue
            suppressed[next_idx] = meta
            break
    return suppressed
