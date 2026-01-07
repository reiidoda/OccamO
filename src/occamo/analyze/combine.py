from __future__ import annotations

from dataclasses import dataclass

from occamo.analyze.static_ast import FunctionFinding


@dataclass(frozen=True)
class RankedFinding:
    finding: FunctionFinding
    score: float


def rank(
    findings: list[FunctionFinding],
    score_overrides: dict[str, float] | None = None,
) -> list[RankedFinding]:
    ranked = []
    for f in findings:
        score = f.signals.risk_score
        if score_overrides and f.function_id in score_overrides:
            score = score_overrides[f.function_id]
        ranked.append(RankedFinding(f, score))
    ranked.sort(
        key=lambda x: (-x.score, x.finding.file, x.finding.lineno, x.finding.qualname),
    )
    return ranked
