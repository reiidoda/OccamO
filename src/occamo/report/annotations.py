from __future__ import annotations

from .models import OccamOReport
from .severity import github_annotation_level, severity_from_score


def _escape_github_command(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def to_github_annotations(report: OccamOReport, top_n: int = 10) -> str:
    lines: list[str] = []

    if report.regression_mode:
        if report.regressions:
            for r in report.regressions:
                severity = severity_from_score(r.head_risk_score)
                level = github_annotation_level(severity)
                title = _escape_github_command("OccamO regression")
                message = _escape_github_command(
                    f"Risk +{r.risk_delta:.3f}: {r.base_hint} -> {r.head_hint} ({r.qualname}). {r.explanation}"
                )
                lines.append(f"::{level} file={r.file},line={r.lineno},title={title}::{message}")
            return "\n".join(lines)
        return ""

    for f in report.findings[:top_n]:
        level = github_annotation_level(f.severity)
        title = _escape_github_command("OccamO hotspot")
        message = _escape_github_command(
            f"{f.complexity_hint} (risk {f.risk_score:.3f}, {f.qualname})"
        )
        lines.append(f"::{level} file={f.file},line={f.lineno},title={title}::{message}")

    return "\n".join(lines)
