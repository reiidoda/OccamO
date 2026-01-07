from __future__ import annotations

from .models import OccamOReport
from .severity import check_run_annotation_level, severity_from_score


def _link(path: str, line: int, repo_url: str | None, sha: str | None) -> str:
    if repo_url and sha:
        url = f"{repo_url}/blob/{sha}/{path}#L{line}"
        return f"[{path}:{line}]({url})"
    return f"{path}:{line}"


def to_check_run_output(
    report: OccamOReport,
    top_n: int = 10,
    repo_url: str | None = None,
    sha: str | None = None,
) -> dict:
    title = "OccamO analysis"
    regressions_count = (
        report.stats.regressions_total
        if report.stats and report.regression_mode
        else len(report.regressions)
    )
    findings_count = report.stats.findings_total if report.stats else len(report.findings)
    summary_lines = [
        f"Mode: {'changed-only' if report.changed_only else 'full-scan'}",
        f"Baseline compare: {'enabled' if report.regression_mode else 'disabled'}",
        f"Regressions: {regressions_count}" if report.regression_mode else "Regressions: n/a",
        f"Findings: {findings_count}",
    ]
    if report.suppressions:
        summary_lines.append(f"Suppressions: {len(report.suppressions)}")
    summary = "\n".join(f"- {line}" for line in summary_lines)

    text_lines: list[str] = []
    if report.regression_mode:
        if report.regressions:
            text_lines.append("**Regressions**")
            text_lines.append("")
            has_dynamic = any(r.dynamic for r in report.regressions[:top_n])
            if has_dynamic:
                text_lines.append("| Severity | Risk Δ | Hint Δ | Dynamic | Location | Why |")
                text_lines.append("|---|---:|---:|---|---|---|")
            else:
                text_lines.append("| Severity | Risk Δ | Hint Δ | Location | Why |")
                text_lines.append("|---|---:|---:|---|---|")
            for r in report.regressions[:top_n]:
                loc = _link(r.file, r.lineno, repo_url, sha)
                hint_delta = f"{r.hint_delta:+d}" if r.hint_delta is not None else "n/a"
                severity = r.regression_severity or "low"
                why = r.explanation or "Risk score increased."
                if has_dynamic:
                    reg_dynamic = r.dynamic
                    if reg_dynamic:
                        if reg_dynamic.status in {"confirmed", "downgraded"}:
                            dyn = f"{reg_dynamic.status} ({reg_dynamic.ratio:.2f}x)"
                        else:
                            dyn = reg_dynamic.status
                    else:
                        dyn = "n/a"
                    text_lines.append(
                        f"| {severity} | {r.risk_delta:+.3f} | {hint_delta} | {dyn} | {loc} `{r.qualname}` | {why} |"
                    )
                else:
                    text_lines.append(
                        f"| {severity} | {r.risk_delta:+.3f} | {hint_delta} | {loc} `{r.qualname}` | {why} |"
                    )
        else:
            text_lines.append("_No regressions vs base._")
    elif report.findings:
        text_lines.append("**Top hotspots**")
        text_lines.append("")
        has_dynamic = any(f.dynamic for f in report.findings[:top_n])
        if has_dynamic:
            text_lines.append("| Severity | Risk | Dynamic | Location |")
            text_lines.append("|---|---:|---|---|")
        else:
            text_lines.append("| Severity | Risk | Location |")
            text_lines.append("|---|---:|---|")
        for f in report.findings[:top_n]:
            loc = _link(f.file, f.lineno, repo_url, sha)
            if has_dynamic:
                finding_dynamic = f.dynamic
                dyn = f"{finding_dynamic.status} ({finding_dynamic.label})" if finding_dynamic else "n/a"
                text_lines.append(
                    f"| {f.severity} | {f.risk_score:.3f} | {dyn} | {loc} `{f.qualname}` |"
                )
            else:
                text_lines.append(f"| {f.severity} | {f.risk_score:.3f} | {loc} `{f.qualname}` |")
    else:
        text_lines.append("_No findings._")

    annotations = []
    if report.regression_mode:
        if report.regressions:
            for r in report.regressions[:top_n]:
                severity = severity_from_score(r.head_risk_score)
                annotations.append(
                    {
                        "path": r.file,
                        "start_line": r.lineno,
                        "end_line": r.lineno,
                        "annotation_level": check_run_annotation_level(severity),
                        "title": "OccamO regression",
                        "message": (
                            f"Risk +{r.risk_delta:.3f}: {r.base_hint} -> {r.head_hint} "
                            f"({r.qualname}). {r.explanation or ''}"
                        ).strip(),
                    }
                )
    else:
        for f in report.findings[:top_n]:
            annotations.append(
                {
                    "path": f.file,
                    "start_line": f.lineno,
                    "end_line": f.end_lineno,
                    "annotation_level": check_run_annotation_level(f.severity),
                    "title": "OccamO hotspot",
                    "message": f"{f.complexity_hint} (risk {f.risk_score:.3f}, {f.qualname})",
                }
            )

    return {
        "title": title,
        "summary": summary,
        "text": "\n".join(text_lines),
        "annotations": annotations,
    }
