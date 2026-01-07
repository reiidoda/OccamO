from __future__ import annotations

from .models import OccamOReport
from .severity import severity_rank


def to_comment_markdown(report: OccamOReport, top_n: int = 10) -> str:
    lines: list[str] = []
    lines.append("<!-- occamo-comment -->")
    lines.append("### OccamO summary")
    lines.append("")
    lines.append(f"- Mode: `{'changed-only' if report.changed_only else 'full-scan'}`")
    lines.append(f"- Baseline compare: `{'enabled' if report.regression_mode else 'disabled'}`")
    if report.suppressions:
        lines.append(f"- Suppressions: `{len(report.suppressions)}`")
    if report.stats:
        if report.regression_mode:
            lines.append(f"- Regressions: `{report.stats.regressions_total}`")
        lines.append(f"- Findings: `{report.stats.findings_total}`")
        if report.stats.severity_counts:
            severity_ordered = sorted(
                report.stats.severity_counts.items(),
                key=lambda item: severity_rank(item[0]),
                reverse=True,
            )
            severity_str = ", ".join(f"{key}:{value}" for key, value in severity_ordered)
            lines.append(f"- Findings by severity: `{severity_str}`")
    else:
        if report.regression_mode:
            lines.append(f"- Regressions: `{len(report.regressions)}`")
        lines.append(f"- Findings: `{len(report.findings)}`")
    lines.append("")

    if report.regression_mode and report.regressions:
        lines.append("**Regressions**")
        lines.append("")
        has_dynamic = any(r.dynamic for r in report.regressions[:top_n])
        if has_dynamic:
            lines.append("| Severity | Risk (base -> head) | Hint (base -> head) | Dynamic | Location | Why |")
            lines.append("|---|---|---|---|---|---|")
        else:
            lines.append("| Severity | Risk (base -> head) | Hint (base -> head) | Location | Why |")
            lines.append("|---|---|---|---|---|")
        for r in report.regressions[:top_n]:
            loc = f"{r.file}:{r.lineno} `{r.qualname}`"
            risk = f"{r.base_risk_score:.3f} -> {r.head_risk_score:.3f} ({r.risk_delta:+.3f})"
            hint = f"{r.base_hint} -> {r.head_hint}"
            why = r.explanation or "Risk score increased."
            severity = r.regression_severity or "low"
            if has_dynamic:
                reg_dynamic = r.dynamic
                if reg_dynamic:
                    if reg_dynamic.status in {"confirmed", "downgraded"}:
                        dyn = f"{reg_dynamic.status} ({reg_dynamic.ratio:.2f}x)"
                    else:
                        dyn = reg_dynamic.status
                else:
                    dyn = "n/a"
                lines.append(f"| {severity} | {risk} | {hint} | {dyn} | {loc} | {why} |")
            else:
                lines.append(f"| {severity} | {risk} | {hint} | {loc} | {why} |")
        if len(report.regressions) > top_n:
            lines.append("")
            lines.append(f"_+{len(report.regressions) - top_n} more regressions_")
        regression_suggestions = [
            (r, r.suggestions) for r in report.regressions[:top_n] if r.suggestions
        ]
        if regression_suggestions:
            lines.append("")
            lines.append("**Fix ideas**")
            lines.append("")
            for r, items in regression_suggestions:
                loc = f"{r.file}:{r.lineno} `{r.qualname}`"
                joined = "; ".join(items)
                lines.append(f"- {loc}: {joined}")
        if report.suppressions:
            lines.append("")
            lines.append("**Suppressions**")
            lines.append("")
            lines.append("| Location | Reason | Ticket |")
            lines.append("|---|---|---|")
            for s in report.suppressions[:top_n]:
                loc = f"{s.file}:{s.lineno} `{s.qualname}`"
                reason = s.reason or "n/a"
                ticket = s.ticket or "n/a"
                lines.append(f"| {loc} | {reason} | {ticket} |")
        return "\n".join(lines)

    if report.regression_mode and not report.regressions:
        lines.append("No regressions vs base.")
        if report.suppressions:
            lines.append("")
            lines.append("**Suppressions**")
            lines.append("")
            lines.append("| Location | Reason | Ticket |")
            lines.append("|---|---|---|")
            for s in report.suppressions[:top_n]:
                loc = f"{s.file}:{s.lineno} `{s.qualname}`"
                reason = s.reason or "n/a"
                ticket = s.ticket or "n/a"
                lines.append(f"| {loc} | {reason} | {ticket} |")
        return "\n".join(lines)

    if not report.findings:
        lines.append("_No findings._")
        if report.suppressions:
            lines.append("")
            lines.append("**Suppressions**")
            lines.append("")
            lines.append("| Location | Reason | Ticket |")
            lines.append("|---|---|---|")
            for s in report.suppressions[:top_n]:
                loc = f"{s.file}:{s.lineno} `{s.qualname}`"
                reason = s.reason or "n/a"
                ticket = s.ticket or "n/a"
                lines.append(f"| {loc} | {reason} | {ticket} |")
        return "\n".join(lines)

    lines.append("**Top hotspots**")
    lines.append("")
    has_dynamic = any(f.dynamic for f in report.findings[:top_n])
    if has_dynamic:
        lines.append("| Severity | Risk | Dynamic | Location |")
        lines.append("|---|---:|---|---|")
    else:
        lines.append("| Severity | Risk | Location |")
        lines.append("|---|---:|---|")
    for f in report.findings[:top_n]:
        loc = f"{f.file}:{f.lineno} `{f.qualname}`"
        if has_dynamic:
            finding_dynamic = f.dynamic
            if finding_dynamic:
                dyn = f"{finding_dynamic.status} ({finding_dynamic.label})"
            else:
                dyn = "n/a"
            lines.append(f"| {f.severity} | {f.risk_score:.3f} | {dyn} | {loc} |")
        else:
            lines.append(f"| {f.severity} | {f.risk_score:.3f} | {loc} |")
    if len(report.findings) > top_n:
        lines.append("")
        lines.append(f"_+{len(report.findings) - top_n} more findings_")

    finding_suggestions = [
        (f, f.suggestions) for f in report.findings[:top_n] if f.suggestions
    ]
    if finding_suggestions:
        lines.append("")
        lines.append("**Fix ideas**")
        lines.append("")
        for f, items in finding_suggestions:
            loc = f"{f.file}:{f.lineno} `{f.qualname}`"
            joined = "; ".join(items)
            lines.append(f"- {loc}: {joined}")

    if report.suppressions:
        lines.append("")
        lines.append("**Suppressions**")
        lines.append("")
        lines.append("| Location | Reason | Ticket |")
        lines.append("|---|---|---|")
        for s in report.suppressions[:top_n]:
            loc = f"{s.file}:{s.lineno} `{s.qualname}`"
            reason = s.reason or "n/a"
            ticket = s.ticket or "n/a"
            lines.append(f"| {loc} | {reason} | {ticket} |")

    return "\n".join(lines)
