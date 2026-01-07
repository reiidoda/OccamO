from __future__ import annotations

from .models import OccamOReport
from .severity import severity_rank


def to_markdown(report: OccamOReport, top_n: int = 10) -> str:
    lines: list[str] = []
    lines.append("# OccamO report")
    lines.append("")
    lines.append(f"- Generated: `{report.generated_at}`")
    lines.append(f"- Mode: `{'changed-only' if report.changed_only else 'full-scan'}`")
    lines.append(f"- Base ref: `{report.base_ref}`")
    lines.append(f"- Baseline compare: `{'enabled' if report.regression_mode else 'disabled'}`")
    lines.append(f"- Schema: `v{report.schema_version}`")
    if report.suppressions:
        lines.append(f"- Suppressions: `{len(report.suppressions)}`")
    if report.stats:
        lines.append(f"- Findings: `{report.stats.findings_total}`")
        if report.regression_mode:
            lines.append(f"- Regressions: `{report.stats.regressions_total}`")
        if report.stats.severity_counts:
            severity_ordered = sorted(
                report.stats.severity_counts.items(),
                key=lambda item: severity_rank(item[0]),
                reverse=True,
            )
            severity_str = ", ".join(f"{key}:{value}" for key, value in severity_ordered)
            lines.append(f"- Findings by severity: `{severity_str}`")
    lines.append("")

    if report.regression_mode:
        if report.regressions:
            lines.append("## Regressions vs base")
            lines.append("")
            has_dynamic = any(r.dynamic for r in report.regressions)
            if has_dynamic:
                lines.append("| Severity | Risk Δ | Hint Δ | Dynamic | Base | Head | Location | Why |")
                lines.append("|---|---:|---:|---|---|---|---|---|")
            else:
                lines.append("| Severity | Risk Δ | Hint Δ | Base | Head | Location | Why |")
                lines.append("|---|---:|---:|---|---|---|---|")
            for r in report.regressions:
                loc = f"{r.file}:{r.lineno} `{r.qualname}`"
                hint_delta = f"{r.hint_delta:+d}" if r.hint_delta is not None else "n/a"
                base = f"{r.base_risk_score:.3f} / {r.base_hint}"
                head = f"{r.head_risk_score:.3f} / {r.head_hint}"
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
                    lines.append(
                        f"| {severity} | {r.risk_delta:+.3f} | {hint_delta} | {dyn} | {base} | {head} | {loc} | {why} |"
                    )
                else:
                    lines.append(
                        f"| {severity} | {r.risk_delta:+.3f} | {hint_delta} | {base} | {head} | {loc} | {why} |"
                    )
            lines.append("")
            regression_suggestions = [
                (r, r.suggestions) for r in report.regressions if r.suggestions
            ]
            if regression_suggestions:
                lines.append("### Fix suggestions")
                lines.append("")
                for r, items in regression_suggestions:
                    loc = f"{r.file}:{r.lineno} `{r.qualname}`"
                    joined = "; ".join(items)
                    lines.append(f"- {loc}: {joined}")
                lines.append("")
        else:
            lines.append("✅ No regressions vs base.")
            lines.append("")

    if report.diffs:
        added = sum(1 for d in report.diffs if d.change_type == "added")
        removed = sum(1 for d in report.diffs if d.change_type == "removed")
        changed = sum(1 for d in report.diffs if d.change_type == "changed")
        lines.append("## Change summary (base -> head)")
        lines.append("")
        lines.append(
            f"- Added: `{added}`  Removed: `{removed}`  Changed: `{changed}`"
        )
        lines.append("")
        lines.append("| Type | Trend | Risk (base -> head) | Hint (base -> head) | Location |")
        lines.append("|---|---|---|---|---|")
        diffs_ordered = sorted(
            report.diffs,
            key=lambda d: (
                0 if d.trend == "worse" else 1 if d.trend == "new" else 2 if d.trend == "better" else 3,
                d.file,
                d.lineno,
            ),
        )
        for d in diffs_ordered[:top_n]:
            risk = (
                f"{d.base_risk_score:.3f} -> {d.head_risk_score:.3f}"
                if d.base_risk_score is not None and d.head_risk_score is not None
                else "n/a"
            )
            hint = (
                f"{d.base_hint} -> {d.head_hint}"
                if d.base_hint is not None and d.head_hint is not None
                else "n/a"
            )
            loc = f"{d.file}:{d.lineno} `{d.qualname}`"
            lines.append(f"| {d.change_type} | {d.trend} | {risk} | {hint} | {loc} |")
        if len(report.diffs) > top_n:
            lines.append("")
            lines.append(f"_+{len(report.diffs) - top_n} more changes_")
        lines.append("")

    if report.suppressions:
        lines.append("## Suppressions")
        lines.append("")
        lines.append("| Location | Reason | Ticket | Comment |")
        lines.append("|---|---|---|---|")
        for s in report.suppressions[:top_n]:
            loc = f"{s.file}:{s.lineno} `{s.qualname}`"
            reason = s.reason or "n/a"
            ticket = s.ticket or "n/a"
            comment = s.comment or "occamo: ignore"
            lines.append(f"| {loc} | {reason} | {ticket} | {comment} |")
        if len(report.suppressions) > top_n:
            lines.append("")
            lines.append(f"_+{len(report.suppressions) - top_n} more suppressions_")
        lines.append("")

    if not report.findings:
        lines.append("✅ No findings (or no analyzable functions found).")
        return "\n".join(lines)

    lines.append("## Top hotspots (heuristic)")
    lines.append("")
    has_dynamic = any(f.dynamic for f in report.findings[:top_n])
    if has_dynamic:
        lines.append("| Severity | Risk | Confidence | Dynamic | Hint | Location |")
        lines.append("|---|---:|---:|---|---|---|")
    else:
        lines.append("| Severity | Risk | Confidence | Hint | Location |")
        lines.append("|---|---:|---:|---|---|")
    for f in report.findings[:top_n]:
        loc = f"{f.file}:{f.lineno} `{f.qualname}`"
        if has_dynamic:
            finding_dynamic = f.dynamic
            dyn = f"{finding_dynamic.status} ({finding_dynamic.label})" if finding_dynamic else "n/a"
            lines.append(
                f"| {f.severity} | {f.risk_score:.3f} | {f.confidence:.2f} | {dyn} | {f.complexity_hint} | {loc} |"
            )
        else:
            lines.append(
                f"| {f.severity} | {f.risk_score:.3f} | {f.confidence:.2f} | {f.complexity_hint} | {loc} |"
            )

    lines.append("")
    finding_suggestions = [
        (f, f.suggestions) for f in report.findings[:top_n] if f.suggestions
    ]
    if finding_suggestions:
        lines.append("### Fix suggestions")
        lines.append("")
        for f, items in finding_suggestions:
            loc = f"{f.file}:{f.lineno} `{f.qualname}`"
            joined = "; ".join(items)
            lines.append(f"- {loc}: {joined}")
        lines.append("")
    lines.append(
        "> Notes: OccamO uses static AST heuristics; dynamic verification is optional and best-effort."
    )
    return "\n".join(lines)
