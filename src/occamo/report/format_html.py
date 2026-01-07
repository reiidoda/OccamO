from __future__ import annotations

from html import escape
from pathlib import Path

from .models import OccamOReport
from .severity import severity_rank


def _severity_class(severity: str) -> str:
    value = severity.lower()
    if value in {"critical", "high"}:
        return "sev-high"
    if value == "medium":
        return "sev-medium"
    if value == "low":
        return "sev-low"
    return "sev-info"


def _row(cells: list[str]) -> str:
    inner = "".join(f"<td>{cell}</td>" for cell in cells)
    return f"<tr>{inner}</tr>"


def to_html(report: OccamOReport, top_n: int = 10) -> str:
    lines: list[str] = []
    lines.append("<!doctype html>")
    lines.append('<html lang="en">')
    lines.append("<head>")
    lines.append('<meta charset="utf-8">')
    lines.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    lines.append("<title>OccamO report</title>")
    lines.append(
        "<style>"
        "body{font-family:'IBM Plex Sans','Segoe UI',sans-serif;background:#f6f3ee;color:#1f2a2e;"
        "margin:0;padding:24px;}h1{margin:0 0 12px;}h2{margin-top:28px;}"
        ".meta{list-style:none;padding:0;margin:0 0 18px;display:grid;grid-template-columns:"
        "repeat(auto-fit,minmax(220px,1fr));gap:6px;} .card{background:#ffffff;border-radius:14px;"
        "padding:16px 18px;box-shadow:0 8px 24px rgba(31,42,46,0.08);margin-bottom:18px;}"
        "table{width:100%;border-collapse:collapse;margin-top:8px;font-size:14px;}"
        "th,td{padding:8px 10px;border-bottom:1px solid #e7e2d9;text-align:left;vertical-align:top;}"
        "th{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:#5b666a;}"
        ".sev-high{color:#8c1d18;font-weight:600;}"
        ".sev-medium{color:#a35a00;font-weight:600;}"
        ".sev-low{color:#2b5f8a;font-weight:600;}"
        ".sev-info{color:#4b5563;font-weight:600;}"
        ".tag{display:inline-block;padding:2px 8px;border-radius:999px;background:#edf2f7;font-size:12px;}"
        ".note{color:#586069;font-size:13px;}"
        "</style>"
    )
    lines.append("</head>")
    lines.append("<body>")
    lines.append("<h1>OccamO report</h1>")
    lines.append("<div class=\"card\">")
    lines.append("<ul class=\"meta\">")
    lines.append(f"<li><span class=\"tag\">Generated</span> {escape(report.generated_at)}</li>")
    lines.append(
        f"<li><span class=\"tag\">Mode</span> "
        f"{'changed-only' if report.changed_only else 'full-scan'}</li>"
    )
    lines.append(f"<li><span class=\"tag\">Base ref</span> {escape(report.base_ref)}</li>")
    lines.append(
        f"<li><span class=\"tag\">Baseline compare</span> "
        f"{'enabled' if report.regression_mode else 'disabled'}</li>"
    )
    lines.append(f"<li><span class=\"tag\">Schema</span> v{report.schema_version}</li>")
    if report.suppressions:
        lines.append(f"<li><span class=\"tag\">Suppressions</span> {len(report.suppressions)}</li>")
    if report.stats:
        lines.append(f"<li><span class=\"tag\">Findings</span> {report.stats.findings_total}</li>")
        if report.regression_mode:
            lines.append(
                f"<li><span class=\"tag\">Regressions</span> {report.stats.regressions_total}</li>"
            )
        if report.stats.severity_counts:
            severity_ordered = sorted(
                report.stats.severity_counts.items(),
                key=lambda item: severity_rank(item[0]),
                reverse=True,
            )
            severity_str = ", ".join(f"{key}:{value}" for key, value in severity_ordered)
            lines.append(
                f"<li><span class=\"tag\">By severity</span> {escape(severity_str)}</li>"
            )
    lines.append("</ul>")
    lines.append("</div>")

    if report.regression_mode:
        lines.append("<div class=\"card\">")
        lines.append("<h2>Regressions vs base</h2>")
        if report.regressions:
            has_dynamic = any(r.dynamic for r in report.regressions)
            headers = [
                "Severity",
                "Risk Delta",
                "Hint Delta",
                "Dynamic" if has_dynamic else None,
                "Base",
                "Head",
                "Location",
                "Why",
            ]
            lines.append("<table><thead><tr>")
            for header in headers:
                if header:
                    lines.append(f"<th>{escape(header)}</th>")
            lines.append("</tr></thead><tbody>")
            for r in report.regressions[:top_n]:
                hint_delta = f"{r.hint_delta:+d}" if r.hint_delta is not None else "n/a"
                base = f"{r.base_risk_score:.3f} / {escape(r.base_hint)}"
                head = f"{r.head_risk_score:.3f} / {escape(r.head_hint)}"
                loc = f"{escape(r.file)}:{r.lineno} {escape(r.qualname)}"
                severity = r.regression_severity or "low"
                why = escape(r.explanation or "Risk score increased.")
                dynamic = ""
                if has_dynamic:
                    if r.dynamic:
                        if r.dynamic.status in {"confirmed", "downgraded"}:
                            dynamic = f"{r.dynamic.status} ({r.dynamic.ratio:.2f}x)"
                        else:
                            dynamic = r.dynamic.status
                    else:
                        dynamic = "n/a"
                cells = [
                    f"<span class=\"{_severity_class(severity)}\">{escape(severity)}</span>",
                    f"{r.risk_delta:+.3f}",
                    hint_delta,
                ]
                if has_dynamic:
                    cells.append(escape(dynamic))
                cells.extend([base, head, loc, why])
                lines.append(_row([escape(cell) if idx in {1, 2} else cell for idx, cell in enumerate(cells)]))
            lines.append("</tbody></table>")
            if len(report.regressions) > top_n:
                lines.append(
                    f"<p class=\"note\">+{len(report.regressions) - top_n} more regressions</p>"
                )
            regression_suggestions = [
                (r, r.suggestions) for r in report.regressions[:top_n] if r.suggestions
            ]
            if regression_suggestions:
                lines.append("<h3>Fix suggestions</h3>")
                lines.append("<ul>")
                for r, items in regression_suggestions:
                    loc = f"{escape(r.file)}:{r.lineno} {escape(r.qualname)}"
                    joined = escape("; ".join(items))
                    lines.append(f"<li><strong>{loc}</strong>: {joined}</li>")
                lines.append("</ul>")
        else:
            lines.append("<p class=\"note\">No regressions vs base.</p>")
        lines.append("</div>")

    if report.findings:
        lines.append("<div class=\"card\">")
        lines.append("<h2>Top hotspots</h2>")
        has_dynamic = any(f.dynamic for f in report.findings[:top_n])
        headers = [
            "Severity",
            "Risk",
            "Confidence",
            "Dynamic" if has_dynamic else None,
            "Hint",
            "Location",
        ]
        lines.append("<table><thead><tr>")
        for header in headers:
            if header:
                lines.append(f"<th>{escape(header)}</th>")
        lines.append("</tr></thead><tbody>")
        for f in report.findings[:top_n]:
            loc = f"{escape(f.file)}:{f.lineno} {escape(f.qualname)}"
            dynamic = ""
            if has_dynamic:
                if f.dynamic:
                    dynamic = f"{f.dynamic.status} ({f.dynamic.label})"
                else:
                    dynamic = "n/a"
            cells = [
                f"<span class=\"{_severity_class(f.severity)}\">{escape(f.severity)}</span>",
                f"{f.risk_score:.3f}",
                f"{f.confidence:.2f}",
            ]
            if has_dynamic:
                cells.append(escape(dynamic))
            cells.extend([escape(f.complexity_hint), loc])
            lines.append(_row([escape(cell) if idx in {1, 2} else cell for idx, cell in enumerate(cells)]))
        lines.append("</tbody></table>")
        finding_suggestions = [
            (f, f.suggestions) for f in report.findings[:top_n] if f.suggestions
        ]
        if finding_suggestions:
            lines.append("<h3>Fix suggestions</h3>")
            lines.append("<ul>")
            for f, items in finding_suggestions:
                loc = f"{escape(f.file)}:{f.lineno} {escape(f.qualname)}"
                joined = escape("; ".join(items))
                lines.append(f"<li><strong>{loc}</strong>: {joined}</li>")
            lines.append("</ul>")
        lines.append("</div>")
    else:
        lines.append("<div class=\"card\"><p class=\"note\">No findings.</p></div>")

    if report.suppressions:
        lines.append("<div class=\"card\">")
        lines.append("<h2>Suppressions</h2>")
        lines.append("<table><thead><tr>")
        for header in ["Location", "Reason", "Ticket", "Comment"]:
            lines.append(f"<th>{escape(header)}</th>")
        lines.append("</tr></thead><tbody>")
        for s in report.suppressions[:top_n]:
            loc = f"{escape(s.file)}:{s.lineno} {escape(s.qualname)}"
            reason = escape(s.reason or "n/a")
            ticket = escape(s.ticket or "n/a")
            comment = escape(s.comment or "occamo: ignore")
            lines.append(_row([loc, reason, ticket, comment]))
        lines.append("</tbody></table>")
        if len(report.suppressions) > top_n:
            lines.append(
                f"<p class=\"note\">+{len(report.suppressions) - top_n} more suppressions</p>"
            )
        lines.append("</div>")

    lines.append("<p class=\"note\">OccamO uses static heuristics; dynamic verification is optional.</p>")
    lines.append("</body></html>")
    return "\n".join(lines)


def write_html(report: OccamOReport, path: Path, top_n: int = 10) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_html(report, top_n=top_n), encoding="utf-8")
