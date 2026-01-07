from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import OccamOReport, ReportStats


def _stats_from_report(report: OccamOReport) -> ReportStats:
    if report.stats is not None:
        return report.stats
    findings_total = len(report.findings)
    regressions_total = len(report.regressions)
    max_risk_score = max((f.risk_score for f in report.findings), default=0.0)
    avg_risk_score = (
        sum(f.risk_score for f in report.findings) / findings_total if findings_total else 0.0
    )
    max_regression_delta = max((r.risk_delta for r in report.regressions), default=0.0)
    return ReportStats(
        findings_total=findings_total,
        regressions_total=regressions_total,
        severity_counts={},
        hint_counts={},
        max_risk_score=max_risk_score,
        avg_risk_score=avg_risk_score,
        max_regression_delta=max_regression_delta,
    )


def trend_entry(report: OccamOReport, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    stats = _stats_from_report(report)
    entry = {
        "generated_at": report.generated_at,
        "findings_total": stats.findings_total,
        "regressions_total": stats.regressions_total,
        "max_risk_score": stats.max_risk_score,
        "avg_risk_score": stats.avg_risk_score,
        "max_regression_delta": stats.max_regression_delta,
        "base_ref": report.base_ref,
        "changed_only": report.changed_only,
    }
    if extra:
        entry.update(extra)
    return entry


def update_trend(
    report: OccamOReport,
    path: Path,
    max_entries: int = 200,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {"schema_version": 1, "entries": []}
    if path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                data["entries"] = raw
            elif isinstance(raw, dict):
                data = {"schema_version": int(raw.get("schema_version", 1)), "entries": raw.get("entries", [])}
        except Exception:
            data = {"schema_version": 1, "entries": []}
    entries: list[dict[str, Any]] = list(data.get("entries", []))
    entries.append(trend_entry(report, extra=extra))
    if max_entries and len(entries) > max_entries:
        entries = entries[-max_entries:]
    data["entries"] = entries
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def _sparkline(values: list[float], width: int, height: int, padding: int) -> str:
    if not values:
        return ""
    lo = min(values)
    hi = max(values)
    if hi == lo:
        hi = lo + 1.0
    span_x = max(1, len(values) - 1)
    points = []
    for idx, value in enumerate(values):
        x = padding + (width - 2 * padding) * (idx / span_x)
        y = padding + (height - 2 * padding) * (1.0 - (value - lo) / (hi - lo))
        points.append(f"{x:.1f},{y:.1f}")
    return " ".join(points)


def trend_to_html(trend_data: dict[str, Any], title: str = "OccamO trend") -> str:
    entries = trend_data.get("entries", [])
    values = [float(item.get("max_risk_score", 0.0) or 0.0) for item in entries]
    reg_values = [float(item.get("regressions_total", 0.0) or 0.0) for item in entries]
    width = 720
    height = 180
    padding = 16
    risk_points = _sparkline(values, width, height, padding)
    reg_points = _sparkline(reg_values, width, height, padding)
    lines = [
        "<!doctype html>",
        "<html lang=\"en\">",
        "<head>",
        "<meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        f"<title>{title}</title>",
        "<style>",
        "body{font-family:'IBM Plex Sans','Segoe UI',sans-serif;background:#f6f3ee;color:#1f2a2e;"
        "margin:0;padding:24px;}h1{margin:0 0 16px;} .card{background:#ffffff;border-radius:16px;"
        "padding:16px 18px;box-shadow:0 16px 30px rgba(31,42,46,0.12);} .note{color:#5b666a;}"
        "svg{width:100%;height:auto;}",
        "</style>",
        "</head>",
        "<body>",
        f"<h1>{title}</h1>",
        "<div class=\"card\">",
        "<svg viewBox=\"0 0 720 180\" preserveAspectRatio=\"none\">",
        "<rect x=\"0\" y=\"0\" width=\"720\" height=\"180\" fill=\"#f4efe7\" rx=\"12\" />",
    ]
    if risk_points:
        lines.append(f"<polyline points=\"{risk_points}\" fill=\"none\" stroke=\"#f97316\" stroke-width=\"3\"/>")
    if reg_points:
        lines.append(f"<polyline points=\"{reg_points}\" fill=\"none\" stroke=\"#38bdf8\" stroke-width=\"2\"/>")
    if not entries:
        lines.append("<text x=\"24\" y=\"92\" fill=\"#5b666a\">No trend data yet.</text>")
    lines.extend(
        [
            "</svg>",
            "<p class=\"note\">Orange: max risk score, Blue: regressions count</p>",
            "</div>",
            "</body></html>",
        ]
    )
    return "\n".join(lines)


def write_trend_html(trend_data: dict[str, Any], path: Path, title: str = "OccamO trend") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(trend_to_html(trend_data, title=title), encoding="utf-8")
