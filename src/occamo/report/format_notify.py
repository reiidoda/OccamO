from __future__ import annotations

from typing import Any

from .models import OccamOReport, RegressionFinding
from .severity import normalize_severity, severity_rank


def _select_regressions(
    report: OccamOReport,
    min_severity: str,
    max_items: int,
) -> list[RegressionFinding]:
    threshold = severity_rank(normalize_severity(min_severity))
    items = [
        r for r in report.regressions if severity_rank(r.regression_severity) >= threshold
    ]
    items.sort(key=lambda r: (-r.risk_delta, r.file, r.lineno, r.qualname))
    return items[: max(0, max_items or len(items))]


def slack_payload(
    report: OccamOReport,
    min_severity: str = "high",
    max_items: int = 5,
) -> dict[str, Any]:
    items = _select_regressions(report, min_severity, max_items)
    if not items:
        text = f"OccamO: no regressions meeting severity >= {min_severity}."
        return {"text": text}
    lines = [f"*OccamO regressions* (severity >= {min_severity})"]
    for r in items:
        loc = f"{r.file}:{r.lineno} `{r.qualname}`"
        lines.append(
            f"- {r.regression_severity.upper()} delta {r.risk_delta:+.2f} {loc} - {r.explanation}"
        )
    return {"text": "\n".join(lines)}


def teams_payload(
    report: OccamOReport,
    min_severity: str = "high",
    max_items: int = 5,
) -> dict[str, Any]:
    items = _select_regressions(report, min_severity, max_items)
    if not items:
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": "OccamO regressions",
            "themeColor": "2f855a",
            "sections": [
                {
                    "activityTitle": "OccamO regressions",
                    "text": f"No regressions meeting severity >= {min_severity}.",
                }
            ],
        }
    lines = []
    for r in items:
        loc = f"{r.file}:{r.lineno} {r.qualname}"
        lines.append(
            f"- **{r.regression_severity.upper()}** delta {r.risk_delta:+.2f} {loc} - {r.explanation}"
        )
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "OccamO regressions",
        "themeColor": "c53030",
        "sections": [
            {
                "activityTitle": f"OccamO regressions (severity >= {min_severity})",
                "text": "\n".join(lines),
            }
        ],
    }
