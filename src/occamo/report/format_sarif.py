from __future__ import annotations

import json
from pathlib import Path

from occamo import __version__

from .models import OccamOReport
from .severity import sarif_level, severity_from_score


def _relpath(path_str: str, repo_root: str) -> str:
    try:
        root = Path(repo_root).resolve()
        path = Path(path_str)
        if not path.is_absolute():
            return path.as_posix()
        return path.resolve().relative_to(root).as_posix()
    except Exception:
        return path_str


def _regression_keys(report: OccamOReport) -> set[tuple[str, str, int]]:
    return {(r.file, r.qualname, r.lineno) for r in report.regressions}


def to_sarif(report: OccamOReport) -> dict:
    rules = [
        {
            "id": "occamo.hotspot",
            "name": "Complexity hotspot",
            "shortDescription": {"text": "Potential complexity hotspot (heuristic)"},
            "fullDescription": {
                "text": "Static signals suggest elevated algorithmic complexity in this function.",
            },
            "help": {
                "text": "Review loop nesting, recursion, and sorting patterns to confirm complexity.",
                "markdown": (
                    "Static analysis detected signals (loops, recursion, sort calls) that may "
                    "indicate higher algorithmic complexity. Review the implementation to confirm."
                ),
            },
            "properties": {
                "tags": ["performance", "complexity", "occamo"],
                "precision": "medium",
            },
        },
        {
            "id": "occamo.regression",
            "name": "Complexity regression",
            "shortDescription": {"text": "Potential complexity regression vs baseline"},
            "fullDescription": {
                "text": "Static signals suggest complexity has increased compared to baseline.",
            },
            "help": {
                "text": "Compare baseline and head signals to confirm a regression.",
                "markdown": (
                    "OccamO detected a higher risk score or complexity hint compared to the "
                    "baseline. Review recent changes for added loops, recursion, or sorting."
                ),
            },
            "properties": {
                "tags": ["performance", "complexity", "regression", "occamo"],
                "precision": "high",
            },
        },
    ]

    results: list[dict] = []
    reg_keys = _regression_keys(report)
    for f in report.findings:
        if (f.file, f.qualname, f.lineno) in reg_keys:
            continue
        properties = {
            "risk_score": f.risk_score,
            "confidence": f.confidence,
            "severity": f.severity,
            "signals": f.signals,
        }
        if getattr(f, "explanation", ""):
            properties["explanation"] = f.explanation
        if getattr(f, "suggestions", None):
            properties["suggestions"] = f.suggestions
        finding_dynamic = f.dynamic
        if finding_dynamic is not None:
            properties["dynamic"] = {
                "label": finding_dynamic.label,
                "confidence": finding_dynamic.confidence,
                "status": finding_dynamic.status,
                "note": finding_dynamic.note,
            }
        results.append(
            {
                "ruleId": "occamo.hotspot",
                "level": sarif_level(f.severity),
                "message": {
                    "text": f"{f.complexity_hint} (risk {f.risk_score:.3f}, {f.qualname})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _relpath(f.file, report.repo_root),
                            },
                            "region": {
                                "startLine": f.lineno,
                                "endLine": max(f.end_lineno, f.lineno),
                            },
                        }
                    }
                ],
                "properties": properties,
            }
        )

    for r in report.regressions:
        severity = severity_from_score(r.head_risk_score)
        results.append(
            {
                "ruleId": "occamo.regression",
                "level": sarif_level(severity),
                "message": {
                    "text": (
                        f"Risk +{r.risk_delta:.3f}: {r.base_hint} -> {r.head_hint} ({r.qualname})"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _relpath(r.file, report.repo_root),
                            },
                            "region": {"startLine": r.lineno},
                        }
                    }
                ],
                "properties": {
                    "risk_delta": r.risk_delta,
                    "base_hint": r.base_hint,
                    "head_hint": r.head_hint,
                    "base_risk_score": r.base_risk_score,
                    "head_risk_score": r.head_risk_score,
                    "regression_severity": r.regression_severity,
                    "explanation": r.explanation,
                    "suggestions": r.suggestions,
                    "base_signals": r.base_signals,
                    "head_signals": r.head_signals,
                },
            }
        )
        regression_dynamic = r.dynamic
        if regression_dynamic is not None:
            results[-1]["properties"]["dynamic"] = {
                "status": regression_dynamic.status,
                "ratio": regression_dynamic.ratio,
                "note": regression_dynamic.note,
            }

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "automationDetails": {"id": "occamo-analysis"},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": report.generated_at,
                    }
                ],
                "tool": {
                    "driver": {
                        "name": "OccamO",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(report: OccamOReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_sarif(report), indent=2), encoding="utf-8")
