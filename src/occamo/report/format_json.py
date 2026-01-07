from __future__ import annotations

import json
from pathlib import Path

from .models import (
    SCHEMA_VERSION,
    ChangeFinding,
    DynamicCheck,
    DynamicRegression,
    FindingReport,
    OccamOReport,
    RegressionFinding,
    ReportStats,
    Suppression,
)


def write_json(report: OccamOReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")


def read_json(path: Path) -> OccamOReport:
    raw = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for f in raw.get("findings", []):
        dynamic = None
        dynamic_raw = f.get("dynamic")
        if isinstance(dynamic_raw, dict):
            dynamic = DynamicCheck(
                label=str(dynamic_raw.get("label", "")),
                confidence=float(dynamic_raw.get("confidence", 0.0)),
                status=str(dynamic_raw.get("status", "")),
                note=str(dynamic_raw.get("note", "")),
            )
        findings.append(
            FindingReport(
                file=str(f.get("file", "")),
                qualname=str(f.get("qualname", "")),
                function_id=str(f.get("function_id", "")),
                lineno=int(f.get("lineno", 1)),
                end_lineno=int(f.get("end_lineno", f.get("lineno", 1))),
                severity=str(f.get("severity", "info")),
                complexity_hint=str(f.get("complexity_hint", "")),
                confidence=float(f.get("confidence", 0.0)),
                risk_score=float(f.get("risk_score", 0.0)),
                signals=dict(f.get("signals", {})),
                body_hash=str(f.get("body_hash", "")),
                explanation=str(f.get("explanation", "")),
                suggestions=list(f.get("suggestions", [])) if isinstance(f.get("suggestions", []), list) else [],
                rule_id=str(f.get("rule_id", "")),
                rule_name=str(f.get("rule_name", "")),
                dynamic=dynamic,
            )
        )
    regressions = []
    for r in raw.get("regressions", []):
        dynamic_reg = None
        dynamic_raw = r.get("dynamic")
        if isinstance(dynamic_raw, dict):
            dynamic_reg = DynamicRegression(
                status=str(dynamic_raw.get("status", "")),
                ratio=float(dynamic_raw.get("ratio", 0.0)),
                note=str(dynamic_raw.get("note", "")),
            )
        hint_delta = r.get("hint_delta")
        if hint_delta is not None:
            try:
                hint_delta = int(hint_delta)
            except (TypeError, ValueError):
                hint_delta = None
        regressions.append(
            RegressionFinding(
                file=str(r.get("file", "")),
                qualname=str(r.get("qualname", "")),
                function_id=str(r.get("function_id", "")),
                lineno=int(r.get("lineno", 1)),
                base_risk_score=float(r.get("base_risk_score", 0.0)),
                head_risk_score=float(r.get("head_risk_score", 0.0)),
                base_hint=str(r.get("base_hint", "")),
                head_hint=str(r.get("head_hint", "")),
                risk_delta=float(r.get("risk_delta", 0.0)),
                hint_delta=hint_delta,
                regression_severity=str(r.get("regression_severity", "")),
                explanation=str(r.get("explanation", "")),
                suggestions=list(r.get("suggestions", [])) if isinstance(r.get("suggestions", []), list) else [],
                base_signals=dict(r.get("base_signals", {})),
                head_signals=dict(r.get("head_signals", {})),
                dynamic=dynamic_reg,
            )
        )
    diffs = []
    for d in raw.get("diffs", []):
        hint_delta = d.get("hint_delta")
        if hint_delta is not None:
            try:
                hint_delta = int(hint_delta)
            except (TypeError, ValueError):
                hint_delta = None
        risk_delta = d.get("risk_delta")
        if risk_delta is not None:
            try:
                risk_delta = float(risk_delta)
            except (TypeError, ValueError):
                risk_delta = None
        diffs.append(
            ChangeFinding(
                file=str(d.get("file", "")),
                qualname=str(d.get("qualname", "")),
                function_id=str(d.get("function_id", "")),
                lineno=int(d.get("lineno", 1)),
                change_type=str(d.get("change_type", "")),
                trend=str(d.get("trend", "")),
                base_risk_score=(
                    float(d.get("base_risk_score")) if d.get("base_risk_score") is not None else None
                ),
                head_risk_score=(
                    float(d.get("head_risk_score")) if d.get("head_risk_score") is not None else None
                ),
                base_hint=(
                    str(d.get("base_hint")) if d.get("base_hint") is not None else None
                ),
                head_hint=(
                    str(d.get("head_hint")) if d.get("head_hint") is not None else None
                ),
                risk_delta=risk_delta,
                hint_delta=hint_delta,
                regression_severity=(
                    str(d.get("regression_severity")) if d.get("regression_severity") is not None else None
                ),
            )
        )
    stats_raw = raw.get("stats")
    stats = None
    if isinstance(stats_raw, dict):
        stats = ReportStats(
            findings_total=int(stats_raw.get("findings_total", 0)),
            regressions_total=int(stats_raw.get("regressions_total", 0)),
            severity_counts=dict(stats_raw.get("severity_counts", {})),
            hint_counts=dict(stats_raw.get("hint_counts", {})),
            max_risk_score=float(stats_raw.get("max_risk_score", 0.0)),
            avg_risk_score=float(stats_raw.get("avg_risk_score", 0.0)),
            max_regression_delta=float(stats_raw.get("max_regression_delta", 0.0)),
        )
    suppressions = []
    for s in raw.get("suppressions", []):
        suppressions.append(
            Suppression(
                file=str(s.get("file", "")),
                qualname=str(s.get("qualname", "")),
                function_id=str(s.get("function_id", "")),
                lineno=int(s.get("lineno", 1)),
                end_lineno=int(s.get("end_lineno", s.get("lineno", 1))),
                comment_line=int(s.get("comment_line", 0)),
                reason=str(s.get("reason", "")),
                ticket=str(s.get("ticket", "")),
                comment=str(s.get("comment", "")),
            )
        )

    return OccamOReport(
        schema_version=int(raw.get("schema_version", SCHEMA_VERSION)),
        generated_at=str(raw.get("generated_at", "")),
        repo_root=str(raw.get("repo_root", "")),
        changed_only=bool(raw.get("changed_only", False)),
        base_ref=str(raw.get("base_ref", "")),
        regression_mode=bool(raw.get("regression_mode", False)),
        findings=findings,
        regressions=regressions,
        stats=stats,
        diffs=diffs,
        suppressions=suppressions,
    )
