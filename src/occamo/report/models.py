from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = 7


@dataclass(frozen=True)
class DynamicCheck:
    label: str
    confidence: float
    status: str
    note: str = ""


@dataclass(frozen=True)
class DynamicRegression:
    status: str
    ratio: float
    note: str = ""


@dataclass(frozen=True)
class Suppression:
    file: str
    qualname: str
    function_id: str
    lineno: int
    end_lineno: int
    comment_line: int
    reason: str = ""
    ticket: str = ""
    comment: str = ""


@dataclass(frozen=True)
class FindingReport:
    file: str
    qualname: str
    function_id: str
    lineno: int
    end_lineno: int
    severity: str
    complexity_hint: str
    confidence: float
    risk_score: float
    signals: dict[str, Any]
    body_hash: str
    explanation: str = ""
    suggestions: list[str] = field(default_factory=list)
    rule_id: str = ""
    rule_name: str = ""
    dynamic: DynamicCheck | None = None


@dataclass(frozen=True)
class RegressionFinding:
    file: str
    qualname: str
    function_id: str
    lineno: int
    base_risk_score: float
    head_risk_score: float
    base_hint: str
    head_hint: str
    risk_delta: float
    hint_delta: int | None
    regression_severity: str
    explanation: str
    suggestions: list[str]
    base_signals: dict[str, Any]
    head_signals: dict[str, Any]
    dynamic: DynamicRegression | None = None


@dataclass(frozen=True)
class ChangeFinding:
    file: str
    qualname: str
    function_id: str
    lineno: int
    change_type: str
    trend: str
    base_risk_score: float | None
    head_risk_score: float | None
    base_hint: str | None
    head_hint: str | None
    risk_delta: float | None
    hint_delta: int | None
    regression_severity: str | None


@dataclass(frozen=True)
class ReportStats:
    findings_total: int
    regressions_total: int
    severity_counts: dict[str, int]
    hint_counts: dict[str, int]
    max_risk_score: float
    avg_risk_score: float
    max_regression_delta: float


@dataclass(frozen=True)
class OccamOReport:
    schema_version: int
    generated_at: str
    repo_root: str
    changed_only: bool
    base_ref: str
    regression_mode: bool
    findings: list[FindingReport]
    regressions: list[RegressionFinding]
    stats: ReportStats | None = None
    diffs: list[ChangeFinding] = field(default_factory=list)
    suppressions: list[Suppression] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if data.get("stats") is None:
            data.pop("stats", None)
        return data
