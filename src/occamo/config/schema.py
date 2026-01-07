from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SeverityOverride:
    pattern: str
    severity: str


@dataclass(frozen=True)
class RiskDeltaBudget:
    pattern: str
    budget: float


@dataclass(frozen=True)
class RuleSeverityOverride:
    rule_id: str
    severity: str


@dataclass(frozen=True)
class OccamOConfig:
    include: list[str] = field(default_factory=lambda: ["src"])
    exclude: list[str] = field(
        default_factory=lambda: [
            "tests",
            "test",
            "spec",
            "specs",
            "bench",
            "benchmarks",
            ".venv",
            "venv",
            ".tox",
            ".eggs",
            "build",
            "dist",
            "coverage",
            "htmlcov",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".cache",
            "node_modules",
            "vendor",
            ".git",
        ]
    )
    report_include: list[str] = field(default_factory=list)
    report_exclude: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=lambda: ["python"])
    max_files: int = 200
    changed_only: bool = False
    changed_only_strict: bool = False
    diff_functions: bool = True
    compare_base: bool = False
    min_confidence: float | None = None
    min_risk_score: float | None = None
    min_severity: str | None = None
    min_regression_risk_delta: float | None = None
    min_regression_hint_delta: int | None = None
    min_regression_severity: str | None = None
    min_function_lines: int | None = None
    warn_regression_risk_delta: float | None = None
    fail_regression_risk_delta: float | None = None
    dynamic_verify: bool = False
    dynamic_top: int = 5
    dynamic_timeout_seconds: float = 1.5
    dynamic_confidence: float = 0.6
    dynamic_trials: int = 3
    dynamic_slowdown_ratio: float = 1.2
    dynamic_warmups: int = 1
    dynamic_memory_limit_mb: int | None = None
    dynamic_jitter_threshold: float | None = 0.35
    dynamic_sizes: list[int] = field(default_factory=lambda: [16, 32, 64, 128])
    max_findings: int | None = None
    fail_on_finding_severity: str | None = None
    max_risk_score: float | None = None
    notify_min_severity: str = "high"
    notify_max_items: int = 5
    rules_enabled: bool = True
    rule_plugins: list[str] = field(default_factory=list)
    enabled_rules: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    rule_severity_overrides: list[RuleSeverityOverride] = field(default_factory=list)
    rule_config: dict[str, dict] = field(default_factory=dict)
    call_graph_enabled: bool = True
    call_graph_passes: int = 2
    hot_paths: list[str] = field(default_factory=list)
    hot_functions: list[str] = field(default_factory=list)
    hot_path_multiplier: float = 1.5
    hot_profile_path: str | None = None
    hot_profile_top: int = 20
    hot_trace_summary_path: str | None = None
    parallel_workers: int = 0
    analysis_time_budget_seconds: float | None = None
    cache_path: str | None = None
    use_cache: bool = True
    gating_preset: str | None = None
    fail_on_regressions: bool = False
    fail_on_severity: str | None = None
    max_regressions: int | None = None
    max_high_regressions: int | None = None
    max_risk_delta: float | None = None
    risk_delta_budget: float | None = None
    risk_delta_budgets: list[RiskDeltaBudget] = field(default_factory=list)
    severity_overrides: list[SeverityOverride] = field(default_factory=list)
    loop_depth_fail_paths: list[str] = field(default_factory=list)
    no_regressions_paths: list[str] = field(default_factory=list)
    new_findings_only: bool = False
