from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

from .schema import OccamOConfig, RiskDeltaBudget, RuleSeverityOverride, SeverityOverride

log = logging.getLogger(__name__)


def _load_raw_config(path: Path) -> dict[str, Any]:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as e:
        log.warning("Failed to load %s (%s). Skipping.", path, e)
        return {}


def _get_list(raw: dict[str, Any], key: str) -> list[str] | None:
    if key not in raw:
        return None
    v = raw.get(key)
    if isinstance(v, list):
        return [str(x) for x in v]
    return None


def _get_int_list(raw: dict[str, Any], key: str) -> list[int] | None:
    if key not in raw:
        return None
    v = raw.get(key)
    if not isinstance(v, list):
        return None
    out: list[int] = []
    for item in v:
        try:
            out.append(int(item))
        except (TypeError, ValueError):
            continue
    return out


def _get_optional_int(raw: dict[str, Any], key: str) -> int | None:
    if key not in raw:
        return None
    v = raw.get(key)
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _get_optional_float(raw: dict[str, Any], key: str) -> float | None:
    if key not in raw:
        return None
    v = raw.get(key)
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _get_optional_str(raw: dict[str, Any], key: str) -> str | None:
    if key not in raw:
        return None
    v = raw.get(key)
    if v is None:
        return None
    return str(v)


def _get_bool(raw: dict[str, Any], key: str, default: bool) -> bool:
    if key not in raw:
        return default
    v = raw.get(key)
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        if v.strip().lower() in {"true", "yes", "1", "on"}:
            return True
        if v.strip().lower() in {"false", "no", "0", "off"}:
            return False
    return default


def _get_severity_overrides(raw: dict[str, Any]) -> list[SeverityOverride]:
    out: list[SeverityOverride] = []
    raw_overrides = raw.get("severity_overrides", [])
    if not isinstance(raw_overrides, list):
        return out
    for item in raw_overrides:
        if not isinstance(item, dict):
            continue
        pattern = str(item.get("pattern", "")).strip()
        severity = str(item.get("severity", "")).strip().lower()
        if not pattern or not severity:
            continue
        out.append(SeverityOverride(pattern=pattern, severity=severity))
    return out


def _get_risk_delta_budgets(raw: dict[str, Any]) -> list[RiskDeltaBudget]:
    out: list[RiskDeltaBudget] = []
    raw_budgets = raw.get("risk_delta_budgets", [])
    if not isinstance(raw_budgets, list):
        return out
    for item in raw_budgets:
        if not isinstance(item, dict):
            continue
        pattern = str(item.get("pattern", "")).strip()
        budget = item.get("budget")
        if budget is None:
            continue
        try:
            budget_val = float(budget)
        except (TypeError, ValueError):
            continue
        if not pattern:
            continue
        out.append(RiskDeltaBudget(pattern=pattern, budget=budget_val))
    return out


def _get_rule_severity_overrides(raw: dict[str, Any]) -> list[RuleSeverityOverride]:
    out: list[RuleSeverityOverride] = []
    raw_overrides = raw.get("rule_severity_overrides", [])
    if not isinstance(raw_overrides, list):
        return out
    for item in raw_overrides:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("rule_id", "")).strip()
        severity = str(item.get("severity", "")).strip().lower()
        if not rule_id or not severity:
            continue
        out.append(RuleSeverityOverride(rule_id=rule_id, severity=severity))
    return out


def _merge_config(
    base: OccamOConfig,
    raw: dict[str, Any],
    include_set: bool,
    exclude_set: bool,
) -> tuple[OccamOConfig, bool, bool]:
    include = base.include
    exclude = base.exclude
    report_include = base.report_include
    report_exclude = base.report_exclude
    languages = base.languages

    raw_include = _get_list(raw, "include")
    if raw_include is not None:
        if include_set:
            include = [*include, *raw_include]
        else:
            include = raw_include
            include_set = True

    raw_exclude = _get_list(raw, "exclude")
    if raw_exclude is not None:
        if exclude_set:
            exclude = [*exclude, *raw_exclude]
        else:
            exclude = raw_exclude
            exclude_set = True

    raw_report_include = _get_list(raw, "report_include")
    if raw_report_include is not None:
        report_include = [*report_include, *raw_report_include]

    raw_report_exclude = _get_list(raw, "report_exclude")
    if raw_report_exclude is not None:
        report_exclude = [*report_exclude, *raw_report_exclude]

    raw_languages = _get_list(raw, "languages")
    if raw_languages is not None:
        languages = raw_languages

    max_files = base.max_files
    if "max_files" in raw:
        try:
            max_files = int(raw.get("max_files", max_files))
        except (TypeError, ValueError):
            max_files = base.max_files

    changed_only = _get_bool(raw, "changed_only", base.changed_only)
    changed_only_strict = _get_bool(raw, "changed_only_strict", base.changed_only_strict)
    diff_functions = _get_bool(raw, "diff_functions", base.diff_functions)
    compare_base = _get_bool(raw, "compare_base", base.compare_base)
    min_confidence = _get_optional_float(raw, "min_confidence")
    if min_confidence is None:
        min_confidence = base.min_confidence
    min_risk_score = _get_optional_float(raw, "min_risk_score")
    if min_risk_score is None:
        min_risk_score = base.min_risk_score
    min_severity = _get_optional_str(raw, "min_severity")
    if min_severity is None:
        min_severity = base.min_severity
    min_regression_risk_delta = _get_optional_float(raw, "min_regression_risk_delta")
    if min_regression_risk_delta is None:
        min_regression_risk_delta = base.min_regression_risk_delta
    min_regression_hint_delta = _get_optional_int(raw, "min_regression_hint_delta")
    if min_regression_hint_delta is None:
        min_regression_hint_delta = base.min_regression_hint_delta
    min_regression_severity = _get_optional_str(raw, "min_regression_severity")
    if min_regression_severity is None:
        min_regression_severity = base.min_regression_severity
    min_function_lines = _get_optional_int(raw, "min_function_lines")
    if min_function_lines is None:
        min_function_lines = base.min_function_lines
    warn_regression_risk_delta = _get_optional_float(raw, "warn_regression_risk_delta")
    if warn_regression_risk_delta is None:
        warn_regression_risk_delta = base.warn_regression_risk_delta
    fail_regression_risk_delta = _get_optional_float(raw, "fail_regression_risk_delta")
    if fail_regression_risk_delta is None:
        fail_regression_risk_delta = base.fail_regression_risk_delta
    dynamic_verify = _get_bool(raw, "dynamic_verify", base.dynamic_verify)
    dynamic_top = _get_optional_int(raw, "dynamic_top")
    if dynamic_top is None:
        dynamic_top = base.dynamic_top
    dynamic_timeout_seconds = _get_optional_float(raw, "dynamic_timeout_seconds")
    if dynamic_timeout_seconds is None:
        dynamic_timeout_seconds = base.dynamic_timeout_seconds
    dynamic_confidence = _get_optional_float(raw, "dynamic_confidence")
    if dynamic_confidence is None:
        dynamic_confidence = base.dynamic_confidence
    dynamic_trials = _get_optional_int(raw, "dynamic_trials")
    if dynamic_trials is None:
        dynamic_trials = base.dynamic_trials
    dynamic_slowdown_ratio = _get_optional_float(raw, "dynamic_slowdown_ratio")
    if dynamic_slowdown_ratio is None:
        dynamic_slowdown_ratio = base.dynamic_slowdown_ratio
    dynamic_warmups = _get_optional_int(raw, "dynamic_warmups")
    if dynamic_warmups is None:
        dynamic_warmups = base.dynamic_warmups
    dynamic_memory_limit_mb = _get_optional_int(raw, "dynamic_memory_limit_mb")
    if dynamic_memory_limit_mb is None:
        dynamic_memory_limit_mb = base.dynamic_memory_limit_mb
    dynamic_jitter_threshold = _get_optional_float(raw, "dynamic_jitter_threshold")
    if dynamic_jitter_threshold is None:
        dynamic_jitter_threshold = base.dynamic_jitter_threshold
    dynamic_sizes = _get_int_list(raw, "dynamic_sizes")
    if dynamic_sizes is None:
        dynamic_sizes = base.dynamic_sizes
    max_findings = _get_optional_int(raw, "max_findings")
    if max_findings is None:
        max_findings = base.max_findings
    fail_on_finding_severity = _get_optional_str(raw, "fail_on_finding_severity")
    if fail_on_finding_severity is None:
        fail_on_finding_severity = base.fail_on_finding_severity
    max_risk_score = _get_optional_float(raw, "max_risk_score")
    if max_risk_score is None:
        max_risk_score = base.max_risk_score
    notify_min_severity = _get_optional_str(raw, "notify_min_severity")
    if notify_min_severity is None:
        notify_min_severity = base.notify_min_severity
    notify_max_items = _get_optional_int(raw, "notify_max_items")
    if notify_max_items is None:
        notify_max_items = base.notify_max_items
    rules_enabled = _get_bool(raw, "rules_enabled", base.rules_enabled)
    rule_plugins = base.rule_plugins
    raw_rule_plugins = _get_list(raw, "rule_plugins")
    if raw_rule_plugins is not None:
        rule_plugins = [*rule_plugins, *raw_rule_plugins]
    enabled_rules = base.enabled_rules
    raw_enabled_rules = _get_list(raw, "enabled_rules")
    if raw_enabled_rules is not None:
        enabled_rules = [*enabled_rules, *raw_enabled_rules]
    disabled_rules = base.disabled_rules
    raw_disabled_rules = _get_list(raw, "disabled_rules")
    if raw_disabled_rules is not None:
        disabled_rules = [*disabled_rules, *raw_disabled_rules]
    rule_severity_overrides = [*base.rule_severity_overrides, *_get_rule_severity_overrides(raw)]
    rule_config = base.rule_config
    raw_rule_config = raw.get("rule_config")
    if isinstance(raw_rule_config, dict):
        rule_config = {**rule_config, **raw_rule_config}
    call_graph_enabled = _get_bool(raw, "call_graph_enabled", base.call_graph_enabled)
    call_graph_passes = _get_optional_int(raw, "call_graph_passes")
    if call_graph_passes is None:
        call_graph_passes = base.call_graph_passes
    hot_paths = base.hot_paths
    raw_hot_paths = _get_list(raw, "hot_paths")
    if raw_hot_paths is not None:
        hot_paths = [*hot_paths, *raw_hot_paths]
    hot_functions = base.hot_functions
    raw_hot_functions = _get_list(raw, "hot_functions")
    if raw_hot_functions is not None:
        hot_functions = [*hot_functions, *raw_hot_functions]
    hot_path_multiplier = _get_optional_float(raw, "hot_path_multiplier")
    if hot_path_multiplier is None:
        hot_path_multiplier = base.hot_path_multiplier
    hot_profile_path = _get_optional_str(raw, "hot_profile_path")
    if hot_profile_path is None:
        hot_profile_path = base.hot_profile_path
    hot_profile_top = _get_optional_int(raw, "hot_profile_top")
    if hot_profile_top is None:
        hot_profile_top = base.hot_profile_top
    hot_trace_summary_path = _get_optional_str(raw, "hot_trace_summary_path")
    if hot_trace_summary_path is None:
        hot_trace_summary_path = base.hot_trace_summary_path
    parallel_workers = _get_optional_int(raw, "parallel_workers")
    if parallel_workers is None:
        parallel_workers = base.parallel_workers
    analysis_time_budget_seconds = _get_optional_float(raw, "analysis_time_budget_seconds")
    if analysis_time_budget_seconds is None:
        analysis_time_budget_seconds = base.analysis_time_budget_seconds
    cache_path = _get_optional_str(raw, "cache_path")
    if cache_path is None:
        cache_path = base.cache_path
    use_cache = _get_bool(raw, "use_cache", base.use_cache)
    gating_preset = _get_optional_str(raw, "gating_preset")
    if gating_preset is None:
        gating_preset = base.gating_preset
    fail_on_regressions = _get_bool(raw, "fail_on_regressions", base.fail_on_regressions)
    fail_on_severity = _get_optional_str(raw, "fail_on_severity")
    if fail_on_severity is None:
        fail_on_severity = base.fail_on_severity
    max_regressions = _get_optional_int(raw, "max_regressions")
    if max_regressions is None:
        max_regressions = base.max_regressions
    max_high_regressions = _get_optional_int(raw, "max_high_regressions")
    if max_high_regressions is None:
        max_high_regressions = base.max_high_regressions
    max_risk_delta = _get_optional_float(raw, "max_risk_delta")
    if max_risk_delta is None:
        max_risk_delta = base.max_risk_delta
    risk_delta_budget = _get_optional_float(raw, "risk_delta_budget")
    if risk_delta_budget is None:
        risk_delta_budget = base.risk_delta_budget
    risk_delta_budgets = [*base.risk_delta_budgets, *_get_risk_delta_budgets(raw)]
    severity_overrides = [*base.severity_overrides, *_get_severity_overrides(raw)]
    loop_depth_fail_paths = base.loop_depth_fail_paths
    raw_loop_depth_fail_paths = _get_list(raw, "loop_depth_fail_paths")
    if raw_loop_depth_fail_paths is not None:
        loop_depth_fail_paths = [*loop_depth_fail_paths, *raw_loop_depth_fail_paths]
    no_regressions_paths = base.no_regressions_paths
    raw_no_regressions_paths = _get_list(raw, "no_regressions_paths")
    if raw_no_regressions_paths is not None:
        no_regressions_paths = [*no_regressions_paths, *raw_no_regressions_paths]
    new_findings_only = _get_bool(raw, "new_findings_only", base.new_findings_only)

    return (
        OccamOConfig(
            include=include,
            exclude=exclude,
            report_include=report_include,
            report_exclude=report_exclude,
            languages=languages,
            max_files=max_files,
            changed_only=changed_only,
            changed_only_strict=changed_only_strict,
            diff_functions=diff_functions,
            compare_base=compare_base,
            min_confidence=min_confidence,
            min_risk_score=min_risk_score,
            min_severity=min_severity,
            min_regression_risk_delta=min_regression_risk_delta,
            min_regression_hint_delta=min_regression_hint_delta,
            min_regression_severity=min_regression_severity,
            min_function_lines=min_function_lines,
            warn_regression_risk_delta=warn_regression_risk_delta,
            fail_regression_risk_delta=fail_regression_risk_delta,
            dynamic_verify=dynamic_verify,
            dynamic_top=dynamic_top,
            dynamic_timeout_seconds=dynamic_timeout_seconds,
            dynamic_confidence=dynamic_confidence,
            dynamic_trials=dynamic_trials,
            dynamic_slowdown_ratio=dynamic_slowdown_ratio,
            dynamic_warmups=dynamic_warmups,
            dynamic_memory_limit_mb=dynamic_memory_limit_mb,
            dynamic_jitter_threshold=dynamic_jitter_threshold,
            dynamic_sizes=dynamic_sizes,
            max_findings=max_findings,
            fail_on_finding_severity=fail_on_finding_severity,
            max_risk_score=max_risk_score,
            notify_min_severity=notify_min_severity,
            notify_max_items=notify_max_items,
            rules_enabled=rules_enabled,
            rule_plugins=rule_plugins,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            rule_severity_overrides=rule_severity_overrides,
            rule_config=rule_config,
            call_graph_enabled=call_graph_enabled,
            call_graph_passes=call_graph_passes,
            hot_paths=hot_paths,
            hot_functions=hot_functions,
            hot_path_multiplier=hot_path_multiplier,
            hot_profile_path=hot_profile_path,
            hot_profile_top=hot_profile_top,
            hot_trace_summary_path=hot_trace_summary_path,
            parallel_workers=parallel_workers,
            analysis_time_budget_seconds=analysis_time_budget_seconds,
            cache_path=cache_path,
            use_cache=use_cache,
            gating_preset=gating_preset,
            fail_on_regressions=fail_on_regressions,
            fail_on_severity=fail_on_severity,
            max_regressions=max_regressions,
            max_high_regressions=max_high_regressions,
            max_risk_delta=max_risk_delta,
            risk_delta_budget=risk_delta_budget,
            risk_delta_budgets=risk_delta_budgets,
            severity_overrides=severity_overrides,
            loop_depth_fail_paths=loop_depth_fail_paths,
            no_regressions_paths=no_regressions_paths,
            new_findings_only=new_findings_only,
        ),
        include_set,
        exclude_set,
    )


def _resolve_config_paths(repo_root: Path, config_paths: Iterable[Path] | None) -> list[Path]:
    if config_paths is None:
        return [repo_root / ".occamo.yml"]
    resolved: list[Path] = []
    for path in config_paths:
        p = path
        if not p.is_absolute():
            p = repo_root / p
        resolved.append(p)
    return resolved


def load_config(repo_root: Path, config_paths: Iterable[Path] | None = None) -> OccamOConfig:
    paths = _resolve_config_paths(repo_root, config_paths)
    if config_paths is None and not paths[0].exists():
        return OccamOConfig()

    cfg = OccamOConfig()
    include_set = False
    exclude_set = False
    for path in paths:
        if not path.exists():
            log.warning("Config %s not found; skipping.", path)
            continue
        raw = _load_raw_config(path)
        if not isinstance(raw, dict):
            log.warning("Config %s is not a mapping; skipping.", path)
            continue
        cfg, include_set, exclude_set = _merge_config(cfg, raw, include_set, exclude_set)
    return cfg
