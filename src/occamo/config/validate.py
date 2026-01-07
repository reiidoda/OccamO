from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

from occamo.util.languages import SUPPORTED_LANGUAGES, normalize_languages

SEVERITIES = {"info", "low", "medium", "high", "critical"}
GATING_PRESETS = {"strict", "balanced", "relaxed"}

KNOWN_KEYS = {
    "include",
    "exclude",
    "report_include",
    "report_exclude",
    "languages",
    "max_files",
    "changed_only",
    "changed_only_strict",
    "diff_functions",
    "compare_base",
    "min_confidence",
    "min_risk_score",
    "min_severity",
    "min_regression_risk_delta",
    "min_regression_hint_delta",
    "min_regression_severity",
    "min_function_lines",
    "warn_regression_risk_delta",
    "fail_regression_risk_delta",
    "dynamic_verify",
    "dynamic_top",
    "dynamic_timeout_seconds",
    "dynamic_confidence",
    "dynamic_trials",
    "dynamic_slowdown_ratio",
    "dynamic_warmups",
    "dynamic_memory_limit_mb",
    "dynamic_jitter_threshold",
    "dynamic_sizes",
    "max_findings",
    "fail_on_finding_severity",
    "max_risk_score",
    "notify_min_severity",
    "notify_max_items",
    "rules_enabled",
    "rule_plugins",
    "enabled_rules",
    "disabled_rules",
    "rule_severity_overrides",
    "rule_config",
    "call_graph_enabled",
    "call_graph_passes",
    "hot_paths",
    "hot_functions",
    "hot_path_multiplier",
    "hot_profile_path",
    "hot_profile_top",
    "hot_trace_summary_path",
    "parallel_workers",
    "analysis_time_budget_seconds",
    "cache_path",
    "use_cache",
    "gating_preset",
    "fail_on_regressions",
    "fail_on_severity",
    "max_regressions",
    "max_high_regressions",
    "max_risk_delta",
    "risk_delta_budget",
    "risk_delta_budgets",
    "severity_overrides",
    "loop_depth_fail_paths",
    "no_regressions_paths",
    "new_findings_only",
}


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_list_strings(raw: dict[str, Any], key: str, errors: list[str]) -> None:
    if key not in raw:
        return
    value = raw.get(key)
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        errors.append(f"{key} must be a list of strings")


def _validate_optional_number(raw: dict[str, Any], key: str, errors: list[str]) -> None:
    if key not in raw:
        return
    value = raw.get(key)
    if value is None:
        return
    if not _is_number(value):
        errors.append(f"{key} must be a number")


def _validate_optional_int(raw: dict[str, Any], key: str, errors: list[str]) -> None:
    if key not in raw:
        return
    value = raw.get(key)
    if value is None:
        return
    if not _is_int(value):
        errors.append(f"{key} must be an integer")


def _validate_optional_str_choice(raw: dict[str, Any], key: str, choices: set[str], errors: list[str]) -> None:
    if key not in raw:
        return
    value = raw.get(key)
    if value is None:
        return
    if not isinstance(value, str):
        errors.append(f"{key} must be a string")
        return
    if value.lower() not in choices:
        errors.append(f"{key} must be one of: {', '.join(sorted(choices))}")


def _validate_optional_bool(raw: dict[str, Any], key: str, errors: list[str]) -> None:
    if key not in raw:
        return
    value = raw.get(key)
    if value is None:
        return
    if not _is_bool(value):
        errors.append(f"{key} must be a boolean")


def _validate_languages(raw: dict[str, Any], errors: list[str]) -> None:
    if "languages" not in raw:
        return
    value = raw.get("languages")
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        errors.append("languages must be a list of strings")
        return
    normalized = normalize_languages(value)
    unknown = [lang for lang in normalized if lang not in SUPPORTED_LANGUAGES]
    if unknown:
        errors.append(f"languages contains unsupported values: {', '.join(unknown)}")


def _validate_severity_overrides(raw: dict[str, Any], errors: list[str]) -> None:
    if "severity_overrides" not in raw:
        return
    value = raw.get("severity_overrides")
    if not isinstance(value, list):
        errors.append("severity_overrides must be a list")
        return
    for idx, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            errors.append(f"severity_overrides[{idx}] must be a mapping")
            continue
        pattern = item.get("pattern")
        severity = item.get("severity")
        if not isinstance(pattern, str) or not pattern.strip():
            errors.append(f"severity_overrides[{idx}].pattern must be a non-empty string")
        if not isinstance(severity, str) or severity.lower() not in SEVERITIES:
            errors.append(
                f"severity_overrides[{idx}].severity must be one of: {', '.join(sorted(SEVERITIES))}"
            )


def _validate_rule_severity_overrides(raw: dict[str, Any], errors: list[str]) -> None:
    if "rule_severity_overrides" not in raw:
        return
    value = raw.get("rule_severity_overrides")
    if not isinstance(value, list):
        errors.append("rule_severity_overrides must be a list")
        return
    for idx, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            errors.append(f"rule_severity_overrides[{idx}] must be a mapping")
            continue
        rule_id = item.get("rule_id")
        severity = item.get("severity")
        if not isinstance(rule_id, str) or not rule_id.strip():
            errors.append(f"rule_severity_overrides[{idx}].rule_id must be a non-empty string")
        if not isinstance(severity, str) or severity.lower() not in SEVERITIES:
            errors.append(
                f"rule_severity_overrides[{idx}].severity must be one of: {', '.join(sorted(SEVERITIES))}"
            )


def _validate_risk_delta_budgets(raw: dict[str, Any], errors: list[str]) -> None:
    if "risk_delta_budgets" not in raw:
        return
    value = raw.get("risk_delta_budgets")
    if not isinstance(value, list):
        errors.append("risk_delta_budgets must be a list")
        return
    for idx, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            errors.append(f"risk_delta_budgets[{idx}] must be a mapping")
            continue
        pattern = item.get("pattern")
        budget = item.get("budget")
        if not isinstance(pattern, str) or not pattern.strip():
            errors.append(f"risk_delta_budgets[{idx}].pattern must be a non-empty string")
        if not _is_number(budget):
            errors.append(f"risk_delta_budgets[{idx}].budget must be a number")


def validate_raw_config(raw: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in raw.keys():
        if key not in KNOWN_KEYS:
            errors.append(f"Unknown key: {key}")

    _validate_list_strings(raw, "include", errors)
    _validate_list_strings(raw, "exclude", errors)
    _validate_list_strings(raw, "report_include", errors)
    _validate_list_strings(raw, "report_exclude", errors)
    _validate_list_strings(raw, "loop_depth_fail_paths", errors)
    _validate_list_strings(raw, "no_regressions_paths", errors)
    _validate_list_strings(raw, "rule_plugins", errors)
    _validate_list_strings(raw, "enabled_rules", errors)
    _validate_list_strings(raw, "disabled_rules", errors)
    _validate_list_strings(raw, "hot_paths", errors)
    _validate_list_strings(raw, "hot_functions", errors)
    if "dynamic_sizes" in raw:
        value = raw.get("dynamic_sizes")
        if not isinstance(value, list) or not all(isinstance(v, int) and not isinstance(v, bool) for v in value):
            errors.append("dynamic_sizes must be a list of integers")
    _validate_languages(raw, errors)

    if "max_files" in raw and raw.get("max_files") is not None and not _is_int(raw.get("max_files")):
        errors.append("max_files must be an integer")

    for key in [
        "changed_only",
        "changed_only_strict",
        "diff_functions",
        "compare_base",
        "use_cache",
        "fail_on_regressions",
        "new_findings_only",
        "rules_enabled",
        "call_graph_enabled",
    ]:
        _validate_optional_bool(raw, key, errors)
    _validate_optional_bool(raw, "dynamic_verify", errors)

    for key in [
        "min_confidence",
        "min_risk_score",
        "min_regression_risk_delta",
        "warn_regression_risk_delta",
        "fail_regression_risk_delta",
        "dynamic_timeout_seconds",
        "dynamic_confidence",
        "dynamic_slowdown_ratio",
        "dynamic_jitter_threshold",
        "max_risk_score",
        "max_risk_delta",
        "risk_delta_budget",
        "hot_path_multiplier",
        "analysis_time_budget_seconds",
    ]:
        _validate_optional_number(raw, key, errors)

    for key in [
        "min_regression_hint_delta",
        "max_regressions",
        "max_high_regressions",
        "max_findings",
        "notify_max_items",
        "min_function_lines",
        "dynamic_top",
        "dynamic_trials",
        "call_graph_passes",
        "hot_profile_top",
        "parallel_workers",
        "dynamic_warmups",
        "dynamic_memory_limit_mb",
    ]:
        _validate_optional_int(raw, key, errors)

    _validate_optional_str_choice(raw, "min_severity", SEVERITIES, errors)
    _validate_optional_str_choice(raw, "min_regression_severity", SEVERITIES, errors)
    _validate_optional_str_choice(raw, "fail_on_severity", SEVERITIES, errors)
    _validate_optional_str_choice(raw, "fail_on_finding_severity", SEVERITIES, errors)
    _validate_optional_str_choice(raw, "notify_min_severity", SEVERITIES, errors)
    _validate_optional_str_choice(raw, "gating_preset", GATING_PRESETS, errors)

    _validate_severity_overrides(raw, errors)
    _validate_rule_severity_overrides(raw, errors)
    if "rule_config" in raw and raw.get("rule_config") is not None:
        if not isinstance(raw.get("rule_config"), dict):
            errors.append("rule_config must be a mapping")
    if "hot_profile_path" in raw and raw.get("hot_profile_path") is not None:
        if not isinstance(raw.get("hot_profile_path"), str):
            errors.append("hot_profile_path must be a string")
    if "hot_trace_summary_path" in raw and raw.get("hot_trace_summary_path") is not None:
        if not isinstance(raw.get("hot_trace_summary_path"), str):
            errors.append("hot_trace_summary_path must be a string")
    _validate_risk_delta_budgets(raw, errors)

    return errors


def validate_config_path(path: Path) -> list[str]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return [f"{path}: failed to read ({exc})"]
    if not isinstance(raw, dict):
        return [f"{path}: config must be a mapping"]
    errors = validate_raw_config(raw)
    return [f"{path}: {err}" for err in errors]


def validate_config_paths(paths: Iterable[Path]) -> list[str]:
    errors: list[str] = []
    for path in paths:
        if not path.exists():
            errors.append(f"{path}: file not found")
            continue
        errors.extend(validate_config_path(path))
    return errors
