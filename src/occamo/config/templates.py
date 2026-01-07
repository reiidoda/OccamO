"""Templates for generated OccamO configuration files."""

DEFAULT_CONFIG = """# OccamO configuration example (repo-relative paths)
include:
  - "src"
exclude:
  - "tests"
  - "test"
  - "spec"
  - "specs"
  - "bench"
  - "benchmarks"
  - ".venv"
  - "venv"
  - ".tox"
  - ".eggs"
  - "build"
  - "dist"
  - "coverage"
  - "htmlcov"
  - ".mypy_cache"
  - ".pytest_cache"
  - ".ruff_cache"
  - ".cache"
  - "node_modules"
  - "vendor"
  - ".git"
report_include:
  - "src"
report_exclude:
  - "src/legacy/**"
languages:
  - "python"

max_files: 200
changed_only: false
changed_only_strict: false
diff_functions: true
compare_base: false
new_findings_only: false

# Gating thresholds (null/empty to disable)
min_risk_score:
min_confidence:
min_severity:
min_regression_risk_delta:
min_regression_hint_delta:
min_regression_severity:
min_function_lines:
warn_regression_risk_delta:
fail_regression_risk_delta:

# Dynamic verification (executes code for top hotspots)
dynamic_verify: false
dynamic_top: 5
dynamic_timeout_seconds: 1.5
dynamic_confidence: 0.6
dynamic_trials: 3
dynamic_slowdown_ratio: 1.2
dynamic_warmups: 1
dynamic_memory_limit_mb:
dynamic_jitter_threshold: 0.35
dynamic_sizes:
  - 16
  - 32
  - 64
  - 128
max_findings:
fail_on_finding_severity:
max_risk_score:
notify_min_severity: high
notify_max_items: 5
rules_enabled: true
rule_plugins: []
enabled_rules: []
disabled_rules: []
rule_severity_overrides:
  - rule_id: "occamo.db-in-loop"
    severity: "high"
rule_config: {}
call_graph_enabled: true
call_graph_passes: 2
hot_paths: []
hot_functions: []
hot_path_multiplier: 1.5
hot_profile_path:
hot_profile_top: 20
hot_trace_summary_path:
parallel_workers: 0
analysis_time_budget_seconds:
fail_on_regressions: false
fail_on_severity:
max_regressions:
max_high_regressions:
max_risk_delta:
risk_delta_budget:
risk_delta_budgets:
  - pattern: "src/core/**"
    budget: 0.5
gating_preset:

# Per-path severity overrides (info, low, medium, high, critical)
severity_overrides:
  - pattern: "src/legacy/**"
    severity: "low"

# Fail if loop depth increases in these paths
loop_depth_fail_paths:
  - "src/core/**"

# Fail if any regression occurs in these paths
no_regressions_paths:
  - "src/critical/**"

# Incremental cache
use_cache: true
cache_path:
"""

MINIMAL_CONFIG = """# OccamO minimal configuration
include:
  - "src"
exclude:
  - "tests"
"""

CI_CONFIG = """# OccamO CI configuration
include:
  - "src"
exclude:
  - "tests"
languages:
  - "python"
changed_only: true
compare_base: true
diff_functions: true
new_findings_only: true
gating_preset: "balanced"
"""

CONFIG_PRESETS = {
    "full": DEFAULT_CONFIG,
    "minimal": MINIMAL_CONFIG,
    "ci": CI_CONFIG,
}
