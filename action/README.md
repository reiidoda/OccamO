# OccamO Composite Action

Runs OccamO analysis and writes Markdown + JSON reports.
Pin `@v1.x.y` for immutable builds. See `docs/RELEASING.md` for tagging and marketplace notes.

## Usage

```yaml
- uses: reiidoda/OccamO/action@v1
  with:
    install: "true"
    install_target: "occamo"
    changed_only: "true"
    compare_base: "true"
    baseline_auto: "true"
    comment_out: "out/occamo.comment.md"
    post_comment: "true"
    check_run_out: "out/occamo.check_run.json"
    post_check_run: "true"
```

Notes:
- If you set `annotations_out`, add a step to `cat` that file so GitHub processes the workflow commands.
- If you set `post_comment`, grant `pull-requests: write` and use a PR event.
- If you set `post_check_run`, grant `checks: write`.
- If you set `baseline_auto`, grant `actions: read` and ensure the baseline workflow uploads the artifact.
- The action appends the Markdown report to `GITHUB_STEP_SUMMARY` when `write_summary` is true.
- Dynamic verification executes code; use it only in trusted CI contexts.
- HTML, trend, and Slack/Teams outputs are written only when their paths are provided.
- If you set `upload_sarif`, grant `security-events: write`.

## Inputs

| Name | Default | Description |
|---|---|---|
| `path` | `.` | Repository root |
| `config` | `""` | Config file path |
| `report_include` | `""` | Report include path (single pattern) |
| `report_exclude` | `""` | Report exclude path (single pattern) |
| `languages` | `""` | Comma-separated languages (python, javascript, typescript, java, kotlin, go) |
| `changed_only` | `true` | Analyze only changed files |
| `changed_only_strict` | `false` | Do not fall back to full scan if git diff is empty/unavailable |
| `diff_functions` | `""` | Filter findings to functions touched by the diff |
| `no_diff_functions` | `false` | Disable diff-based function filtering |
| `compare_base` | `false` | Compare findings vs base ref and flag regressions |
| `base_ref` | `origin/main` | Base ref for diff/compare |
| `baseline_json` | `""` | Baseline JSON report for comparisons |
| `baseline_auto` | `false` | Auto-download baseline artifact from default branch |
| `baseline_workflow` | `occamo-baseline.yml` | Baseline workflow file name or ID |
| `baseline_artifact` | `occamo-baseline` | Baseline artifact name |
| `baseline_download_dir` | `out/occamo-baseline` | Directory to download baseline artifact |
| `baseline_json_path` | `out/occamo.json` | Path to baseline JSON inside the artifact |
| `md_out` | `out/occamo.md` | Markdown output path |
| `json_out` | `out/occamo.json` | JSON output path |
| `html_out` | `""` | HTML output path |
| `sarif_out` | `out/occamo.sarif` | SARIF output path |
| `annotations_out` | `""` | GitHub annotations output path |
| `comment_out` | `""` | PR comment markdown output path |
| `check_run_out` | `""` | GitHub check-run payload JSON output path |
| `trend_out` | `""` | Trend JSON output path |
| `trend_html_out` | `""` | Trend HTML output path |
| `slack_out` | `""` | Slack webhook payload output path |
| `teams_out` | `""` | Teams webhook payload output path |
| `snippets_out` | `""` | Quick-fix snippets Markdown output path |
| `post_comment` | `false` | Post or update the PR comment using GitHub API |
| `post_check_run` | `false` | Post or update a GitHub check-run summary |
| `min_confidence` | `""` | Filter findings below this confidence |
| `min_risk_score` | `""` | Filter findings below this risk score |
| `min_severity` | `""` | Filter findings below this severity |
| `min_regression_risk_delta` | `""` | Filter regressions below this risk delta |
| `min_regression_hint_delta` | `""` | Filter regressions below this hint delta |
| `min_regression_severity` | `""` | Filter regressions below this severity |
| `min_function_lines` | `""` | Ignore functions smaller than this line count |
| `warn_regression_risk_delta` | `""` | Warn when regression risk delta meets/exceeds this value |
| `fail_regression_risk_delta` | `""` | Fail when regression risk delta meets/exceeds this value |
| `dynamic_verify` | `false` | Run dynamic verification for top hotspots (executes code) |
| `dynamic_top` | `""` | Number of hotspots to dynamically verify |
| `dynamic_timeout` | `""` | Timeout (seconds) for each dynamic check |
| `dynamic_confidence` | `""` | Minimum confidence to confirm/downgrade dynamic checks |
| `dynamic_trials` | `""` | Trials per input size for dynamic checks |
| `dynamic_slowdown_ratio` | `""` | Slowdown ratio to confirm regressions in dynamic mode |
| `dynamic_warmups` | `""` | Warmup runs per size |
| `dynamic_memory_limit` | `""` | Memory limit (MB) for dynamic checks |
| `dynamic_jitter_threshold` | `""` | Variance threshold for dynamic checks |
| `dynamic_sizes` | `""` | Comma-separated input sizes for dynamic checks |
| `max_findings` | `""` | Fail if finding count exceeds this value |
| `fail_on_finding_severity` | `""` | Fail if any finding meets/exceeds this severity |
| `max_risk_score` | `""` | Fail if any finding risk score exceeds this value |
| `notify_min_severity` | `""` | Minimum severity for Slack/Teams notifications |
| `notify_max_items` | `""` | Max items for Slack/Teams notifications |
| `rules` | `""` | Enable rule engine |
| `no_rules` | `false` | Disable rule engine |
| `enabled_rules` | `""` | Comma-separated rule IDs to enable |
| `disabled_rules` | `""` | Comma-separated rule IDs to disable |
| `rule_plugins` | `""` | Comma-separated rule plugin modules |
| `rule_severity_overrides` | `""` | Comma-separated rule_id=severity overrides |
| `no_call_graph` | `false` | Disable call graph aggregation |
| `call_graph_passes` | `""` | Iterations for call graph aggregation |
| `hot_paths` | `""` | Comma-separated hot path patterns |
| `hot_functions` | `""` | Comma-separated hot function selectors |
| `hot_multiplier` | `""` | Hot path multiplier |
| `hot_profile` | `""` | Path to pstats or speedscope profile |
| `hot_profile_top` | `""` | Top N profile entries for hot paths |
| `hot_trace_summary` | `""` | Path to trace summary JSON |
| `parallel_workers` | `""` | Number of analysis worker threads |
| `analysis_time_budget` | `""` | Stop analysis after this many seconds |
| `cache_path` | `""` | Cache path for incremental analysis |
| `no_cache` | `false` | Disable incremental cache |
| `refresh_cache` | `false` | Rebuild cache entries for analyzed files |
| `upload_sarif` | `false` | Upload SARIF to GitHub code scanning |
| `fail_on_regressions` | `false` | Fail the step if regressions are detected |
| `fail_on_severity` | `""` | Fail if any regression meets/exceeds this severity |
| `max_regressions` | `""` | Fail if regression count exceeds this value |
| `max_high_regressions` | `""` | Fail if high/critical regressions exceed this value |
| `gating_preset` | `""` | Apply a predefined gating preset |
| `max_risk_delta` | `""` | Fail if any regression risk delta exceeds this value |
| `risk_delta_budget` | `""` | Fail if total regression risk delta exceeds this value |
| `risk_delta_budget_paths` | `""` | Comma-separated path budgets (pattern=budget) |
| `loop_depth_fail_paths` | `""` | Comma-separated paths where loop depth increases should fail |
| `no_regressions_paths` | `""` | Comma-separated paths where any regression should fail |
| `new_findings_only` | `false` | Report only new/worse findings when comparing to base |
| `install` | `false` | Install OccamO before running |
| `python_version` | `3.12` | Python version to use when installing |
| `install_target` | `occamo` | Install target (e.g. occamo or ./) |
| `install_extras` | `""` | Extras to install (comma-separated) |
| `install_command` | `""` | Custom install command (overrides install_target/extras) |
| `fail_on_error` | `true` | Fail the step if analysis exits nonzero |
| `write_summary` | `true` | Append the Markdown report to the GitHub Step Summary |

## Outputs

| Name | Description |
|---|---|
| `findings` | Finding count |
| `regressions` | Regression count |
| `max_risk_score` | Highest risk score |
| `avg_risk_score` | Average risk score |
| `max_regression_delta` | Largest regression delta |
| `gating_failed` | Whether analysis exited nonzero |
| `exit_code` | OccamO exit code |

This action writes report files to the paths you provide. It does not emit other outputs.
