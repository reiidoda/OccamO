# OccamO: Complexity and Performance Regression Guard

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Python](https://img.shields.io/pypi/pyversions/occamo)
![PyPI](https://img.shields.io/pypi/v/occamo)
![Downloads](https://img.shields.io/pypi/dm/occamo)
![CI](https://github.com/reiidoda/OccamO/actions/workflows/ci.yml/badge.svg)
![Bench](https://github.com/reiidoda/OccamO/actions/workflows/bench.yml/badge.svg)
![Release](https://github.com/reiidoda/OccamO/actions/workflows/release-please.yml/badge.svg)
![Docker](https://github.com/reiidoda/OccamO/actions/workflows/docker.yml/badge.svg)
![Coverage](https://codecov.io/gh/reiidoda/OccamO/branch/main/graph/badge.svg)

![OccamO logo](assets/logo.png)

OccamO is a CI-first analyzer that spots algorithmic complexity hotspots and
regressions. It compares a base branch (main) with a PR head, matches functions
by stable IDs, and reports only what got worse. Optional rule engines, call-graph
weighting, hot-path signals, and dynamic verification make the output actionable.

Highlights:
- True baseline regression diff with before -> after risk scores and hints.
- Stable function IDs (path + qualname + normalized body hash) for reliable diffs.
- Changed-only and diff-function modes to keep noise low in PRs.
- Policy-as-code gating (warn/fail thresholds, budgets, no-regression paths).
- GitHub-native UX: PR comments, job summary, annotations, check runs, SARIF.
- Multiple outputs: JSON, Markdown, HTML, SARIF, trend, Slack/Teams, snippets.
- Optional JS/TS/Java/Kotlin/Go analysis via tree-sitter.

## Contents

- Install
- Quick start
- GitHub Actions
- Baselines
- Configuration
- Outputs
- Language support
- Dynamic verification
- Integrations
- VS Code extension
- Developer experience
- Benchmarks
- Docs and policies
- Contributing

## Install

```bash
pip install occamo
```

Extras:

```bash
pip install "occamo[gitignore]"  # gitignore-style .occamoignore matching
pip install "occamo[bench]"      # benchmark harness
pip install "occamo[js]"         # JS/TS/Java/Kotlin/Go analysis via tree-sitter
pip install "occamo[dev]"        # lint/test/dev tools
```

## Quick Start

```bash
occamo init --preset minimal
occamo analyze . --changed-only
```

Typical PR command:

```bash
occamo analyze . \
  --changed-only \
  --compare-base \
  --md out/occamo.md \
  --json out/occamo.json
```

## GitHub Actions

Direct CLI usage:

```yaml
name: OccamO
on:
  pull_request:
  push:
    branches: [ main ]

jobs:
  occamo:
    permissions:
      contents: read
      pull-requests: write   # only if posting PR comments
      checks: write          # only if posting check runs
      security-events: write # only if uploading SARIF
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install OccamO
        run: pip install ./
      - name: Analyze
        run: |
          occamo analyze . --changed-only --compare-base \
            --md out/occamo.md \
            --json out/occamo.json \
            --sarif out/occamo.sarif
      - name: Job summary
        run: cat out/occamo.md >> $GITHUB_STEP_SUMMARY
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: out/occamo.sarif
```

Composite action:

```yaml
- uses: reiidoda/OccamO/action@v1
  with:
    install: "true"
    install_target: "occamo"
    compare_base: "true"
    baseline_auto: "true"
    comment_out: "out/occamo.comment.md"
    post_comment: "true"
    check_run_out: "out/occamo.check_run.json"
    post_check_run: "true"
```

Pin `@v1.x.y` for reproducible builds if you need immutable action versions.

## Baselines

Generate a baseline on the default branch and auto-download it in PRs:

```yaml
name: OccamO Baseline
on:
  push:
    branches: [ main ]

jobs:
  baseline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install ./
      - run: occamo baseline . --json out/occamo.json
      - uses: actions/upload-artifact@v4
        with:
          name: occamo-baseline
          path: out/occamo.json
```

In non-GitHub CI, store the baseline JSON as an artifact and pass it via
`--baseline-json`.

## Configuration

Create `.occamo.yml` (see `.occamo.example.yml` for full template):

```yaml
include:
  - "src"
exclude:
  - "tests"
changed_only: true
compare_base: true
diff_functions: true
new_findings_only: true
languages:
  - "python"
gating_preset: "balanced"
```

Notes:
- Use `.occamoignore` for gitignore-style exclusions (install with `occamo[gitignore]`).
- Suppress a function with `# occamo: ignore reason="..." ticket="ABC-123"`.
- Validate configs with `occamo config validate` and inspect with `occamo config show`.
- JS/TS/Java/Kotlin/Go analysis requires `occamo[js]` and `languages` set.
- Use `min_function_lines` to skip tiny helpers and `new_findings_only` for PRs.
- Use budgets and no-regression paths to enforce critical areas.

## Outputs

OccamO can emit:
- JSON report
- Markdown summary
- HTML report
- SARIF
- GitHub annotations
- PR comment markdown
- Check-run payload
- Trend JSON + HTML
- Slack/Teams notification payloads
- Quick-fix snippets (copy-paste templates)

Report schema: `schema/occamo.schema.json`.

## Language Support

- Python (built in)
- JavaScript/TypeScript, Java, Kotlin, Go (optional via `occamo[js]`)

## Dynamic Verification

Dynamic verification executes code in a subprocess to confirm or downgrade
static findings. It is optional and recommended only in trusted CI contexts.
See `docs/REPRODUCIBILITY.md` for reproducibility guidance.

## Integrations

OccamO is CLI-first and works in GitLab CI, Jenkins, and Azure DevOps.
See `docs/INTEGRATIONS.md` for copy/paste examples.

## VS Code Extension

The beta extension lives in `vscode/` and loads OccamO JSON reports as
editor diagnostics. See `vscode/README.md` for setup.

## Developer Experience

Pre-commit hook:

```yaml
repos:
  - repo: https://github.com/reiidoda/OccamO
    rev: v0.1.0
    hooks:
      - id: occamo
        args: [--changed-only, --diff-functions, --new-findings-only, --max-findings, "25"]
```

Quick-fix snippets:

```bash
occamo analyze . --snippets out/occamo.snippets.md
```

## Benchmarks

```bash
occamo-bench --json out/occamo.bench.json
occamo-bench --json out/occamo.bench.pr.json \
  --baseline out/occamo.bench.json --max-regression 0.15
```

## Docs and Policies

- Architecture: `docs/ARCHITECTURE.md`
- Rules and Rule SDK: `docs/RULES.md`, `docs/RULE_SDK.md`
- IR model: `docs/IR.md`
- Policy cookbook: `docs/POLICY_COOKBOOK.md`
- Supply chain: `docs/SUPPLY_CHAIN.md`
- Releasing: `docs/RELEASING.md`
- Governance: `GOVERNANCE.md`
- Support: `SUPPORT.md`
- Privacy: `PRIVACY.md`
- Security: `SECURITY.md`

## Contributing

See `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.

## License

Apache-2.0
