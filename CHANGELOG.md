# Changelog

## Unreleased
- Add config schema + validation/show commands and report stats summaries.
- Add findings-based gating and composite action outputs/upserts.
- Add JS/TS analysis via optional tree-sitter support.
- Add stable function IDs, regression severity + explanations, and loop-depth gating controls.
- Add optional dynamic verification for hotspots and baseline regressions (trials + slowdown ratio).
- Add baseline diffs (added/removed/changed) plus new findings only mode.
- Add policy controls for per-path risk budgets and no-regression paths.

## 0.1.0
- Initial MVP scaffolding: CLI + static AST heuristics + reports + Git targeting.
