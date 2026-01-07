# Governance

OccamO is a single-maintainer project. This document defines how the project
makes decisions, versions releases, and evolves rules/configs.

## Maintainer Model

- The project is maintained by @reiidoda.
- The maintainer has final decision on scope, acceptance, and roadmap.
- Contributions are welcome but processed on a best-effort basis.

## Semantic Versioning

We follow SemVer (MAJOR.MINOR.PATCH).
- MAJOR: breaking changes to CLI, config, report schema, or rule behavior.
- MINOR: new features, new rules, non-breaking defaults, and new outputs.
- PATCH: bug fixes and performance improvements only.

## Deprecation Policy

We deprecate features with advance notice and clear migration paths.
- Deprecations are announced in release notes and docs.
- Deprecations emit warnings (when possible) in CLI output.
- Removal happens in the next MAJOR release.

Config keys and outputs are not removed in MINOR/PATCH releases.

## Rule Lifecycle

Rules carry a stability label in code:
- experimental: may change behavior or wording.
- stable: behavior locked; only bug fixes and precision improvements.
- deprecated: scheduled for removal in the next MAJOR release.

We promote rules from experimental to stable after:
- At least two minor releases in the wild.
- Tests covering common false-positive/negative cases.

## Triage and Ownership

- Code ownership is defined in `.github/CODEOWNERS`.
- Issues are triaged as time allows and labeled (bug, enhancement, docs, rule).
- PRs that change logic or outputs require maintainer review.

## Support Policy

See `SUPPORT.md` for supported versions and support expectations.
