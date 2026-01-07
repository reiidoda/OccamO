# Contributing

Thanks for your interest in OccamO.

This project is currently maintained by a single maintainer (@reiidoda). PRs
and issues are welcome, but responses may take time and not all requests will
be accepted. For large changes, please open an issue first to align on scope.

## Ways to help

- Report bugs with a minimal repro and expected behavior.
- Improve docs, examples, and CI configurations.
- Add rules or rule tests (see `docs/RULE_SDK.md`).
- Improve analysis quality or performance with small, focused PRs.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
ruff check .
mypy src/occamo
pytest
# Optional benchmarks
occamo-bench --json out/occamo.bench.json
```

## Guidelines

- Keep analysis deterministic and safe (do not execute repo code in static paths).
- Prefer small, focused changes with tests and documentation updates.
- Add fixtures for new rules or regressions to prevent false positives.
- Keep outputs stable; report changes must be justified and documented.

## Pull requests

- Include a clear description of the change and motivation.
- Add or update tests for behavior changes.
- Update docs if user-facing behavior changes.
- Expect feedback and iteration; the maintainer has final decision.

## Code of Conduct

All contributors must follow `CODE_OF_CONDUCT.md`.

## License

By contributing, you agree that your contributions are licensed under the
Apache-2.0 license (see `LICENSE`).
