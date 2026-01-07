from __future__ import annotations

from pathlib import Path

from occamo.rules.builtin import BUILTIN_RULES
from occamo.rules.testing import RuleFixture, run_rule_on_fixture


def test_rule_false_positive_corpus() -> None:
    corpus_dir = Path(__file__).parent / "fixtures" / "corpus"
    files = sorted(corpus_dir.glob("*.py"))
    assert files, "Expected corpus fixtures under tests/fixtures/corpus"

    for path in files:
        src = path.read_text(encoding="utf-8")
        fixture = RuleFixture(src=src, path=path.as_posix())
        for rule in BUILTIN_RULES:
            findings = run_rule_on_fixture(rule, fixture)
            assert not findings, f"Unexpected {rule.id} finding in {path.name}"
