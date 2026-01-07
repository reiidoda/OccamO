from __future__ import annotations

from pathlib import Path

from occamo.config.loader import load_config


def test_load_multiple_configs_merges_lists(tmp_path: Path) -> None:
    cfg1 = tmp_path / "a.yml"
    cfg2 = tmp_path / "b.yml"
    cfg1.write_text("include: ['pkg/a']\nexclude: ['tests']\n", encoding="utf-8")
    cfg2.write_text("include: ['pkg/b']\nseverity_overrides:\n  - pattern: 'pkg/b/**'\n    severity: high\n", encoding="utf-8")

    cfg = load_config(tmp_path, [cfg1, cfg2])

    assert cfg.include == ["pkg/a", "pkg/b"]
    assert cfg.exclude == ["tests"]
    assert len(cfg.severity_overrides) == 1
