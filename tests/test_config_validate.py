from __future__ import annotations

from occamo.config.validate import validate_raw_config


def test_validate_unknown_key() -> None:
    errors = validate_raw_config({"unknown": True})
    assert any("Unknown key" in err for err in errors)


def test_validate_languages() -> None:
    errors = validate_raw_config({"languages": ["python", "brainfuck"]})
    assert any("unsupported" in err for err in errors)
