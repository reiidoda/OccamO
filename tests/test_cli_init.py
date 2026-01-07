from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_cli_init_writes_config(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "occamo", "init", str(tmp_path), "--preset", "minimal"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    cfg = tmp_path / ".occamo.yml"
    assert cfg.exists()
    assert "include:" in cfg.read_text(encoding="utf-8")
