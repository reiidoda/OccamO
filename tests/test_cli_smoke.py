from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_cli_runs(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    f = tmp_path / "src" / "a.py"
    f.write_text("def f(xs):\n    return sum(xs)\n", encoding="utf-8")
    (tmp_path / ".occamo.yml").write_text("include: ['src']\n", encoding="utf-8")

    p = subprocess.run(
        [sys.executable, "-m", "occamo", "analyze", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert p.returncode == 0
    assert "OccamO report" in p.stdout
