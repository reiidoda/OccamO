from __future__ import annotations

import json
from pathlib import Path

from occamo.report.format_check_run import to_check_run_output
from occamo.report.format_comment import to_comment_markdown
from occamo.report.format_html import to_html
from occamo.report.format_json import read_json
from occamo.report.format_md import to_markdown
from occamo.report.format_sarif import to_sarif
from occamo.report.format_snippets import to_snippets_markdown

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SNAPSHOTS_DIR = FIXTURES_DIR / "snapshots"
REPORT_FIXTURE = FIXTURES_DIR / "report_fixture.json"


def _load_report():
    return read_json(REPORT_FIXTURE)


def _read_snapshot(name: str) -> str:
    return (SNAPSHOTS_DIR / name).read_text(encoding="utf-8")


def _dump_json(data: dict) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def _normalize_sarif(data: dict) -> dict:
    runs = data.get("runs") or []
    if runs and isinstance(runs[0], dict):
        tool = runs[0].get("tool") or {}
        driver = tool.get("driver") or {}
        if isinstance(driver, dict):
            driver = {**driver, "version": "0.0.0"}
            tool["driver"] = driver
            runs[0]["tool"] = tool
    data["runs"] = runs
    return data


def test_markdown_snapshot() -> None:
    report = _load_report()
    actual = to_markdown(report, top_n=5)
    assert actual == _read_snapshot("report.md")


def test_comment_snapshot() -> None:
    report = _load_report()
    actual = to_comment_markdown(report, top_n=5)
    assert actual == _read_snapshot("report.comment.md")


def test_html_snapshot() -> None:
    report = _load_report()
    actual = to_html(report, top_n=5)
    assert actual == _read_snapshot("report.html")


def test_sarif_snapshot() -> None:
    report = _load_report()
    sarif = _normalize_sarif(to_sarif(report))
    actual = _dump_json(sarif)
    assert actual == _read_snapshot("report.sarif.json")


def test_check_run_snapshot() -> None:
    report = _load_report()
    payload = to_check_run_output(
        report,
        top_n=5,
        repo_url="https://github.com/acme/occamo",
        sha="deadbeef",
    )
    actual = _dump_json(payload)
    assert actual == _read_snapshot("report.check_run.json")


def test_snippets_snapshot() -> None:
    report = _load_report()
    actual = to_snippets_markdown(report, top_n=5)
    assert actual == _read_snapshot("report.snippets.md")
