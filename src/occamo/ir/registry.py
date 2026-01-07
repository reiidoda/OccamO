from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from occamo.analyze.static_ast import FunctionFinding
from occamo.ir.go import GoIRPlugin
from occamo.ir.java import JavaIRPlugin
from occamo.ir.js_ts import JsTsIRPlugin
from occamo.ir.kotlin import KotlinIRPlugin
from occamo.ir.models import IRModule
from occamo.ir.python import PythonIRPlugin


class IRPlugin(Protocol):
    language: str

    def supports(self, path: Path) -> bool:
        ...

    def build(self, path: Path, src: str, findings: list[FunctionFinding]) -> IRModule | None:
        ...


def _group_findings_by_file(findings: Iterable[FunctionFinding]) -> dict[str, list[FunctionFinding]]:
    grouped: dict[str, list[FunctionFinding]] = {}
    for finding in findings:
        grouped.setdefault(finding.file, []).append(finding)
    return grouped


def build_ir_modules(
    repo_root: Path,
    sources: dict[str, str],
    findings: Iterable[FunctionFinding],
    plugins: list[IRPlugin] | None = None,
) -> list[IRModule]:
    if plugins is None:
        plugins = [
            PythonIRPlugin(),
            JsTsIRPlugin(),
            JavaIRPlugin(),
            KotlinIRPlugin(),
            GoIRPlugin(),
        ]
    grouped = _group_findings_by_file(findings)
    modules: list[IRModule] = []
    for file_path, src in sources.items():
        path = Path(file_path)
        plugin = next((p for p in plugins if p.supports(path)), None)
        if plugin is None:
            continue
        mod = plugin.build(path, src, grouped.get(file_path, []))
        if mod:
            modules.append(mod)
    return modules
