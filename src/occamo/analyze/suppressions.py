from __future__ import annotations

from pathlib import Path

from occamo.analyze.go import TS_AVAILABLE as GO_AVAILABLE
from occamo.analyze.go import collect_suppressions as collect_go_suppressions
from occamo.analyze.java import TS_AVAILABLE as JAVA_AVAILABLE
from occamo.analyze.java import collect_suppressions as collect_java_suppressions
from occamo.analyze.js_ts import TS_AVAILABLE as JS_AVAILABLE
from occamo.analyze.js_ts import collect_suppressions as collect_js_suppressions
from occamo.analyze.kotlin import TS_AVAILABLE as KOTLIN_AVAILABLE
from occamo.analyze.kotlin import collect_suppressions as collect_kotlin_suppressions
from occamo.analyze.static_ast import collect_suppressions as collect_python_suppressions
from occamo.report.models import Suppression
from occamo.util.languages import language_for_path


def collect_suppressions(sources: dict[str, str]) -> list[Suppression]:
    out: list[Suppression] = []
    for file_path, src in sources.items():
        path = Path(file_path)
        language = language_for_path(path)
        if language == "python":
            out.extend(collect_python_suppressions(path, src))
        elif language in {"javascript", "typescript"}:
            if JS_AVAILABLE:
                out.extend(collect_js_suppressions(path, src))
        elif language == "java":
            if JAVA_AVAILABLE:
                out.extend(collect_java_suppressions(path, src))
        elif language == "kotlin":
            if KOTLIN_AVAILABLE:
                out.extend(collect_kotlin_suppressions(path, src))
        elif language == "go":
            if GO_AVAILABLE:
                out.extend(collect_go_suppressions(path, src))
    return out


__all__ = ["collect_suppressions"]
