from __future__ import annotations

import logging
from pathlib import Path

from occamo.analyze.go import TS_AVAILABLE as GO_AVAILABLE
from occamo.analyze.go import UNAVAILABLE_REASON as GO_UNAVAILABLE_REASON
from occamo.analyze.go import analyze_source as analyze_go
from occamo.analyze.java import TS_AVAILABLE as JAVA_AVAILABLE
from occamo.analyze.java import UNAVAILABLE_REASON as JAVA_UNAVAILABLE_REASON
from occamo.analyze.java import analyze_source as analyze_java
from occamo.analyze.js_ts import TS_AVAILABLE, UNAVAILABLE_REASON
from occamo.analyze.js_ts import analyze_source as analyze_js_ts
from occamo.analyze.kotlin import TS_AVAILABLE as KOTLIN_AVAILABLE
from occamo.analyze.kotlin import UNAVAILABLE_REASON as KOTLIN_UNAVAILABLE_REASON
from occamo.analyze.kotlin import analyze_source as analyze_kotlin
from occamo.analyze.static_ast import FunctionFinding
from occamo.analyze.static_ast import analyze_source as analyze_python
from occamo.util.languages import language_for_path

log = logging.getLogger(__name__)

_WARNED = False
_WARNED_JAVA = False
_WARNED_KOTLIN = False
_WARNED_GO = False


def analyze_source(path: Path, src: str) -> list[FunctionFinding]:
    language = language_for_path(path)
    if language == "python":
        return analyze_python(path, src)
    if language in {"javascript", "typescript"}:
        if not TS_AVAILABLE:
            global _WARNED
            if not _WARNED:
                reason = UNAVAILABLE_REASON or "tree-sitter unavailable"
                log.warning("JS/TS analysis unavailable (%s). Install occamo[js] to enable.", reason)
                _WARNED = True
            return []
        return analyze_js_ts(path, src)
    if language == "java":
        if not JAVA_AVAILABLE:
            global _WARNED_JAVA
            if not _WARNED_JAVA:
                reason = JAVA_UNAVAILABLE_REASON or "tree-sitter unavailable"
                log.warning("Java analysis unavailable (%s). Install occamo[js] to enable.", reason)
                _WARNED_JAVA = True
            return []
        return analyze_java(path, src)
    if language == "kotlin":
        if not KOTLIN_AVAILABLE:
            global _WARNED_KOTLIN
            if not _WARNED_KOTLIN:
                reason = KOTLIN_UNAVAILABLE_REASON or "tree-sitter unavailable"
                log.warning("Kotlin analysis unavailable (%s). Install occamo[js] to enable.", reason)
                _WARNED_KOTLIN = True
            return []
        return analyze_kotlin(path, src)
    if language == "go":
        if not GO_AVAILABLE:
            global _WARNED_GO
            if not _WARNED_GO:
                reason = GO_UNAVAILABLE_REASON or "tree-sitter unavailable"
                log.warning("Go analysis unavailable (%s). Install occamo[js] to enable.", reason)
                _WARNED_GO = True
            return []
        return analyze_go(path, src)
    return []


def analyze_file(path: Path) -> list[FunctionFinding]:
    try:
        src = path.read_text(encoding="utf-8")
    except Exception:
        return []
    return analyze_source(path, src)
