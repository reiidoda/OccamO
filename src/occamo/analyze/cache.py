from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from occamo.analyze.signals import StaticSignals
from occamo.analyze.static_ast import FunctionFinding

CACHE_SCHEMA_VERSION = 2


def file_hash(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _finding_to_dict(finding: FunctionFinding) -> dict[str, Any]:
    return {
        "file": finding.file,
        "qualname": finding.qualname,
        "lineno": finding.lineno,
        "end_lineno": finding.end_lineno,
        "signals": asdict(finding.signals),
        "complexity_hint": finding.complexity_hint,
        "confidence": finding.confidence,
        "body_hash": finding.body_hash,
        "function_id": finding.function_id,
    }


def _finding_from_dict(raw: dict[str, Any]) -> FunctionFinding:
    signals = raw.get("signals", {})
    return FunctionFinding(
        file=str(raw.get("file", "")),
        qualname=str(raw.get("qualname", "")),
        lineno=int(raw.get("lineno", 1)),
        end_lineno=int(raw.get("end_lineno", raw.get("lineno", 1))),
        signals=StaticSignals(
            loops=int(signals.get("loops", 0)),
            max_loop_depth=int(signals.get("max_loop_depth", 0)),
            recursion=bool(signals.get("recursion", False)),
            sort_calls=int(signals.get("sort_calls", 0)),
            comprehension=int(signals.get("comprehension", 0)),
        ),
        complexity_hint=str(raw.get("complexity_hint", "")),
        confidence=float(raw.get("confidence", 0.0)),
        body_hash=str(raw.get("body_hash", "")),
        function_id=str(raw.get("function_id", "")),
    )


def load_cache(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema_version": CACHE_SCHEMA_VERSION, "files": {}}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"schema_version": CACHE_SCHEMA_VERSION, "files": {}}
    if not isinstance(raw, dict):
        return {"schema_version": CACHE_SCHEMA_VERSION, "files": {}}
    if raw.get("schema_version") != CACHE_SCHEMA_VERSION:
        return {"schema_version": CACHE_SCHEMA_VERSION, "files": {}}
    files = raw.get("files")
    if not isinstance(files, dict):
        return {"schema_version": CACHE_SCHEMA_VERSION, "files": {}}
    return {"schema_version": CACHE_SCHEMA_VERSION, "files": files}


def save_cache(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def get_cached_findings(
    cache: dict[str, Any], rel_path: str, file_hash_value: str
) -> list[FunctionFinding] | None:
    files = cache.get("files", {})
    entry = files.get(rel_path)
    if not isinstance(entry, dict):
        return None
    if entry.get("hash") != file_hash_value:
        return None
    raw_findings = entry.get("findings", [])
    if not isinstance(raw_findings, list):
        return None
    return [_finding_from_dict(item) for item in raw_findings if isinstance(item, dict)]


def update_cache(
    cache: dict[str, Any],
    rel_path: str,
    file_hash_value: str,
    findings: list[FunctionFinding],
) -> None:
    files = cache.setdefault("files", {})
    files[rel_path] = {
        "hash": file_hash_value,
        "findings": [_finding_to_dict(f) for f in findings],
    }
