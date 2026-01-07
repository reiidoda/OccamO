from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from occamo.analyze.static_ast import FunctionFinding


@dataclass(frozen=True)
class HotSpot:
    function_id: str
    weight: float
    note: str


_SPEEDSCOPE_FRAME = re.compile(r"\(([^:]+):(\d+)\)$")


def _normalize_pattern(pattern: str) -> str:
    p = pattern.strip().replace("\\", "/")
    if not p:
        return ""
    if p.startswith("./"):
        p = p[2:]
    if p.startswith("/"):
        p = p.lstrip("/")
    if p.endswith("/"):
        return f"{p}**"
    return p


def _match_path(patterns: list[str], file_path: str) -> bool:
    rel = PurePosixPath(file_path)
    return any(rel.match(p) for p in patterns)


def _match_by_name(findings: Iterable[FunctionFinding], file_name: str, func_name: str) -> FunctionFinding | None:
    candidates = [
        f
        for f in findings
        if Path(f.file).name == Path(file_name).name and f.qualname.endswith(func_name)
    ]
    if len(candidates) == 1:
        return candidates[0]
    if candidates:
        candidates.sort(key=lambda f: abs(f.lineno))
        return candidates[0]
    return None


def _load_pstats(path: Path, top_n: int) -> list[tuple[str, str, int, float]]:
    try:
        import pstats
    except Exception:
        return []
    try:
        stats = pstats.Stats(str(path))
    except Exception:
        return []
    raw_stats = getattr(stats, "stats", None)
    if not isinstance(raw_stats, dict):
        return []
    entries: list[tuple[str, str, int, float]] = []
    for (filename, lineno, func), (_, nc, _, ct, _) in raw_stats.items():
        score = float(ct) if ct else float(nc)
        entries.append((str(filename), str(func), int(lineno), score))
    entries.sort(key=lambda item: item[3], reverse=True)
    return entries[: max(1, top_n)]


def _load_trace_summary(path: Path, top_n: int) -> list[tuple[str, str, int, float]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if isinstance(data, dict) and "shared" in data and "profiles" in data:
        return _load_speedscope(data, top_n)
    functions = data.get("functions") if isinstance(data, dict) else None
    if not isinstance(functions, list):
        return []
    entries: list[tuple[str, str, int, float]] = []
    for item in functions:
        if not isinstance(item, dict):
            continue
        file_path = str(item.get("file", ""))
        qualname = str(item.get("qualname", ""))
        lineno = int(item.get("lineno", 1) or 1)
        score = float(item.get("count", 0.0) or 0.0)
        if not file_path or not qualname:
            continue
        entries.append((file_path, qualname, lineno, score))
    entries.sort(key=lambda item: item[3], reverse=True)
    return entries[: max(1, top_n)]


def _load_speedscope(data: dict, top_n: int) -> list[tuple[str, str, int, float]]:
    frames = data.get("shared", {}).get("frames", [])
    profiles = data.get("profiles", [])
    weights: dict[int, float] = {}
    for profile in profiles:
        samples = profile.get("samples", [])
        sample_weights = profile.get("weights", [])
        if not isinstance(samples, list) or not isinstance(sample_weights, list):
            continue
        for stack, weight in zip(samples, sample_weights, strict=False):
            if not isinstance(stack, list):
                continue
            for frame_id in stack:
                try:
                    weights[int(frame_id)] = weights.get(int(frame_id), 0.0) + float(weight)
                except Exception:
                    continue
    entries: list[tuple[str, str, int, float]] = []
    for idx, frame in enumerate(frames):
        if idx not in weights:
            continue
        name = str(frame.get("name", ""))
        match = _SPEEDSCOPE_FRAME.search(name)
        if match:
            file_path = match.group(1)
            lineno = int(match.group(2))
            func_name = name.split("(", 1)[0].strip()
        else:
            file_path = ""
            lineno = 1
            func_name = name.strip()
        if not func_name:
            continue
        entries.append((file_path, func_name, lineno, float(weights[idx])))
    entries.sort(key=lambda item: item[3], reverse=True)
    return entries[: max(1, top_n)]


def compute_hotspots(
    findings: list[FunctionFinding],
    hot_paths: list[str],
    hot_functions: list[str],
    hot_multiplier: float,
    profile_path: str | None,
    profile_top: int,
    trace_summary_path: str | None,
) -> list[HotSpot]:
    hotspots: dict[str, HotSpot] = {}
    patterns = [_normalize_pattern(p) for p in hot_paths if _normalize_pattern(p)]
    for finding in findings:
        if not patterns:
            break
        if _match_path(patterns, finding.file):
            hotspots[finding.function_id] = HotSpot(
                function_id=finding.function_id,
                weight=hot_multiplier,
                note="hot path (path rule)",
            )

    for entry in hot_functions:
        entry = str(entry).strip()
        if not entry:
            continue
        if ":" in entry:
            file_part, qualname = entry.rsplit(":", 1)
            match = next(
                (
                    f
                    for f in findings
                    if f.file.endswith(file_part) and f.qualname.endswith(qualname)
                ),
                None,
            )
        else:
            match = next((f for f in findings if f.qualname.endswith(entry)), None)
        if match and match.function_id:
            hotspots[match.function_id] = HotSpot(
                function_id=match.function_id,
                weight=hot_multiplier,
                note="hot path (function rule)",
            )

    if profile_path:
        path = Path(profile_path)
        entries = _load_pstats(path, profile_top)
        for file_name, func_name, _lineno, score in entries:
            match = _match_by_name(findings, file_name, func_name)
            if not match:
                continue
            weight = hot_multiplier + min(1.0, score / max(1.0, entries[0][3]))
            hotspots[match.function_id] = HotSpot(
                function_id=match.function_id,
                weight=weight,
                note="hot path (pstats)",
            )

    if trace_summary_path:
        path = Path(trace_summary_path)
        entries = _load_trace_summary(path, profile_top)
        for file_name, func_name, _lineno, score in entries:
            match = None
            if file_name:
                match = _match_by_name(findings, file_name, func_name)
            if not match:
                match = next((f for f in findings if f.qualname.endswith(func_name)), None)
            if not match:
                continue
            weight = hot_multiplier + min(1.0, score / max(1.0, entries[0][3]))
            hotspots[match.function_id] = HotSpot(
                function_id=match.function_id,
                weight=weight,
                note="hot path (trace)",
            )

    return list(hotspots.values())
