from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from occamo.analyze.static_ast import FunctionFinding
from occamo.git.diff import read_file_at_ref
from occamo.report.models import DynamicCheck, DynamicRegression
from occamo.util.math import simple_curve_fit

_HINT_RANK: dict[str, int] = {
    "O(1) / O(log n) candidate": 0,
    "O(n) candidate": 1,
    "O(n log n) candidate": 2,
    "O(n log n) + loop": 3,
    "O(n^2) candidate": 4,
    "O(n^3) or worse": 5,
    "potentially exponential / high": 6,
}

_DYNAMIC_SCORES: dict[str, float] = {
    "O(1) / O(log n) candidate": 0.3,
    "O(n) candidate": 0.9,
    "O(n log n) candidate": 1.4,
    "O(n^2) candidate": 2.2,
    "O(n^3) or worse": 3.0,
}

_PROBE_SCRIPT = r"""
import contextlib
import importlib
import importlib.util
import inspect
import io
import json
import random
import statistics
import sys
import time
from pathlib import Path

def _apply_resource_limits(memory_limit_mb):
    if not memory_limit_mb:
        return
    try:
        import resource
    except Exception:
        return
    limit = int(memory_limit_mb) * 1024 * 1024
    if limit <= 0:
        return
    try:
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except Exception:
        try:
            resource.setrlimit(resource.RLIMIT_DATA, (limit, limit))
        except Exception:
            return

def _load_module(path, repo_root):
    module = None
    errors = []
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        try:
            spec = importlib.util.spec_from_file_location("occamo_dyn", path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module
        except Exception as exc:
            errors.append(str(exc))
        repo_root = Path(repo_root)
        roots = [repo_root, repo_root / "src"]
        for root in roots:
            try:
                rel = Path(path).resolve().relative_to(root.resolve())
            except Exception:
                continue
            module_name = ".".join(rel.with_suffix("").parts)
            if not module_name:
                continue
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(module_name)
                return module
            except Exception as exc:
                errors.append(str(exc))
            finally:
                if sys.path and sys.path[0] == str(root):
                    sys.path.pop(0)
    raise RuntimeError("import failed: " + "; ".join(errors))

def _make_arg(name, annotation, size):
    lowered = name.lower()
    if lowered in {"n", "size", "count", "limit", "length", "len"}:
        return size
    if lowered in {"xs", "ys", "items", "values", "data", "arr", "list", "seq", "iterable"}:
        return list(range(size))
    if lowered in {"mapping", "dict", "map", "lookup"}:
        return {i: i for i in range(size)}
    if annotation in {int, float}:
        return size
    return list(range(size))

def _build_args(func, size):
    sig = inspect.signature(func)
    args = []
    kwargs = {}
    required = [
        p for p in sig.parameters.values()
        if p.default is inspect._empty
        and p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
    ]
    if len(required) > 3:
        raise RuntimeError("too many required parameters")
    for param in required:
        value = _make_arg(param.name, param.annotation, size)
        if param.kind == inspect.Parameter.KEYWORD_ONLY:
            kwargs[param.name] = value
        else:
            args.append(value)
    return args, kwargs

def _resolve_qualname(module, qualname):
    obj = module
    parts = qualname.split(".") if qualname else []
    for idx, part in enumerate(parts):
        if not hasattr(obj, part):
            raise RuntimeError("qualname not found")
        obj = getattr(obj, part)
        if inspect.isclass(obj) and idx < len(parts) - 1:
            obj = obj()
    return obj

def main():
    payload = json.load(sys.stdin)
    path = payload.get("path")
    qualname = payload.get("qualname", "")
    sizes = payload.get("sizes", [])
    trials = int(payload.get("trials", 1) or 1)
    warmups = int(payload.get("warmups", 0) or 0)
    memory_limit_mb = payload.get("memory_limit_mb")
    repo_root = payload.get("repo_root", ".")
    if not path:
        print(json.dumps({"ok": False, "error": "missing path"}))
        return
    try:
        random.seed(1337)
        _apply_resource_limits(memory_limit_mb)
        module = _load_module(path, repo_root)
        target = _resolve_qualname(module, qualname)
        if not callable(target):
            raise RuntimeError("target not callable")
        times = []
        jitter_values = []
        for size in sizes:
            args, kwargs = _build_args(target, int(size))
            for _ in range(max(warmups, 0)):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    target(*args, **kwargs)
            durations = []
            for _ in range(max(trials, 1)):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    start = time.perf_counter()
                    target(*args, **kwargs)
                    durations.append(time.perf_counter() - start)
            if durations:
                times.append(statistics.median(durations))
                if len(durations) > 1:
                    mean = statistics.mean(durations)
                    if mean > 0:
                        jitter_values.append(statistics.stdev(durations) / mean)
            else:
                times.append(0.0)
        jitter = max(jitter_values) if jitter_values else 0.0
        print(json.dumps({"ok": True, "sizes": sizes, "times": times, "jitter": jitter}))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))

if __name__ == "__main__":
    main()
"""


@dataclass(frozen=True)
class DynamicProbe:
    sizes: list[int]
    times: list[float]
    error: str | None = None
    jitter: float = 0.0


def dynamic_risk_score(label: str) -> float | None:
    return _DYNAMIC_SCORES.get(label)


def _run_probe(
    repo_root: Path,
    path: Path,
    qualname: str,
    sizes: list[int],
    timeout_seconds: float,
    trials: int,
    warmups: int,
    memory_limit_mb: int | None,
) -> DynamicProbe:
    payload = {
        "path": str(path),
        "qualname": qualname,
        "sizes": sizes,
        "trials": trials,
        "warmups": warmups,
        "memory_limit_mb": memory_limit_mb,
        "repo_root": str(repo_root),
    }
    try:
        result = subprocess.run(
            [sys.executable, "-c", _PROBE_SCRIPT],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            env={**os.environ, "PYTHONHASHSEED": "0"},
            cwd=str(repo_root),
        )
    except subprocess.TimeoutExpired:
        return DynamicProbe(sizes=sizes, times=[], error="timeout")
    if result.returncode != 0:
        error = result.stderr.strip() or "probe failed"
        return DynamicProbe(sizes=sizes, times=[], error=error)
    try:
        data = json.loads(result.stdout.strip() or "{}")
    except json.JSONDecodeError:
        return DynamicProbe(sizes=sizes, times=[], error="invalid probe output")
    if not data.get("ok"):
        return DynamicProbe(sizes=sizes, times=[], error=str(data.get("error", "probe error")))
    return DynamicProbe(
        sizes=[int(n) for n in data.get("sizes", [])],
        times=[float(t) for t in data.get("times", [])],
        jitter=float(data.get("jitter", 0.0) or 0.0),
    )


def _dynamic_status(
    static_hint: str,
    dynamic_label: str,
    confidence: float,
    min_confidence: float,
) -> str:
    if confidence < min_confidence:
        return "inconclusive"
    static_rank = _HINT_RANK.get(static_hint)
    dynamic_rank = _HINT_RANK.get(dynamic_label)
    if static_rank is None or dynamic_rank is None:
        return "inconclusive"
    if dynamic_rank < static_rank:
        return "downgraded"
    return "confirmed"


def run_dynamic_checks(
    repo_root: Path,
    findings: Iterable[FunctionFinding],
    top_n: int,
    sizes: list[int],
    timeout_seconds: float,
    min_confidence: float,
    trials: int,
    warmups: int,
    memory_limit_mb: int | None,
    jitter_threshold: float | None,
) -> dict[str, DynamicCheck]:
    results: dict[str, DynamicCheck] = {}
    for finding in list(findings)[: max(0, top_n)]:
        if not finding.file.endswith(".py"):
            if finding.function_id:
                results[finding.function_id] = DynamicCheck(
                    label="unknown",
                    confidence=0.0,
                    status="skipped",
                    note="non-python file",
                )
            continue
        if not finding.function_id:
            continue
        abs_path = repo_root / finding.file
        probe = _run_probe(
            repo_root=repo_root,
            path=abs_path,
            qualname=finding.qualname,
            sizes=sizes,
            timeout_seconds=timeout_seconds,
            trials=trials,
            warmups=warmups,
            memory_limit_mb=memory_limit_mb,
        )
        if probe.error:
            results[finding.function_id] = DynamicCheck(
                label="unknown",
                confidence=0.0,
                status="skipped",
                note=probe.error,
            )
            continue
        fit = simple_curve_fit(probe.sizes, probe.times)
        status = _dynamic_status(
            finding.complexity_hint, fit.label, fit.confidence, min_confidence
        )
        note_parts: list[str] = []
        if status == "inconclusive":
            note_parts.append(f"low confidence ({fit.confidence:.2f})")
        if jitter_threshold is not None and probe.jitter > jitter_threshold:
            status = "inconclusive"
            note_parts.append(f"high variance ({probe.jitter:.2f})")
        note = ", ".join(note_parts)
        results[finding.function_id] = DynamicCheck(
            label=fit.label,
            confidence=fit.confidence,
            status=status,
            note=note,
        )
    return results


def run_dynamic_regressions(
    repo_root: Path,
    regressions: Iterable,
    head_map: dict[str, FunctionFinding],
    base_map: dict[str, FunctionFinding],
    base_ref: str,
    top_n: int,
    sizes: list[int],
    timeout_seconds: float,
    min_confidence: float,
    trials: int,
    slowdown_ratio: float,
    warmups: int,
    memory_limit_mb: int | None,
    jitter_threshold: float | None,
) -> dict[str, DynamicRegression]:
    results: dict[str, DynamicRegression] = {}
    ranked = list(regressions)[: max(0, top_n)]
    if not ranked:
        return results
    with tempfile.TemporaryDirectory(prefix="occamo-base-") as tmp_dir:
        base_root = Path(tmp_dir)
        base_cache: dict[str, Path] = {}

        for regression in ranked:
            function_id = getattr(regression, "function_id", "")
            if not function_id:
                continue
            head = head_map.get(function_id)
            base = base_map.get(function_id)
            if head is None or base is None:
                continue
            if not head.file.endswith(".py") or not base.file.endswith(".py"):
                results[function_id] = DynamicRegression(
                    status="skipped", ratio=1.0, note="non-python file"
                )
                continue

            base_path = base_cache.get(base.file)
            if base_path is None:
                src = read_file_at_ref(repo_root, base_ref, repo_root / base.file)
                if src is None:
                    results[function_id] = DynamicRegression(
                        status="skipped", ratio=1.0, note="base file not found"
                    )
                    continue
                base_path = base_root / base.file
                base_path.parent.mkdir(parents=True, exist_ok=True)
                base_path.write_text(src, encoding="utf-8")
                _ensure_package_tree(base_root, base_path)
                base_cache[base.file] = base_path

            head_path = repo_root / head.file
            base_probe = _run_probe(
                repo_root=base_root,
                path=base_path,
                qualname=base.qualname,
                sizes=sizes,
                timeout_seconds=timeout_seconds,
                trials=trials,
                warmups=warmups,
                memory_limit_mb=memory_limit_mb,
            )
            head_probe = _run_probe(
                repo_root=repo_root,
                path=head_path,
                qualname=head.qualname,
                sizes=sizes,
                timeout_seconds=timeout_seconds,
                trials=trials,
                warmups=warmups,
                memory_limit_mb=memory_limit_mb,
            )
            if base_probe.error or head_probe.error:
                note = base_probe.error or head_probe.error or "probe failed"
                results[function_id] = DynamicRegression(
                    status="skipped", ratio=1.0, note=note
                )
                continue
            ratio = _median_ratio(base_probe.times, head_probe.times)
            if ratio is None:
                results[function_id] = DynamicRegression(
                    status="skipped", ratio=1.0, note="invalid timing data"
                )
                continue
            base_fit = simple_curve_fit(base_probe.sizes, base_probe.times)
            head_fit = simple_curve_fit(head_probe.sizes, head_probe.times)
            note = f"ratio {ratio:.2f}, base={base_fit.label}, head={head_fit.label}"
            status = "inconclusive"
            if min(base_fit.confidence, head_fit.confidence) < min_confidence:
                status = "inconclusive"
                note = f"{note}, low confidence"
            else:
                if ratio >= slowdown_ratio:
                    status = "confirmed"
                elif ratio <= (1.0 / slowdown_ratio):
                    status = "downgraded"
            if jitter_threshold is not None and (
                base_probe.jitter > jitter_threshold or head_probe.jitter > jitter_threshold
            ):
                status = "inconclusive"
                max_jitter = max(base_probe.jitter, head_probe.jitter)
                note = f"{note}, high variance ({max_jitter:.2f})"
            results[function_id] = DynamicRegression(
                status=status,
                ratio=ratio,
                note=note,
            )
    return results


def _median_ratio(base_times: list[float], head_times: list[float]) -> float | None:
    if not base_times or not head_times:
        return None
    ratios: list[float] = []
    for base_t, head_t in zip(base_times, head_times, strict=False):
        if base_t <= 0:
            continue
        ratios.append(head_t / base_t)
    if not ratios:
        return None
    return float(statistics.median(ratios))


def _ensure_package_tree(repo_root: Path, path: Path) -> None:
    try:
        rel = path.resolve().relative_to(repo_root.resolve())
    except Exception:
        return
    current = repo_root
    for part in rel.parts[:-1]:
        current = current / part
        current.mkdir(parents=True, exist_ok=True)
        init_file = current / "__init__.py"
        if not init_file.exists():
            init_file.write_text("", encoding="utf-8")
