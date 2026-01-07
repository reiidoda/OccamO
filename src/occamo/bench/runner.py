from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from occamo.analyze.entrypoints import discover_files
from occamo.analyze.static_ast import analyze_file
from occamo.config.schema import OccamOConfig

from .generators import ModuleSpec
from .isolation import RepoSpec, create_synthetic_repo


@dataclass(frozen=True)
class BenchCase:
    name: str
    spec: RepoSpec


def _default_cases() -> list[BenchCase]:
    return [
        BenchCase(
            name="small",
            spec=RepoSpec(modules=4, module_spec=ModuleSpec(functions=20, loop_depth=2, recursion_every=9)),
        ),
        BenchCase(
            name="medium",
            spec=RepoSpec(
                modules=8,
                module_spec=ModuleSpec(functions=40, loop_depth=3, recursion_every=11, comprehension_every=5),
            ),
        ),
        BenchCase(
            name="large",
            spec=RepoSpec(
                modules=12,
                module_spec=ModuleSpec(functions=70, loop_depth=3, recursion_every=13, comprehension_every=7),
            ),
        ),
    ]


def _prepare_case(case: BenchCase) -> tuple[TemporaryDirectory[str], list[Path]]:
    temp = TemporaryDirectory()
    root = Path(temp.name)
    create_synthetic_repo(root, case.spec)
    cfg = OccamOConfig(include=["src"], exclude=["tests", ".venv", "venv", "build", "dist"], max_files=5000)
    files = discover_files(root, cfg)
    return temp, files


def _run_analyze(files: Iterable[Path]) -> int:
    count = 0
    for fp in files:
        count += len(analyze_file(fp))
    return count


def _measure_simple(func: Callable[[], int], warmups: int, iterations: int) -> list[float]:
    for _ in range(max(0, warmups)):
        func()
    samples: list[float] = []
    for _ in range(max(1, iterations)):
        start = time.perf_counter()
        func()
        samples.append(time.perf_counter() - start)
    return samples


def _run_simple(
    cases: list[BenchCase],
    warmups: int,
    iterations: int,
) -> dict[str, Any]:
    case_results: list[dict[str, Any]] = []
    results: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "cases": case_results,
    }

    for case in cases:
        temp, files = _prepare_case(case)
        try:
            def run_case(local_files: Iterable[Path] = files) -> int:
                return _run_analyze(local_files)

            samples = _measure_simple(run_case, warmups=warmups, iterations=iterations)
            median = statistics.median(samples)
            case_results.append(
                {
                    "name": case.name,
                    "modules": case.spec.modules,
                    "functions": case.spec.module_spec.functions,
                    "loop_depth": case.spec.module_spec.loop_depth,
                    "seconds": median,
                    "samples": samples,
                    "iterations": max(1, iterations),
                }
            )
        finally:
            temp.cleanup()
    return results


def _load_results(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _compare_results(
    baseline: dict[str, Any],
    current: dict[str, Any],
    max_regression: float,
) -> list[str]:
    base_cases = {
        case.get("name"): case
        for case in baseline.get("cases", [])
        if isinstance(case, dict)
    }
    errors: list[str] = []
    for case in current.get("cases", []):
        if not isinstance(case, dict):
            continue
        name = case.get("name")
        base = base_cases.get(name)
        if not base:
            continue
        base_time = float(base.get("seconds", 0.0))
        head_time = float(case.get("seconds", 0.0))
        if base_time <= 0:
            continue
        ratio = head_time / base_time
        if ratio > 1.0 + max_regression:
            pct = (ratio - 1.0) * 100.0
            errors.append(f"{name}: {pct:.1f}% slower ({head_time:.4f}s vs {base_time:.4f}s)")
    return errors


def _filter_cases(cases: list[BenchCase], names: list[str] | None) -> list[BenchCase]:
    if not names:
        return cases
    selected = set(names)
    return [case for case in cases if case.name in selected]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="occamo-bench", description="OccamO benchmark harness")
    parser.add_argument("--engine", choices=["simple", "pyperf"], default="simple")
    parser.add_argument("--case", action="append", default=None, help="Run only these case names")
    parser.add_argument("--iterations", type=int, default=5, help="Timing iterations per case")
    parser.add_argument("--warmups", type=int, default=2, help="Warmup runs per case")
    parser.add_argument("--json", default=None, help="Output JSON path (simple engine only)")
    parser.add_argument("--baseline", default=None, help="Baseline JSON to compare against")
    parser.add_argument(
        "--max-regression",
        type=float,
        default=0.10,
        help="Max allowed slowdown vs baseline (default: 0.10 = 10%%)",
    )

    args = parser.parse_args(argv)
    cases = _filter_cases(_default_cases(), args.case)

    if args.engine == "pyperf":
        try:
            import pyperf  # type: ignore
        except Exception:
            parser.error("pyperf not installed. Use --engine simple or install occamo[bench].")
        if args.baseline:
            parser.error("--baseline is only supported with --engine simple")
        if args.json:
            parser.error("--json is only supported with --engine simple")
        runner = pyperf.Runner()
        for case in cases:
            temp, files = _prepare_case(case)
            try:
                def run_case(local_files: Iterable[Path] = files) -> int:
                    return _run_analyze(local_files)

                runner.bench_func(f"occamo.{case.name}", run_case)
            finally:
                temp.cleanup()
        return 0

    results = _run_simple(cases, warmups=args.warmups, iterations=args.iterations)
    output_path = Path(args.json or "out/occamo.bench.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    if args.baseline:
        baseline = _load_results(Path(args.baseline))
        errors = _compare_results(baseline, results, max_regression=args.max_regression)
        if errors:
            for error in errors:
                print(f"Benchmark regression: {error}")
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
