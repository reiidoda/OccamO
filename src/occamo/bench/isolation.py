from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from .generators import ModuleSpec, generate_module


@dataclass(frozen=True)
class RepoSpec:
    modules: int
    module_spec: ModuleSpec


def create_synthetic_repo(root: Path, spec: RepoSpec) -> None:
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)
    for idx in range(spec.modules):
        module_path = src / f"bench_module_{idx}.py"
        module_path.write_text(generate_module(spec.module_spec), encoding="utf-8")


@contextmanager
def synthetic_repo(spec: RepoSpec) -> Iterator[tuple[TemporaryDirectory[str], Path]]:
    tmp = TemporaryDirectory()
    try:
        root = Path(tmp.name)
        create_synthetic_repo(root, spec)
        yield tmp, root
    finally:
        tmp.cleanup()
