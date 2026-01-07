from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath

from occamo.config.schema import OccamOConfig
from occamo.util.languages import extensions_for_languages

_GLOB_CHARS = set("*?[")


def _is_supported_file(p: Path, extensions: set[str]) -> bool:
    if not p.is_file() or p.suffix.lower() not in extensions:
        return False
    if p.suffix.lower() == ".py" and p.name == "__init__.py":
        return False
    return True


def _has_glob(pattern: str) -> bool:
    return any(ch in pattern for ch in _GLOB_CHARS)


def _expand_glob_patterns(pattern: str) -> list[str]:
    patterns = [pattern]
    if "**/" in pattern:
        patterns.append(pattern.replace("**/", ""))
    if pattern.endswith("/**"):
        suffix = pattern[:-3]
        patterns.append(suffix or ".")
    seen: list[str] = []
    for item in patterns:
        if not item:
            continue
        if item not in seen:
            seen.append(item)
    return seen


def _normalize_pattern(pattern: str) -> str:
    p = pattern.strip()
    if not p or p.startswith("#"):
        return ""
    p = p.replace("\\", "/")
    if p.startswith("./"):
        p = p[2:]
    if p.startswith("/"):
        p = p.lstrip("/")
    if p == ".":
        return "**"
    if p.endswith("/"):
        return f"{p}**"
    if not _has_glob(p) and Path(p).suffix == "":
        return f"{p}/**"
    return p


def _normalize_patterns(patterns: Iterable[str]) -> list[str]:
    out: list[str] = []
    for pattern in patterns:
        norm = _normalize_pattern(str(pattern))
        if not norm:
            continue
        for expanded in _expand_glob_patterns(norm):
            if expanded not in out:
                out.append(expanded)
    return out


def _load_ignore_lines(repo_root: Path) -> list[str]:
    ignore_path = repo_root / ".occamoignore"
    if not ignore_path.exists():
        return []
    try:
        lines = ignore_path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    return [line for line in lines if line.strip() and not line.lstrip().startswith("#")]


def _build_ignore_matcher(repo_root: Path) -> Callable[[PurePosixPath], bool]:
    lines = _load_ignore_lines(repo_root)
    if not lines:
        return lambda _p: False
    try:
        import pathspec
    except Exception:
        patterns = _normalize_patterns(
            [line for line in lines if not line.lstrip().startswith("!")]
        )

        def match_patterns(rel: PurePosixPath) -> bool:
            return any(rel.match(pattern) for pattern in patterns)

        return match_patterns

    spec = pathspec.PathSpec.from_lines("gitignore", lines)

    def match_spec(rel: PurePosixPath) -> bool:
        return bool(spec.match_file(rel.as_posix()))

    return match_spec


def _build_included_predicate(repo_root: Path, cfg: OccamOConfig) -> Callable[[Path], bool]:
    include_patterns = _normalize_patterns(cfg.include or ["."])
    exclude_patterns = _normalize_patterns(cfg.exclude)
    ignore_matcher = _build_ignore_matcher(repo_root)

    def included(p: Path) -> bool:
        try:
            rel = p.resolve().relative_to(repo_root.resolve())
        except Exception:
            return False
        rel_posix = PurePosixPath(rel.as_posix())
        if include_patterns and not any(rel_posix.match(pattern) for pattern in include_patterns):
            return False
        if any(rel_posix.match(pattern) for pattern in exclude_patterns):
            return False
        if ignore_matcher(rel_posix):
            return False
        return True

    return included


def select_files(repo_root: Path, cfg: OccamOConfig, candidates: Iterable[Path]) -> list[Path]:
    included = _build_included_predicate(repo_root, cfg)
    extensions = extensions_for_languages(cfg.languages)
    out: list[Path] = []
    for p in candidates:
        if _is_supported_file(p, extensions) and included(p):
            out.append(p)
    return out


def discover_files(repo_root: Path, cfg: OccamOConfig) -> list[Path]:
    patterns = cfg.include or ["."]
    included = _build_included_predicate(repo_root, cfg)
    extensions = extensions_for_languages(cfg.languages)
    seen: set[Path] = set()
    files: list[Path] = []
    for pattern in patterns:
        pattern = str(pattern).strip()
        if not pattern:
            continue
        if pattern.startswith("./"):
            pattern = pattern[2:]
        if pattern.startswith("/"):
            pattern = pattern.lstrip("/")
        matches: list[Path]
        if _has_glob(pattern):
            matches = []
            for glob_pattern in _expand_glob_patterns(pattern):
                matches.extend(repo_root.glob(glob_pattern))
        else:
            matches = [repo_root / pattern]
        for match in matches:
            candidates: list[Path]
            if match.is_dir():
                candidates = []
                for ext in extensions:
                    candidates.extend(match.rglob(f"*{ext}"))
            else:
                candidates = [match]
            for p in candidates:
                if not _is_supported_file(p, extensions):
                    continue
                try:
                    rp = p.resolve()
                except Exception:
                    continue
                if rp in seen:
                    continue
                seen.add(rp)
                if not included(p):
                    continue
                files.append(p)
                if len(files) >= cfg.max_files:
                    return files
    return files
