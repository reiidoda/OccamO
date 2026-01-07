from __future__ import annotations

import subprocess
from pathlib import Path


def _run_git_checked(repo_root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _run_git(repo_root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return _run_git_checked(repo_root, args)


def ref_exists(repo_root: Path, ref: str) -> bool:
    p = _run_git_checked(repo_root, ["rev-parse", "--verify", ref])
    return p.returncode == 0


def read_file_at_ref(repo_root: Path, ref: str, path: Path) -> str | None:
    try:
        rel = path.resolve().relative_to(repo_root.resolve())
    except Exception:
        return None
    p = _run_git_checked(repo_root, ["show", f"{ref}:{rel.as_posix()}"])
    if p.returncode != 0:
        return None
    return p.stdout


def changed_files(repo_root: Path, base_ref: str = "origin/main") -> list[Path] | None:
    """Best-effort list of changed files vs a base ref.

    Returns None if git diff fails, else a list (possibly empty).
    """
    p = _run_git(repo_root, ["diff", "--name-only", f"{base_ref}...HEAD"])
    if p.returncode != 0:
        return None
    out = p.stdout
    files: list[Path] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        files.append(repo_root / line)
    return files


def changed_lines(
    repo_root: Path, base_ref: str = "origin/main"
) -> dict[Path, list[tuple[int, int]]] | None:
    """Return changed line ranges (new file side) by file.

    Returns None if git diff fails.
    """
    p = _run_git(repo_root, ["diff", "-U0", "--no-color", f"{base_ref}...HEAD"])
    if p.returncode != 0:
        return None

    ranges: dict[Path, list[tuple[int, int]]] = {}
    current_file: Path | None = None
    for line in p.stdout.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path == "/dev/null":
                current_file = None
                continue
            if path.startswith("b/"):
                path = path[2:]
            current_file = repo_root / path
            ranges.setdefault(current_file, [])
            continue
        if line.startswith("@@") and current_file is not None:
            # Format: @@ -a,b +c,d @@
            try:
                header = line.split("+", 1)[1]
                new_range = header.split(" ", 1)[0]
                if "," in new_range:
                    start_s, count_s = new_range.split(",", 1)
                    start = int(start_s)
                    count = int(count_s)
                else:
                    start = int(new_range)
                    count = 1
                if count == 0:
                    continue
                end = start + count - 1
                ranges[current_file].append((start, end))
            except Exception:
                continue
    return ranges
