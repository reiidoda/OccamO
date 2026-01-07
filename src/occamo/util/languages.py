from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

LANGUAGE_ALIASES = {
    "py": "python",
    "python": "python",
    "js": "javascript",
    "jsx": "javascript",
    "javascript": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "typescript": "typescript",
    "java": "java",
    "kotlin": "kotlin",
    "kt": "kotlin",
    "kts": "kotlin",
    "go": "go",
    "golang": "go",
}

LANGUAGE_EXTENSIONS = {
    "python": [".py"],
    "javascript": [".js", ".jsx"],
    "typescript": [".ts", ".tsx"],
    "java": [".java"],
    "kotlin": [".kt", ".kts"],
    "go": [".go"],
}

SUPPORTED_LANGUAGES = sorted(LANGUAGE_EXTENSIONS.keys())


def normalize_language(name: str) -> str:
    key = name.strip().lower()
    return LANGUAGE_ALIASES.get(key, key)


def normalize_languages(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        lang = normalize_language(str(value))
        if not lang:
            continue
        if lang in seen:
            continue
        seen.add(lang)
        out.append(lang)
    return out


def extensions_for_languages(values: Iterable[str]) -> set[str]:
    languages = normalize_languages(values)
    exts: set[str] = set()
    for lang in languages:
        exts.update(LANGUAGE_EXTENSIONS.get(lang, []))
    return exts


def language_for_path(path: Path) -> str | None:
    suffix = path.suffix.lower()
    for lang, extensions in LANGUAGE_EXTENSIONS.items():
        if suffix in extensions:
            return lang
    return None
