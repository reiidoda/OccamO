from __future__ import annotations

import hashlib


def _normalize_path(path_str: str) -> str:
    value = path_str.replace("\\", "/")
    if value.startswith("./"):
        value = value[2:]
    return value


def hash_text(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def stable_function_id(path_str: str, qualname: str, body_hash: str) -> str:
    parts = [
        _normalize_path(path_str or ""),
        qualname or "",
        body_hash or "",
    ]
    digest = hashlib.sha1("::".join(parts).encode("utf-8")).hexdigest()
    return f"occamo:{digest[:16]}"
