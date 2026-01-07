from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class IRCall:
    name: str
    qualname: str | None
    lineno: int
    in_loop_depth: int
    object_name: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class IRFunction:
    function_id: str
    file: str
    qualname: str
    lineno: int
    end_lineno: int
    language: str
    calls: list[IRCall] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class IRModule:
    file: str
    language: str
    functions: list[IRFunction]
    metadata: dict[str, object] = field(default_factory=dict)
