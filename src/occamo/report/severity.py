from __future__ import annotations


def severity_from_score(score: float) -> str:
    if score >= 3.0:
        return "high"
    if score >= 2.0:
        return "medium"
    if score >= 1.0:
        return "low"
    return "info"


def score_from_severity(severity: str) -> float:
    value = normalize_severity(severity)
    mapping = {
        "info": 0.3,
        "low": 0.9,
        "medium": 1.6,
        "high": 2.6,
        "critical": 3.4,
    }
    return mapping.get(value, 0.3)


def normalize_severity(severity: str) -> str:
    value = severity.strip().lower()
    if value in {"info", "low", "medium", "high", "critical"}:
        return value
    return "info"


def severity_rank(severity: str) -> int:
    value = normalize_severity(severity)
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(value, 0)


def sarif_level(severity: str) -> str:
    value = normalize_severity(severity)
    if value in {"high", "critical"}:
        return "error"
    if value == "medium":
        return "warning"
    return "note"


def github_annotation_level(severity: str) -> str:
    value = normalize_severity(severity)
    if value in {"high", "critical"}:
        return "error"
    if value == "medium":
        return "warning"
    return "notice"


def check_run_annotation_level(severity: str) -> str:
    value = normalize_severity(severity)
    if value in {"high", "critical"}:
        return "failure"
    if value == "medium":
        return "warning"
    return "notice"
