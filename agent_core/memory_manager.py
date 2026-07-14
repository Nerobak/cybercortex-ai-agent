from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_MEMORY_FILE = Path("memory/scan_history.json")


def _utc_timestamp() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _normalize_target(target: str) -> str:
    """
    Normalize a URL or domain into a consistent hostname.

    Examples:
        https://example.com/path -> example.com
        www.example.com          -> example.com
        example.com              -> example.com
    """
    value = target.strip().lower()

    if "://" not in value:
        value = f"https://{value}"

    parsed = urlparse(value)
    hostname = parsed.hostname or ""

    if hostname.startswith("www."):
        hostname = hostname[4:]

    return hostname


def _empty_memory() -> dict[str, Any]:
    """Return the initial memory structure."""
    return {
        "schema_version": 1,
        "assessments": [],
    }


def load_memory(
    memory_file: str | Path = DEFAULT_MEMORY_FILE,
) -> dict[str, Any]:
    """
    Load assessment memory from disk.

    Returns an empty memory structure when the file does not exist.
    """
    path = Path(memory_file)

    if not path.exists():
        return _empty_memory()

    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (json.JSONDecodeError, OSError) as error:
        return {
            **_empty_memory(),
            "load_error": str(error),
        }

    if not isinstance(data, dict):
        return _empty_memory()

    if not isinstance(data.get("assessments"), list):
        data["assessments"] = []

    data.setdefault("schema_version", 1)

    return data


def save_memory(
    memory: dict[str, Any],
    memory_file: str | Path = DEFAULT_MEMORY_FILE,
) -> dict[str, Any]:
    """Write assessment memory to disk."""
    path = Path(memory_file)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with path.open("w", encoding="utf-8") as file:
            json.dump(memory, file, indent=2, ensure_ascii=False)
    except OSError as error:
        return {
            "success": False,
            "error": str(error),
            "memory_file": str(path),
        }

    return {
        "success": True,
        "memory_file": str(path),
        "assessment_count": len(memory.get("assessments", [])),
    }


def record_assessment(
    target: str,
    results: dict[str, Any],
    report_file: str | None = None,
    mode: str = "safe",
    memory_file: str | Path = DEFAULT_MEMORY_FILE,
) -> dict[str, Any]:
    """
    Save a completed assessment.

    The function stores normalized results rather than raw HTTP bodies or
    complete scanner output.
    """
    normalized_target = _normalize_target(target)

    if not normalized_target:
        return {
            "success": False,
            "error": "A valid target is required.",
        }

    memory = load_memory(memory_file)

    assessment = {
        "assessment_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"),
        "target": normalized_target,
        "original_target": target,
        "timestamp": _utc_timestamp(),
        "mode": mode,
        "report_file": report_file,
        "results": results,
    }

    memory["assessments"].append(assessment)

    save_result = save_memory(memory, memory_file)

    if not save_result["success"]:
        return save_result

    return {
        "success": True,
        "assessment": assessment,
        "memory_file": save_result["memory_file"],
        "assessment_count": save_result["assessment_count"],
    }


def get_target_history(
    target: str,
    memory_file: str | Path = DEFAULT_MEMORY_FILE,
) -> list[dict[str, Any]]:
    """Return every stored assessment for a target."""
    normalized_target = _normalize_target(target)
    memory = load_memory(memory_file)

    history = [
        assessment
        for assessment in memory.get("assessments", [])
        if assessment.get("target") == normalized_target
    ]

    return sorted(
        history,
        key=lambda item: item.get("timestamp", ""),
    )


def get_latest_assessment(
    target: str,
    memory_file: str | Path = DEFAULT_MEMORY_FILE,
) -> dict[str, Any] | None:
    """Return the most recent stored assessment for a target."""
    history = get_target_history(target, memory_file)

    if not history:
        return None

    return history[-1]


def list_targets(
    memory_file: str | Path = DEFAULT_MEMORY_FILE,
) -> list[dict[str, Any]]:
    """Return a summary of all targets stored in memory."""
    memory = load_memory(memory_file)
    summary: dict[str, dict[str, Any]] = {}

    for assessment in memory.get("assessments", []):
        target = assessment.get("target")

        if not target:
            continue

        if target not in summary:
            summary[target] = {
                "target": target,
                "assessment_count": 0,
                "latest_assessment": None,
            }

        summary[target]["assessment_count"] += 1

        current_timestamp = assessment.get("timestamp", "")
        latest = summary[target]["latest_assessment"]

        if latest is None or current_timestamp > latest:
            summary[target]["latest_assessment"] = current_timestamp

    return sorted(
        summary.values(),
        key=lambda item: item["target"],
    )


def clear_target_history(
    target: str,
    memory_file: str | Path = DEFAULT_MEMORY_FILE,
) -> dict[str, Any]:
    """Delete stored assessments for one target."""
    normalized_target = _normalize_target(target)
    memory = load_memory(memory_file)

    original_count = len(memory.get("assessments", []))

    memory["assessments"] = [
        assessment
        for assessment in memory.get("assessments", [])
        if assessment.get("target") != normalized_target
    ]

    removed_count = original_count - len(memory["assessments"])
    save_result = save_memory(memory, memory_file)

    if not save_result["success"]:
        return save_result

    return {
        "success": True,
        "target": normalized_target,
        "removed_count": removed_count,
    }
