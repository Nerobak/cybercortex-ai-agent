"""Shared, offline-safe helpers for the file-upload analysis tools."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any, Iterator

MAX_EVIDENCE_ITEMS = 200
SENSITIVE_KEYS = {
    "body",
    "content",
    "data",
    "file",
    "files",
    "filename",
    "filepath",
    "path_value",
    "raw_request",
    "raw_response",
}


def iter_evidence(value: Any, source: str = "evidence") -> Iterator[tuple[str, Any]]:
    """Walk bounded structured evidence without retaining file content."""
    pending = [(source, value)]
    seen = 0
    while pending and seen < MAX_EVIDENCE_ITEMS:
        location, item = pending.pop(0)
        seen += 1
        yield location, item
        if isinstance(item, dict):
            for key in sorted(item, key=str):
                child = item[key]
                if str(key).lower() in SENSITIVE_KEYS:
                    continue
                pending.append((f"{location}.{key}", child))
        elif isinstance(item, (list, tuple)):
            pending.extend(
                (f"{location}[{index}]", child)
                for index, child in enumerate(item[:MAX_EVIDENCE_ITEMS])
            )


def safe_text(value: Any, limit: int = 4000) -> str:
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, (dict, list, tuple)):
        try:
            return json.dumps(value, sort_keys=True, default=str)[:limit]
        except (TypeError, ValueError):
            return ""
    return str(value)[:limit] if value is not None else ""


def evidence_id(source: str, kind: str, value: str = "") -> str:
    digest = sha256(f"{source}|{kind}|{value}".encode()).hexdigest()[:12]
    return f"upload-{digest}"


def observation(source: str, kind: str, detail: str, confidence: str) -> dict[str, Any]:
    return {
        "evidence_id": evidence_id(source, kind, detail),
        "type": kind,
        "detail": detail,
        "source": source,
        "confidence": confidence,
        "classification": "observation",
        "vulnerability_status": "observation",
        "network_tested": False,
    }


def contains_any(text: str, patterns: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(re.search(pattern, lowered, re.I) for pattern in patterns)
