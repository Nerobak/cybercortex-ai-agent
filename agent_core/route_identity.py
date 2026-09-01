"""Canonical identity helpers for documented and observed HTTP routes."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit


def normalize_route_path(value: Any) -> str:
    """Return a stable path template without query or fragment components."""
    text = str(value or "/").strip()
    parsed = urlsplit(text)
    path = parsed.path if re.match(r"^[a-z][a-z0-9+.-]*://", text, re.I) else text
    path = path.split("?", 1)[0]
    path = path.split("#", 1)[0]
    path = re.sub(r"/{2,}", "/", path)
    if not path.startswith("/"):
        path = f"/{path}"
    if len(path) > 1:
        path = path.rstrip("/")
    return path or "/"


def route_identity(item: dict[str, Any]) -> tuple[str, str]:
    """Identify an HTTP operation by method and normalized path."""
    return (
        str(item.get("method") or "GET").upper(),
        normalize_route_path(item.get("path") or item.get("url") or "/"),
    )
