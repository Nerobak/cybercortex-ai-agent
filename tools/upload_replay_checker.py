"""Strictly bounded opt-in replay for researcher-owned benign files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from tools.scope_guard import enforce_scope

MAX_UPLOAD_REPLAY_BYTES = 1024 * 1024
SAFE_EXTENSIONS = {".txt", ".csv", ".json", ".png", ".jpg", ".jpeg", ".gif", ".pdf"}
BLOCKED_EXTENSIONS = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".sh",
    ".bat",
    ".cmd",
    ".com",
    ".ps1",
    ".php",
    ".jsp",
    ".asp",
    ".aspx",
    ".py",
    ".jar",
    ".war",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".iso",
    ".svg",
    ".html",
    ".htm",
}
MAGIC_BLOCKLIST = (b"MZ", b"\x7fELF", b"#!", b"PK\x03\x04", b"Rar!", b"\x1f\x8b")


def _enabled(value: bool | None) -> bool:
    if value is not None:
        return value
    return os.getenv("UPLOAD_REPLAY_ENABLED", "false").lower() == "true"


def check_upload_replay(
    request: dict[str, Any],
    *,
    enabled: bool | None = None,
    authenticated_profile: bool = False,
    requester: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    base = {"success": True, "automatic_execution": False, "uploaded": False}
    if not _enabled(enabled):
        return {
            **base,
            "status": "disabled",
            "reason": "UPLOAD_REPLAY_ENABLED is false.",
        }
    if not authenticated_profile:
        return {
            **base,
            "status": "blocked_by_policy",
            "reason": "Authenticated profile is required.",
        }
    if not request.get("researcher_owned_file_confirmed") or not request.get(
        "test_owned_resource_confirmed"
    ):
        return {
            **base,
            "status": "blocked_by_policy",
            "reason": "Researcher ownership confirmations are required.",
        }
    url = str(request.get("url") or "")
    if urlparse(url).scheme not in {"http", "https"} or not enforce_scope(url).get(
        "allowed"
    ):
        return {
            **base,
            "status": "blocked_by_policy",
            "reason": "Upload URL is invalid or outside configured scope.",
        }
    path = Path(str(request.get("file_path") or ""))
    try:
        size = path.stat().st_size
    except OSError:
        return {
            **base,
            "status": "blocked_by_policy",
            "reason": "Controlled local file is unavailable.",
        }
    extension = path.suffix.lower()
    if size <= 0 or size > MAX_UPLOAD_REPLAY_BYTES:
        return {
            **base,
            "status": "blocked_by_policy",
            "reason": "File size is outside the bounded replay limit.",
        }
    if extension in BLOCKED_EXTENSIONS or extension not in SAFE_EXTENSIONS:
        return {
            **base,
            "status": "blocked_by_policy",
            "reason": "File type is not allowed for replay.",
        }
    with path.open("rb") as handle:
        content = handle.read(MAX_UPLOAD_REPLAY_BYTES + 1)
    prefix = content[:16]
    embedded_archive = any(magic in content[16:] for magic in MAGIC_BLOCKLIST[3:])
    active_content = any(
        marker in content.lower()
        for marker in (b"<script", b"<?php", b"<html", b"javascript:")
    )
    if (
        any(prefix.startswith(magic) for magic in MAGIC_BLOCKLIST)
        or embedded_archive
        or active_content
    ):
        return {
            **base,
            "status": "blocked_by_policy",
            "reason": "Executable, active, archive, or polyglot content is prohibited.",
        }
    if requester is None:
        return {
            **base,
            "status": "ready_for_bounded_replay",
            "reason": "No requester was supplied; no network traffic was sent.",
        }
    response = requester(
        url,
        file_path=path,
        field_name=str(request.get("field_name") or "file"),
        timeout=min(int(request.get("timeout", 10)), 15),
        allow_redirects=False,
    )
    return {
        **base,
        "status": "completed",
        "uploaded": True,
        "automatic_execution": False,
        "evidence": {
            "status_code": int(response.status_code),
            "response_size": (
                len(getattr(response, "content", b""))
                if hasattr(response, "content")
                else 0
            ),
            "content_type": str(
                getattr(response, "headers", {}).get("Content-Type", "")
            ).split(";")[0],
            "filename_disclosed": False,
        },
        "classification": "observation",
        "vulnerability_status": "observation",
    }


upload_replay_checker = check_upload_replay
