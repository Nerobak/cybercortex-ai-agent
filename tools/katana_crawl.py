"""Bounded, scope-aware Katana integration."""

from __future__ import annotations

import subprocess
from urllib.parse import urlparse, urlunparse

from config import BUG_BOUNTY_USER_AGENT, MAX_CRAWL_DEPTH
from tools.scope_guard import enforce_scope

DESTRUCTIVE_SEGMENTS = {
    "logout",
    "log-out",
    "signout",
    "delete",
    "remove",
    "destroy",
    "payment",
    "pay",
    "purchase",
    "checkout",
    "refund",
    "cancel",
}


def _lines(value: str | bytes | None) -> list[str]:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return [line.strip() for line in (value or "").splitlines() if line.strip()]


def _safe_url(raw: str, origin: str, same_origin: bool) -> tuple[bool, str]:
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False, raw
    clean = urlunparse(parsed._replace(fragment=""))
    base = urlparse(origin)
    if same_origin and (parsed.scheme, parsed.hostname, parsed.port) != (
        base.scheme,
        base.hostname,
        base.port,
    ):
        return False, clean
    segments = {segment.lower() for segment in parsed.path.split("/") if segment}
    if segments & DESTRUCTIVE_SEGMENTS:
        return False, clean
    return bool(enforce_scope(clean).get("allowed")), clean


def katana_crawl(
    url: str,
    depth: int = MAX_CRAWL_DEPTH,
    *,
    timeout: int = 60,
    max_urls: int = 100,
    same_origin: bool = True,
    user_agent: str | None = None,
) -> dict:
    command = [
        "katana",
        "-u",
        url,
        "-d",
        str(max(0, depth)),
        "-silent",
        "-H",
        f"User-Agent: {user_agent or BUG_BOUNTY_USER_AGENT}",
    ]
    stdout: str | bytes | None = ""
    stderr: str | bytes | None = ""
    status = "completed"
    returncode = 0
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
        if returncode:
            status = "failed"
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = exc.stdout, exc.stderr
        status = "timed_out_partial" if _lines(stdout) else "timed_out"
        returncode = -1
    except FileNotFoundError:
        return {
            "success": False,
            "status": "failed",
            "url": url,
            "urls": [],
            "count": 0,
            "out_of_scope_urls": [],
            "error": "Katana executable was not found.",
        }
    except Exception as exc:
        return {
            "success": False,
            "status": "failed",
            "url": url,
            "urls": [],
            "count": 0,
            "out_of_scope_urls": [],
            "error": str(exc),
        }

    accepted: list[str] = []
    rejected: list[str] = []
    for raw in _lines(stdout):
        allowed, clean = _safe_url(raw, url, same_origin)
        collection = accepted if allowed else rejected
        if clean not in collection:
            collection.append(clean)
        if len(accepted) >= max_urls:
            break
    error = (
        stderr.decode(errors="replace") if isinstance(stderr, bytes) else stderr or ""
    ).strip() or None
    if status.startswith("timed_out"):
        error = (
            f"Katana timed out after {timeout} seconds; partial output retained."
            if accepted
            else f"Katana timed out after {timeout} seconds."
        )
    return {
        "success": status in {"completed", "timed_out_partial"},
        "status": status,
        "url": url,
        "depth": depth,
        "max_urls": max_urls,
        "count": len(accepted),
        "urls": accepted,
        "out_of_scope_urls": rejected,
        "returncode": returncode,
        "error": error,
    }
