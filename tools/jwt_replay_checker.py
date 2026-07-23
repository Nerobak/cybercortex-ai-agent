"""Explicitly enabled, bounded replay of one controlled JWT request."""

from __future__ import annotations

from typing import Any, Callable
from urllib.parse import urljoin

import requests

from config import (
    JWT_MAX_RESPONSE_BYTES,
    JWT_REPLAY_ENABLED,
    JWT_TIMEOUT_SECONDS,
)
from tools.scope_guard import enforce_scope

SAFE_METHODS = {"GET", "HEAD"}
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie"}


def _safe_headers(headers: Any) -> dict[str, str]:
    if not hasattr(headers, "items"):
        return {}
    return {
        str(name): (
            "[REDACTED]" if str(name).lower() in SENSITIVE_HEADERS else str(value)[:200]
        )
        for name, value in headers.items()
    }


def check_jwt_replay(
    request_evidence: dict[str, Any],
    *,
    enabled: bool | None = None,
    authenticated_profile: bool = False,
    requester: Callable[..., Any] = requests.request,
) -> dict[str, Any]:
    """Send no request unless every explicit replay safety precondition passes."""
    enabled = JWT_REPLAY_ENABLED if enabled is None else enabled
    base = {
        "success": True,
        "vulnerability_status": "observation",
        "network_testing_occurred": False,
    }
    if not enabled:
        return {**base, "status": "disabled", "reason": "JWT replay is disabled."}
    if not authenticated_profile:
        return {
            **base,
            "status": "authentication_required",
            "reason": "Authenticated profile and explicit opt-in are required.",
        }
    if not isinstance(request_evidence, dict):
        return {
            **base,
            "status": "not_applicable",
            "reason": "Controlled request evidence is required.",
        }
    url = request_evidence.get("url")
    token = request_evidence.get("token")
    method = str(request_evidence.get("method", "GET")).upper()
    if not isinstance(url, str) or not isinstance(token, str) or not token:
        return {
            **base,
            "status": "not_applicable",
            "reason": "An in-scope URL and controlled token are required.",
        }
    if not enforce_scope(url).get("allowed"):
        return {
            **base,
            "status": "blocked",
            "reason": "Endpoint is outside configured scope.",
        }
    idempotent_approved = bool(request_evidence.get("idempotent_request_approved"))
    if method not in SAFE_METHODS and not idempotent_approved:
        return {
            **base,
            "status": "blocked",
            "reason": "Only safe GET/HEAD or an explicitly approved idempotent request is allowed.",
        }
    if request_evidence.get("token_type") == "refresh" and not request_evidence.get(
        "refresh_token_authorized"
    ):
        return {
            **base,
            "status": "blocked",
            "reason": "Refresh-token replay was not explicitly authorized.",
        }

    headers = {
        str(name): str(value)
        for name, value in (request_evidence.get("headers") or {}).items()
        if str(name).lower() not in SENSITIVE_HEADERS
    }
    headers["Authorization"] = f"Bearer {token}"
    try:
        response = requester(
            method,
            url,
            headers=headers,
            timeout=JWT_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
        redirects = 0
        while (
            getattr(response, "is_redirect", False)
            and redirects < 3
            and response.headers.get("Location")
        ):
            next_url = urljoin(url, response.headers["Location"])
            if not enforce_scope(next_url).get("allowed"):
                return {
                    **base,
                    "status": "blocked",
                    "reason": "Redirect left configured scope.",
                }
            response = requester(
                method,
                next_url,
                headers=headers,
                timeout=JWT_TIMEOUT_SECONDS,
                allow_redirects=False,
            )
            redirects += 1
        content = getattr(response, "content", b"")
        if len(content) > JWT_MAX_RESPONSE_BYTES:
            return {
                **base,
                "status": "blocked",
                "reason": "Response exceeded the configured size limit.",
                "network_testing_occurred": True,
            }
        status_code = int(getattr(response, "status_code", 0))
        status = (
            "token_rejected"
            if status_code in {401, 403}
            else "token_accepted" if 200 <= status_code < 400 else "inconclusive"
        )
        return {
            **base,
            "status": status,
            "http_status": status_code,
            "response_bytes": len(content),
            "response_content_type": str(
                getattr(response, "headers", {}).get("Content-Type", "")
            )[:100],
            "response_headers": _safe_headers(getattr(response, "headers", {})),
            "redirect_count": redirects,
            "network_testing_occurred": True,
            "manual_verification_required": True,
            "limitations": [
                "Token acceptance alone does not establish a vulnerability."
            ],
        }
    except requests.Timeout:
        return {
            **base,
            "success": False,
            "status": "failed",
            "reason": "Replay request timed out.",
            "network_testing_occurred": True,
        }
    except requests.RequestException:
        return {
            **base,
            "success": False,
            "status": "failed",
            "reason": "Replay request failed.",
            "network_testing_occurred": True,
        }


jwt_replay_checker = check_jwt_replay
