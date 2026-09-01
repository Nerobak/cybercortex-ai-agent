"""Strictly opt-in, bounded replay for safe controlled workflow requests."""

from __future__ import annotations

from typing import Any, Callable
from urllib.parse import urlsplit

import requests

from config import (
    BUSINESS_LOGIC_MAX_REQUESTS_PER_RUN,
    BUSINESS_LOGIC_MAX_RESPONSE_BYTES,
    BUSINESS_LOGIC_MAX_STEPS,
    BUSINESS_LOGIC_REPLAY_ENABLED,
    BUSINESS_LOGIC_TIMEOUT_SECONDS,
)
from tools.scope_guard import enforce_scope
from tools.safe_http import ScopedHTTPClient

SAFE_METHODS = {"GET", "HEAD"}
BLOCKED_PATH_TERMS = {
    "pay",
    "checkout",
    "purchase",
    "withdraw",
    "deposit",
    "transfer",
    "refund",
    "coupon",
    "loyalty",
    "delete",
    "password",
    "email",
    "mfa",
    "role",
    "permission",
    "admin",
    "kyc",
    "identity",
    "inventory",
    "price",
}
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization"}


def check_workflow_replay(
    evidence: Any,
    *,
    enabled: bool | None = None,
    authenticated_profile: bool = False,
    requester: Callable[..., Any] = requests.request,
) -> dict[str, Any]:
    base = {
        "success": True,
        "network_tested": False,
        "vulnerability_status": "observation",
        "manual_verification_required": True,
    }
    enabled = BUSINESS_LOGIC_REPLAY_ENABLED if enabled is None else enabled
    if not enabled:
        return {
            **base,
            "status": "disabled",
            "reason": "Business-logic replay is disabled by default.",
        }
    if not authenticated_profile:
        return {
            **base,
            "status": "blocked_by_policy",
            "reason": "Authenticated profile is required.",
        }
    if (
        not isinstance(evidence, dict)
        or not evidence.get("controlled_accounts_confirmed")
        or not evidence.get("test_owned_resources_confirmed")
    ):
        return {
            **base,
            "status": "insufficient_evidence",
            "reason": "Controlled-account and test-owned-resource confirmations are required.",
        }
    requests_data = evidence.get("requests") or evidence.get("steps") or []
    if not isinstance(requests_data, list) or not requests_data:
        return {
            **base,
            "status": "not_applicable",
            "reason": "Explicit request steps are required.",
        }
    if len(requests_data) > min(
        BUSINESS_LOGIC_MAX_STEPS, BUSINESS_LOGIC_MAX_REQUESTS_PER_RUN
    ):
        return {
            **base,
            "status": "blocked_by_policy",
            "reason": "Configured request or step limit exceeded.",
        }
    completed = []
    for item in requests_data:
        if not isinstance(item, dict):
            return {**base, "status": "failed", "reason": "Malformed request step."}
        method = str(item.get("method", "GET")).upper()
        url = item.get("url")
        path = urlsplit(str(url or "")).path.lower()
        if method not in SAFE_METHODS:
            return {
                **base,
                "status": "blocked_by_policy",
                "reason": "State-changing requests are rejected by business-logic replay policy.",
            }
        if any(term in path for term in BLOCKED_PATH_TERMS):
            return {
                **base,
                "status": "blocked_by_policy",
                "reason": "Financial, destructive, security-setting, regulated, administrative, or manipulation routes are prohibited.",
            }
        if not isinstance(url, str) or not enforce_scope(url).get("allowed"):
            return {
                **base,
                "status": "blocked_by_policy",
                "reason": "Request is outside configured scope.",
            }
        headers = {
            str(k): str(v)
            for k, v in (item.get("headers") or {}).items()
            if str(k).lower() not in SENSITIVE_HEADERS
        }
        try:
            client = ScopedHTTPClient(
                requester=requester,
                requester_takes_method=True,
                scope_prevalidated=True,
            )
            response, redirect_chain = client.request(
                method,
                url,
                headers=headers,
                timeout=BUSINESS_LOGIC_TIMEOUT_SECONDS,
                follow_redirects=True,
                max_redirects=3,
            )
            redirects = len(redirect_chain)
            content = getattr(response, "content", b"")
            if len(content) > BUSINESS_LOGIC_MAX_RESPONSE_BYTES:
                return {
                    **base,
                    "status": "blocked_by_policy",
                    "reason": "Response exceeded configured size limit.",
                    "network_tested": True,
                }
            completed.append(
                {
                    "method": method,
                    "path": urlsplit(url).path,
                    "status_class": f"{int(getattr(response, 'status_code', 0)) // 100}xx",
                    "response_bytes": len(content),
                    "redirect_count": redirects,
                }
            )
        except requests.Timeout:
            return {
                **base,
                "success": False,
                "status": "failed",
                "reason": "Replay request timed out.",
                "network_tested": True,
            }
        except requests.RequestException:
            return {
                **base,
                "success": False,
                "status": "failed",
                "reason": "Replay request failed.",
                "network_tested": True,
            }
    return {
        **base,
        "status": "completed",
        "network_tested": True,
        "requests_completed": len(completed),
        "observations": completed,
        "limitations": [
            "Successful replay is an observation and does not establish a vulnerability."
        ],
    }


workflow_replay_checker = check_workflow_replay
