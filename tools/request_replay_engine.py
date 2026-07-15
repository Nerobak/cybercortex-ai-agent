from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

import requests

from tools.authz_differential_tester import (
    analyze_authorization_difference,
)
from tools.scope_guard import enforce_scope

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

DEFAULT_TIMEOUT_SECONDS = 15
MAX_RESPONSE_BODY_BYTES = 1_000_000

REDACTED_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
}


def _validate_url(url: str) -> dict[str, Any]:
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        return {
            "success": False,
            "error": "Only HTTP and HTTPS URLs are supported.",
        }

    if not parsed.hostname:
        return {
            "success": False,
            "error": "The request URL must contain a valid hostname.",
        }

    return {
        "success": True,
        "hostname": parsed.hostname,
        "path": parsed.path or "/",
    }


def _sanitize_headers(
    headers: dict[str, Any] | None,
) -> dict[str, str]:
    """
    Return normalized headers while removing values that should not appear
    in logs, reports, or saved findings.
    """
    if not headers:
        return {}

    sanitized: dict[str, str] = {}

    for name, value in headers.items():
        normalized_name = str(name).strip()
        normalized_value = str(value).strip()

        if normalized_name.lower() in REDACTED_HEADERS:
            sanitized[normalized_name] = "[REDACTED]"
        else:
            sanitized[normalized_name] = normalized_value

    return sanitized


def _prepare_headers(
    common_headers: dict[str, str] | None,
    authorization_headers: dict[str, str] | None,
) -> dict[str, str]:
    """
    Merge normal request headers with one controlled authorization context.
    """
    prepared: dict[str, str] = {}

    if common_headers:
        prepared.update(
            {
                str(name).strip(): str(value).strip()
                for name, value in common_headers.items()
            }
        )

    if authorization_headers:
        prepared.update(
            {
                str(name).strip(): str(value).strip()
                for name, value in authorization_headers.items()
            }
        )

    prepared.setdefault(
        "User-Agent",
        "CyberCortexAI/2.0 Authorized-Testing",
    )

    prepared.setdefault(
        "Accept",
        "application/json, text/plain, */*",
    )

    return prepared


def _parse_response_body(response: requests.Response) -> Any:
    """
    Prefer parsed JSON. Fall back to bounded text.

    Response content is capped to reduce accidental storage of very large or
    sensitive responses.
    """
    content = response.content[:MAX_RESPONSE_BODY_BYTES]

    content_type = response.headers.get(
        "Content-Type",
        "",
    ).lower()

    if "application/json" in content_type:
        try:
            return response.json()
        except requests.JSONDecodeError:
            pass

    return content.decode(
        response.encoding or "utf-8",
        errors="replace",
    )


def _send_request(
    method: str,
    url: str,
    headers: dict[str, str],
    query_params: dict[str, Any] | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    verify_tls: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=query_params,
            timeout=timeout_seconds,
            allow_redirects=False,
            verify=verify_tls,
        )

    except requests.RequestException as error:
        return {
            "success": False,
            "error": str(error),
        }

    elapsed_ms = round(
        (time.perf_counter() - started) * 1000,
        2,
    )

    return {
        "success": True,
        "request": {
            "method": method,
            "url": response.request.url,
            "headers": _sanitize_headers(dict(response.request.headers)),
        },
        "response": {
            "status_code": response.status_code,
            "headers": _sanitize_headers(dict(response.headers)),
            "body": _parse_response_body(response),
            "elapsed_ms": elapsed_ms,
        },
    }


def replay_authorization_contexts(
    url: str,
    account_a_headers: dict[str, str],
    account_b_headers: dict[str, str],
    method: str = "GET",
    common_headers: dict[str, str] | None = None,
    query_params: dict[str, Any] | None = None,
    object_identifier: str | None = None,
    ownership_confirmed: bool = False,
    separate_accounts_confirmed: bool = False,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """
    Replay one explicit, authorized request with two controlled authorization
    contexts and analyze the resulting response difference.

    This function does not enumerate identifiers or discover new targets.
    """
    normalized_method = method.strip().upper()

    if normalized_method not in SAFE_METHODS:
        return {
            "success": False,
            "error": (
                f"Method {normalized_method} is not supported by the "
                "safe replay engine. Allowed methods: "
                + ", ".join(sorted(SAFE_METHODS))
            ),
        }

    url_validation = _validate_url(url)

    if not url_validation["success"]:
        return url_validation

    scope_result = enforce_scope(url)

    if not scope_result.get("allowed"):
        return {
            "success": False,
            "error": scope_result.get(
                "error",
                "The target is outside the configured scope.",
            ),
            "scope": scope_result,
        }

    if not account_a_headers:
        return {
            "success": False,
            "error": "Account A authorization headers are required.",
        }

    if not account_b_headers:
        return {
            "success": False,
            "error": "Account B authorization headers are required.",
        }

    headers_a = _prepare_headers(
        common_headers=common_headers,
        authorization_headers=account_a_headers,
    )

    headers_b = _prepare_headers(
        common_headers=common_headers,
        authorization_headers=account_b_headers,
    )

    account_a_result = _send_request(
        method=normalized_method,
        url=url,
        headers=headers_a,
        query_params=query_params,
        timeout_seconds=timeout_seconds,
        verify_tls=verify_tls,
    )

    if not account_a_result["success"]:
        return {
            "success": False,
            "error": "Account A request failed.",
            "account_a": account_a_result,
        }

    account_b_result = _send_request(
        method=normalized_method,
        url=url,
        headers=headers_b,
        query_params=query_params,
        timeout_seconds=timeout_seconds,
        verify_tls=verify_tls,
    )

    if not account_b_result["success"]:
        return {
            "success": False,
            "error": "Account B request failed.",
            "account_a": account_a_result,
            "account_b": account_b_result,
        }

    analysis = analyze_authorization_difference(
        baseline_response=account_a_result["response"],
        candidate_response=account_b_result["response"],
        endpoint=url_validation["path"],
        method=normalized_method,
        object_identifier=object_identifier,
        ownership_confirmed=ownership_confirmed,
        separate_accounts_confirmed=separate_accounts_confirmed,
    )

    return {
        "success": True,
        "target": url,
        "method": normalized_method,
        "scope": scope_result,
        "account_a": account_a_result,
        "account_b": account_b_result,
        "analysis": analysis,
    }
