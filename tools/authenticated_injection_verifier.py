from __future__ import annotations

import hashlib
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from tools.raw_http_request_parser import parse_raw_http_request
from tools.safe_http import ScopedHTTPClient
from tools.scope_guard import enforce_scope

MAX_RESPONSE_BYTES = 500_000
DEFAULT_TIMEOUT_SECONDS = 15
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
}


def _fingerprint(response: requests.Response) -> dict[str, Any]:
    content = response.content[:MAX_RESPONSE_BYTES]
    return {
        "status_code": response.status_code,
        "body_length": len(content),
        "body_sha256": hashlib.sha256(content).hexdigest(),
        "content_type": response.headers.get("Content-Type", "")[:120],
        "elapsed_ms": round(response.elapsed.total_seconds() * 1000, 2),
        "_comparison_text": content.decode(response.encoding or "utf-8", "replace"),
    }


def _public_fingerprint(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if not key.startswith("_")}


def _similarity(left: dict[str, Any], right: dict[str, Any]) -> float:
    return round(
        SequenceMatcher(
            None, left.get("_comparison_text", ""), right.get("_comparison_text", "")
        ).ratio(),
        4,
    )


def _payloads(original: str) -> tuple[str, str]:
    if original.strip().lstrip("-").isdigit():
        return f"{original} AND 1=1", f"{original} AND 1=2"
    return f"{original}' AND '1'='1", f"{original}' AND '1'='2"


def _replace_parameter(url: str, parameter: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    updated: list[tuple[str, str]] = []
    for name, current in pairs:
        if name == parameter and not replaced:
            updated.append((name, value))
            replaced = True
        else:
            updated.append((name, current))
    if not replaced:
        raise ValueError(f"Query parameter '{parameter}' was not present.")
    return urlunsplit(parsed._replace(query=urlencode(updated)))


def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in {"host", "content-length"}
    }


def verify_boolean_sql_injection(
    raw_request: str,
    parameter: str,
    *,
    default_scheme: str = "https",
    authorization_confirmed: bool = False,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """Run one bounded, non-extracting boolean differential SQLi check."""
    if not authorization_confirmed:
        return {
            "success": False,
            "error": "Explicit authorization confirmation is required.",
        }
    parsed = parse_raw_http_request(raw_request, default_scheme=default_scheme)
    if not parsed.get("success"):
        return parsed
    if parsed.get("method") != "GET":
        return {
            "success": False,
            "error": "Only GET requests are supported by the bounded verifier.",
        }
    url = parsed["url"]
    scope = enforce_scope(url)
    if not scope.get("allowed"):
        return {"success": False, "error": scope.get("error"), "scope": scope}

    query_pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    originals = [value for name, value in query_pairs if name == parameter]
    if not originals:
        return {
            "success": False,
            "error": f"Query parameter '{parameter}' was not present.",
        }
    true_value, false_value = _payloads(originals[0])
    urls = (
        url,
        _replace_parameter(url, parameter, true_value),
        _replace_parameter(url, parameter, false_value),
    )
    headers = _safe_headers(parsed.get("headers", {}))
    fingerprints: list[dict[str, Any]] = []
    client = ScopedHTTPClient(
        requester=requests.get,
        requester_takes_method=False,
        scope_prevalidated=True,
    )
    try:
        for request_url in urls:
            response, _ = client.request(
                "GET",
                request_url,
                headers=headers,
                timeout=timeout_seconds,
                follow_redirects=False,
                verify=verify_tls,
            )
            fingerprints.append(_fingerprint(response))
    except requests.RequestException as exc:
        return {"success": False, "error": f"Controlled request failed: {exc}"}

    baseline, true_case, false_case = fingerprints
    baseline_true = _similarity(baseline, true_case)
    baseline_false = _similarity(baseline, false_case)
    true_false = _similarity(true_case, false_case)
    delta = round(baseline_true - baseline_false, 4)
    consistent_status = baseline["status_code"] == true_case["status_code"]
    strong_differential = consistent_status and delta >= 0.25 and true_false <= 0.75

    finding = {
        "title": (
            "Boolean-based SQL injection candidate"
            if strong_differential
            else "SQL injection differential not established"
        ),
        "category": "sql_injection",
        "severity": "high" if strong_differential else "informational",
        "confidence": "high" if strong_differential else "low",
        "status": "needs_manual_verification" if strong_differential else "observation",
        "source_tool": "authenticated_injection_verifier",
        "endpoint": urlsplit(url)._replace(query="").geturl(),
        "method": "GET",
        "evidence": [
            f"Baseline-to-true similarity: {baseline_true}.",
            f"Baseline-to-false similarity: {baseline_false}.",
            f"True-to-false similarity: {true_false}.",
            f"Differential score: {delta}.",
        ],
        "impact": (
            "The parameter may influence a server-side SQL predicate."
            if strong_differential
            else "The bounded comparison did not establish SQL predicate control."
        ),
        "recommendation": "Use parameterized queries and verify the candidate manually without extracting data.",
        "manual_verification": [
            "Repeat once to exclude unstable or personalized responses.",
            "Confirm the behavior in server logs or a controlled test environment.",
            "Do not enumerate data or modify records.",
        ],
        "metadata": {
            "parameter": parameter,
            "request_count": 3,
            "payload_family": "boolean_differential_non_extracting",
        },
    }
    return {
        "success": True,
        "finding": finding,
        "responses": {
            "baseline": _public_fingerprint(baseline),
            "true_case": _public_fingerprint(true_case),
            "false_case": _public_fingerprint(false_case),
        },
        "scope": scope,
    }
