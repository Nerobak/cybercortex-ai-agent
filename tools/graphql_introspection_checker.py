"""Explicitly enabled, bounded and scope-safe GraphQL introspection check."""

from __future__ import annotations

import json
import re
from typing import Any, Callable
from urllib.parse import urljoin

import requests

from config import (
    GRAPHQL_INTROSPECTION_ENABLED,
    GRAPHQL_MAX_RESPONSE_BYTES,
    GRAPHQL_TIMEOUT_SECONDS,
)
from tools.scope_guard import enforce_scope

INTROSPECTION_QUERY = "query CyberCortexSchemaCheck { __schema { queryType { name } mutationType { name } subscriptionType { name } } }"
WORDING = "GraphQL introspection was available on the tested endpoint. This may aid schema discovery but does not by itself establish a security vulnerability."
SECRET = re.compile(r"authorization|cookie|token|secret|password|api.?key", re.I)


def _redact(value: Any, key: str = "") -> Any:
    if SECRET.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value[:50]]
    if isinstance(value, str) and len(value) > 500:
        return value[:500] + "... [truncated]"
    return value


def _post_scoped(
    url: str,
    *,
    timeout: float,
    headers: dict[str, str],
    max_bytes: int,
    requester: Callable[..., Any] | None = None,
) -> tuple[Any, list[dict[str, Any]]]:
    if not enforce_scope(url).get("allowed"):
        raise PermissionError("Requested endpoint is outside configured scope.")
    call = requester or requests.post
    current, chain = url, []
    for _ in range(3):
        response = call(
            current,
            json={"query": INTROSPECTION_QUERY},
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        if response.is_redirect or response.is_permanent_redirect:
            destination = urljoin(current, response.headers.get("Location", ""))
            allowed = bool(enforce_scope(destination).get("allowed"))
            chain.append(
                {
                    "from": current,
                    "to": destination,
                    "status_code": response.status_code,
                    "allowed": allowed,
                }
            )
            if not allowed:
                raise PermissionError(
                    "Redirect destination is outside configured scope."
                )
            current = destination
            continue
        raw = bytearray()
        iterator = (
            response.iter_content(chunk_size=8192)
            if hasattr(response, "iter_content")
            else [getattr(response, "content", b"")]
        )
        for chunk in iterator:
            raw.extend(chunk)
            if len(raw) > max_bytes:
                raise ValueError("GraphQL response exceeded configured size limit.")
        response._content = bytes(raw)
        return response, chain
    raise PermissionError("GraphQL redirect limit exceeded.")


def graphql_introspection_checker(
    endpoint: Any,
    *,
    enabled: bool | None = None,
    timeout: float | None = None,
    max_response_bytes: int | None = None,
    headers: dict[str, str] | None = None,
    requester: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    permitted = GRAPHQL_INTROSPECTION_ENABLED if enabled is None else enabled
    base = {
        "success": True,
        "classification": "request_blocked",
        "introspection_status": "request_blocked",
        "vulnerability_status": "observation",
        "network_checked": False,
        "schema": None,
        "evidence": {},
        "errors": [],
    }
    if not permitted:
        return {
            **base,
            "status": "skipped",
            "reason": "GraphQL introspection is disabled by configuration.",
        }
    if (
        not isinstance(endpoint, dict)
        or endpoint.get("confidence") not in {"confirmed", "likely"}
        or not endpoint.get("url")
    ):
        return {
            **base,
            "classification": "endpoint_not_confirmed",
            "introspection_status": "endpoint_not_confirmed",
            "status": "not_applicable",
            "reason": "Endpoint is not confirmed or high-confidence.",
        }
    url = endpoint["url"]
    if not enforce_scope(url).get("allowed"):
        return {
            **base,
            "status": "skipped",
            "reason": "Endpoint was rejected by configured scope.",
        }
    safe_headers = {
        "Content-Type": "application/json",
        "Accept": "application/graphql-response+json, application/json",
        "User-Agent": "CyberCortexAI-GraphQL/2.1-planning",
    }
    for key, value in (headers or {}).items():
        # Explicitly supplied authentication context may be sent to the
        # authorized endpoint, but headers are never retained in evidence.
        safe_headers[key] = value
    try:
        response, redirects = _post_scoped(
            url,
            timeout=timeout or GRAPHQL_TIMEOUT_SECONDS,
            headers=safe_headers,
            max_bytes=max_response_bytes or GRAPHQL_MAX_RESPONSE_BYTES,
            requester=requester,
        )
        status = int(response.status_code)
        content_type = response.headers.get("Content-Type", "")
        try:
            payload = response.json()
        except (ValueError, json.JSONDecodeError):
            payload = None
        evidence = {
            "endpoint": url,
            "http_status": status,
            "content_type": content_type,
            "redirect_chain": redirects,
            "response_bytes": len(response.content),
            "response_summary": (
                _redact(payload)
                if isinstance(payload, dict)
                else {"structured_json": False}
            ),
        }
        if status in {401, 403}:
            classification = "authentication_required"
        elif (
            isinstance(payload, dict)
            and isinstance(payload.get("data"), dict)
            and payload["data"].get("__schema")
        ):
            classification = "introspection_available"
        elif (
            isinstance(payload, dict)
            and payload.get("errors")
            and any(
                "introspection" in str(x).lower()
                and any(
                    w in str(x).lower()
                    for w in ("disabled", "not allowed", "forbidden")
                )
                for x in payload["errors"]
            )
        ):
            classification = "introspection_disabled"
        elif status >= 400:
            classification = "failed"
        else:
            classification = "inconclusive"
        result = {
            **base,
            "classification": classification,
            "introspection_status": classification,
            "status": "completed",
            "network_checked": True,
            "evidence": evidence,
        }
        if classification == "introspection_available":
            result["message"] = WORDING
        return result
    except requests.Timeout:
        return {
            **base,
            "success": False,
            "classification": "failed",
            "introspection_status": "failed",
            "status": "timed_out",
            "errors": ["GraphQL introspection request timed out."],
        }
    except PermissionError as exc:
        return {**base, "status": "skipped", "errors": [str(exc)]}
    except ValueError as exc:
        return {
            **base,
            "success": False,
            "classification": "failed",
            "introspection_status": "failed",
            "status": "failed",
            "network_checked": True,
            "errors": [str(exc)],
        }
    except requests.RequestException as exc:
        return {
            **base,
            "success": False,
            "classification": "failed",
            "introspection_status": "failed",
            "status": "failed",
            "errors": [f"Request failed: {type(exc).__name__}"],
        }
