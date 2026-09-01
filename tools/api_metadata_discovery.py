"""Bounded, scope-safe discovery of common API metadata documents."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from config import (
    API_METADATA_DISCOVERY_ENABLED,
    API_METADATA_MAX_REQUESTS,
    API_METADATA_MAX_RESPONSE_BYTES,
    API_METADATA_TIMEOUT_SECONDS,
)
from tools.openapi_surface_analyzer import (
    load_structured_document,
    openapi_version,
    sanitize_openapi_document,
)
from tools.safe_http import (
    PolicyViolationError,
    ResponseTooLargeError,
    ScopedHTTPClient,
    UnsafeRedirectError,
)
from tools.scope_guard import enforce_scope

METADATA_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api/openapi.json",
    "/api/swagger.json",
    "/docs",
    "/redoc",
)
ABSOLUTE_MAX_REQUESTS = len(METADATA_PATHS)


def _safe_url(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port is not None else ""
    return urlunsplit((parsed.scheme, f"{host}{port}", parsed.path or "/", "", ""))


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port is not None else ""
    return urlunsplit((parsed.scheme, f"{host}{port}", "/", "", ""))


def api_metadata_discovery(
    target: str,
    *,
    enabled: bool = API_METADATA_DISCOVERY_ENABLED,
    max_requests: int = API_METADATA_MAX_REQUESTS,
    timeout_seconds: int = API_METADATA_TIMEOUT_SECONDS,
    max_response_bytes: int = API_METADATA_MAX_RESPONSE_BYTES,
    http_client: ScopedHTTPClient | None = None,
) -> dict[str, Any]:
    """GET a fixed set of metadata paths; never enumerate arbitrary paths."""
    if not enabled:
        return {
            "success": True,
            "documents": [],
            "metadata_requests": [],
            "network_tested": False,
            "status": "disabled",
        }
    if not 1 <= max_requests <= ABSOLUTE_MAX_REQUESTS:
        return {"success": False, "error": "max_requests must be between 1 and 8."}
    if not 1 <= timeout_seconds <= 30:
        return {"success": False, "error": "timeout_seconds must be between 1 and 30."}
    if not 1 <= max_response_bytes <= 2_000_000:
        return {
            "success": False,
            "error": "max_response_bytes must be between 1 and 2000000.",
        }
    parsed_target = urlsplit(target)
    if parsed_target.scheme not in {"http", "https"} or not parsed_target.hostname:
        return {"success": False, "error": "A valid HTTP(S) target is required."}
    target_scope = enforce_scope(target)
    if not target_scope.get("allowed"):
        return {
            "success": False,
            "error": target_scope.get("error", "Target is outside scope."),
        }

    client = http_client or ScopedHTTPClient(max_response_bytes=max_response_bytes)
    starting_requests = int(getattr(client, "requests_used", 0))
    origin = _origin(target)
    documents: list[dict[str, Any]] = []
    requests_made: list[dict[str, Any]] = []
    for path in METADATA_PATHS[:max_requests]:
        requests_used = (
            int(
                getattr(client, "requests_used", starting_requests + len(requests_made))
            )
            - starting_requests
        )
        if isinstance(requests_used, int) and requests_used >= max_requests:
            break
        candidate = urljoin(origin, path.lstrip("/"))
        scope = enforce_scope(candidate)
        if not scope.get("allowed"):
            requests_made.append(
                {
                    "url": _safe_url(candidate),
                    "method": "GET",
                    "status": "blocked_out_of_scope",
                    "openapi_detected": False,
                }
            )
            continue
        request_record: dict[str, Any] = {
            "url": _safe_url(candidate),
            "method": "GET",
            "status": "requested",
            "openapi_detected": False,
        }
        try:
            response, redirect_chain = client.request(
                "GET",
                candidate,
                purpose="discovery",
                timeout=timeout_seconds,
                max_redirects=max(0, min(3, max_requests - requests_used - 1)),
                follow_redirects=True,
                headers={
                    "Accept": "application/json, application/yaml, text/yaml, */*",
                    "User-Agent": "CyberCortexAI/2.1 Authorized-Metadata-Discovery",
                },
            )
            content = response.content
            if not isinstance(content, bytes):
                content = bytes(content or b"")
            if len(content) > max_response_bytes:
                raise ResponseTooLargeError(
                    f"Response exceeded the {max_response_bytes}-byte metadata limit."
                )
            content_type = (
                str(response.headers.get("Content-Type") or "").split(";", 1)[0].lower()
            )
            request_record.update(
                {
                    "status": "completed",
                    "status_code": int(response.status_code),
                    "content_type": content_type,
                    "response_bytes": len(content),
                    "effective_url": _safe_url(getattr(response, "url", candidate)),
                    "redirect_chain": [
                        {
                            "from": _safe_url(hop.get("from")),
                            "to": _safe_url(hop.get("to")),
                            "status_code": hop.get("status_code"),
                            "allowed": bool(hop.get("allowed")),
                        }
                        for hop in redirect_chain
                        if isinstance(hop, dict)
                    ],
                }
            )
            structured = None
            if response.status_code < 400 and "html" not in content_type:
                try:
                    structured = load_structured_document(content)
                except UnicodeDecodeError:
                    structured = None
            version = openapi_version(structured)
            if version is not None and isinstance(structured, dict):
                request_record["openapi_detected"] = True
                documents.append(
                    {
                        "source_url": _safe_url(getattr(response, "url", candidate)),
                        "requested_url": _safe_url(candidate),
                        "format": (
                            "json"
                            if path.endswith(".json") or "json" in content_type
                            else "yaml"
                        ),
                        "openapi_version": version,
                        "document": sanitize_openapi_document(structured),
                    }
                )
        except UnsafeRedirectError as exc:
            request_record.update(
                {
                    "status": "blocked_redirect",
                    "error": "Redirect left authorized scope or exceeded the redirect bound.",
                    "redirect_chain": [
                        {
                            "from": _safe_url(hop.get("from")),
                            "to": _safe_url(hop.get("to")),
                            "status_code": hop.get("status_code"),
                            "allowed": bool(hop.get("allowed")),
                        }
                        for hop in exc.redirect_chain
                        if isinstance(hop, dict)
                    ],
                }
            )
        except ResponseTooLargeError:
            request_record.update(
                {
                    "status": "response_too_large",
                    "error": "Response exceeded the configured metadata size limit.",
                }
            )
        except PolicyViolationError as exc:
            request_record.update({"status": "policy_blocked", "error": str(exc)})
        except requests.RequestException as exc:
            request_record.update(
                {"status": "request_failed", "error": type(exc).__name__}
            )
        requests_made.append(request_record)

    return {
        "success": True,
        "documents": documents,
        "metadata_requests": requests_made,
        "document_count": len(documents),
        "request_count": len(requests_made),
        "network_request_count": int(
            getattr(client, "requests_used", starting_requests) - starting_requests
        ),
        "network_tested": any(
            item.get("status") != "blocked_out_of_scope" for item in requests_made
        ),
        "bounds": {
            "max_requests": max_requests,
            "timeout_seconds": timeout_seconds,
            "max_response_bytes": max_response_bytes,
            "methods": ["GET"],
        },
        "vulnerability_status": "not_assessed",
    }
