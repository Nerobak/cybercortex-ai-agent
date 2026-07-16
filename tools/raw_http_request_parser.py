from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlparse

SUPPORTED_HTTP_VERSIONS = {
    "HTTP/1.0",
    "HTTP/1.1",
    "HTTP/2",
    "HTTP/2.0",
}

REDACTED_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
}


def _normalize_newlines(raw_request: str) -> str:
    """Convert CRLF and CR newlines to standard LF newlines."""
    return raw_request.replace("\r\n", "\n").replace("\r", "\n")


def _split_head_and_body(raw_request: str) -> tuple[str, str]:
    """Separate the request headers from the request body."""
    normalized = _normalize_newlines(raw_request)

    if "\n\n" not in normalized:
        return normalized.strip(), ""

    head, body = normalized.split("\n\n", 1)

    return head.strip(), body


def _parse_request_line(request_line: str) -> dict[str, Any]:
    """
    Parse an HTTP request line.

    Example:
        GET /api/users?id=100 HTTP/1.1
    """
    parts = request_line.strip().split()

    if len(parts) != 3:
        return {
            "success": False,
            "error": (
                "The request line must contain a method, target, " "and HTTP version."
            ),
        }

    method, request_target, http_version = parts

    normalized_method = method.upper()
    normalized_version = http_version.upper()

    if not normalized_method.isalpha():
        return {
            "success": False,
            "error": "The HTTP method is invalid.",
        }

    if normalized_version not in SUPPORTED_HTTP_VERSIONS:
        return {
            "success": False,
            "error": f"Unsupported HTTP version: {http_version}",
        }

    return {
        "success": True,
        "method": normalized_method,
        "request_target": request_target,
        "http_version": normalized_version,
    }


def _parse_headers(header_lines: list[str]) -> dict[str, Any]:
    """
    Parse HTTP headers while supporting folded continuation lines.
    """
    headers: dict[str, str] = {}
    current_header: str | None = None

    for line in header_lines:
        if not line.strip():
            continue

        if line.startswith((" ", "\t")):
            if current_header is None:
                return {
                    "success": False,
                    "error": "Header continuation found without a header.",
                }

            headers[current_header] += " " + line.strip()
            continue

        if ":" not in line:
            return {
                "success": False,
                "error": f"Invalid HTTP header line: {line}",
            }

        name, value = line.split(":", 1)

        normalized_name = name.strip()

        if not normalized_name:
            return {
                "success": False,
                "error": "HTTP header names cannot be empty.",
            }

        headers[normalized_name] = value.strip()
        current_header = normalized_name

    return {
        "success": True,
        "headers": headers,
    }


def _get_header(
    headers: dict[str, str],
    header_name: str,
) -> str | None:
    """Retrieve a header without case sensitivity."""
    expected = header_name.lower()

    for name, value in headers.items():
        if name.lower() == expected:
            return value

    return None


def _build_url(
    request_target: str,
    headers: dict[str, str],
    default_scheme: str,
) -> dict[str, Any]:
    """Build an absolute URL from a Burp-style request."""
    parsed_target = urlparse(request_target)

    if parsed_target.scheme in {"http", "https"}:
        return {
            "success": True,
            "url": request_target,
        }

    host = _get_header(headers, "Host")

    if not host:
        return {
            "success": False,
            "error": (
                "The request requires either an absolute URL " "or a Host header."
            ),
        }

    scheme = default_scheme.lower()

    if scheme not in {"http", "https"}:
        return {
            "success": False,
            "error": "Default scheme must be http or https.",
        }

    path = request_target if request_target.startswith("/") else f"/{request_target}"

    return {
        "success": True,
        "url": f"{scheme}://{host}{path}",
    }


def _parse_body(
    body: str,
    content_type: str | None,
) -> dict[str, Any]:
    """Parse JSON and form bodies when possible."""
    stripped_body = body.strip()

    if not stripped_body:
        return {
            "raw": "",
            "parsed": None,
            "format": "empty",
        }

    normalized_content_type = (content_type or "").lower()

    if "application/json" in normalized_content_type:
        try:
            return {
                "raw": body,
                "parsed": json.loads(stripped_body),
                "format": "json",
            }
        except json.JSONDecodeError:
            return {
                "raw": body,
                "parsed": None,
                "format": "invalid_json",
            }

    if "application/x-www-form-urlencoded" in normalized_content_type:
        return {
            "raw": body,
            "parsed": parse_qs(
                stripped_body,
                keep_blank_values=True,
            ),
            "format": "form",
        }

    return {
        "raw": body,
        "parsed": None,
        "format": "text",
    }


def _sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact credentials for logs and reports."""
    sanitized: dict[str, str] = {}

    for name, value in headers.items():
        if name.lower() in REDACTED_HEADERS:
            sanitized[name] = "[REDACTED]"
        else:
            sanitized[name] = value

    return sanitized


def extract_authorization_context(
    parsed_request: dict[str, Any],
) -> dict[str, str]:
    """
    Extract credential-bearing headers for replay.

    Returned values must remain local and must not be written to reports.
    """
    headers = parsed_request.get("headers", {})
    authorization_context: dict[str, str] = {}

    for name, value in headers.items():
        if name.lower() in REDACTED_HEADERS:
            authorization_context[name] = value

    return authorization_context


def parse_raw_http_request(
    raw_request: str,
    default_scheme: str = "https",
) -> dict[str, Any]:
    """
    Parse a raw HTTP request copied from Burp Repeater.

    This function performs parsing only. It does not send any request.
    """
    if not isinstance(raw_request, str) or not raw_request.strip():
        return {
            "success": False,
            "error": "A raw HTTP request is required.",
        }

    head, body = _split_head_and_body(raw_request)
    head_lines = head.splitlines()

    if not head_lines:
        return {
            "success": False,
            "error": "The HTTP request is empty.",
        }

    request_line_result = _parse_request_line(head_lines[0])

    if not request_line_result["success"]:
        return request_line_result

    headers_result = _parse_headers(head_lines[1:])

    if not headers_result["success"]:
        return headers_result

    headers = headers_result["headers"]

    url_result = _build_url(
        request_target=request_line_result["request_target"],
        headers=headers,
        default_scheme=default_scheme,
    )

    if not url_result["success"]:
        return url_result

    parsed_url = urlparse(url_result["url"])
    query_parameters = parse_qs(
        parsed_url.query,
        keep_blank_values=True,
    )

    content_type = _get_header(headers, "Content-Type")
    parsed_body = _parse_body(body, content_type)

    return {
        "success": True,
        "method": request_line_result["method"],
        "http_version": request_line_result["http_version"],
        "request_target": request_line_result["request_target"],
        "url": url_result["url"],
        "scheme": parsed_url.scheme,
        "host": parsed_url.hostname,
        "port": parsed_url.port,
        "path": parsed_url.path or "/",
        "query_string": parsed_url.query,
        "query_parameters": query_parameters,
        "headers": headers,
        "sanitized_headers": _sanitize_headers(headers),
        "authorization_context": extract_authorization_context(
            {
                "headers": headers,
            }
        ),
        "content_type": content_type,
        "body": parsed_body,
    }
