from __future__ import annotations

import json
import re
import time
from collections import deque
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

import requests

from tools.scope_guard import enforce_scope

DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_PAGES = 100
DEFAULT_DELAY_SECONDS = 0.25
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_MAX_BODY_BYTES = 1_000_000

SAFE_CONTENT_TYPES = {
    "application/json",
    "application/problem+json",
    "text/html",
    "text/plain",
    "application/javascript",
    "text/javascript",
}

IDENTIFIER_FIELD_PATTERN = re.compile(
    r"(?:^|[_-])(?:id|uuid|guid|key)$|" r"(?:id|uuid|guid)$",
    re.IGNORECASE,
)

UUID_PATTERN = re.compile(
    r"\b[0-9a-f]{8}-"
    r"[0-9a-f]{4}-"
    r"[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}\b",
    re.IGNORECASE,
)

URL_PATTERN = re.compile(
    r"""(?:"|')(
        /[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]+
        |
        https?://[^\s"'<>]+
    )(?:"|')""",
    re.VERBOSE,
)

HTML_LINK_PATTERN = re.compile(
    r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""",
    re.IGNORECASE,
)

JSON_KEY_VALUE_PATTERN = re.compile(
    r"""["']([A-Za-z0-9_.-]*(?:id|uuid|guid|key))["']
        \s*:\s*
        ["']?([A-Za-z0-9_.:@/-]+)["']?""",
    re.IGNORECASE | re.VERBOSE,
)

PATH_SKIP_SEGMENTS = {
    "api",
    "rest",
    "graphql",
    "v1",
    "v2",
    "v3",
    "assets",
    "static",
    "images",
    "css",
    "js",
}

REDACTED_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
}


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)

    normalized = parsed._replace(
        fragment="",
    )

    return urlunparse(normalized)


def _same_origin(first_url: str, second_url: str) -> bool:
    first = urlparse(first_url)
    second = urlparse(second_url)

    first_port = first.port or (443 if first.scheme == "https" else 80)

    second_port = second.port or (443 if second.scheme == "https" else 80)

    return (
        first.scheme == second.scheme
        and first.hostname == second.hostname
        and first_port == second_port
    )


def _sanitize_headers(
    headers: dict[str, Any] | None,
) -> dict[str, str]:
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


def _looks_like_identifier(value: str) -> bool:
    text = value.strip()

    if not text:
        return False

    if text.isdigit():
        return True

    if UUID_PATTERN.fullmatch(text):
        return True

    if len(text) >= 8 and re.fullmatch(
        r"[A-Za-z0-9_-]+",
        text,
    ):
        return True

    return False


def _identifier_type(value: str) -> str:
    text = value.strip()

    if text.isdigit():
        return "numeric"

    if UUID_PATTERN.fullmatch(text):
        return "uuid"

    return "opaque"


def _singularize(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")

    if normalized.endswith("ies") and len(normalized) > 3:
        return normalized[:-3] + "y"

    if normalized.endswith("sses"):
        return normalized[:-2]

    if normalized.endswith("s") and len(normalized) > 1:
        return normalized[:-1]

    return normalized


def _extract_path_identifiers(
    url: str,
) -> list[dict[str, Any]]:
    parsed = urlparse(url)

    segments = [segment for segment in parsed.path.split("/") if segment]

    identifiers: list[dict[str, Any]] = []

    for index, segment in enumerate(segments):
        decoded_segment = segment.strip()

        if not _looks_like_identifier(decoded_segment):
            continue

        parent = segments[index - 1] if index > 0 else "object"

        object_name = _singularize(parent)

        identifiers.append(
            {
                "source": "path",
                "endpoint": parsed.path or "/",
                "field": object_name,
                "value": decoded_segment,
                "identifier_type": _identifier_type(decoded_segment),
            }
        )

    return identifiers


def _extract_query_identifiers(
    url: str,
) -> list[dict[str, Any]]:
    parsed = urlparse(url)

    query = parse_qs(
        parsed.query,
        keep_blank_values=True,
    )

    identifiers: list[dict[str, Any]] = []

    for field, values in query.items():
        normalized_field = re.sub(
            r"[^a-z0-9_-]",
            "",
            field.lower(),
        )

        field_looks_like_id = bool(IDENTIFIER_FIELD_PATTERN.search(normalized_field))

        for value in values:
            if field_looks_like_id or _looks_like_identifier(value):
                identifiers.append(
                    {
                        "source": "query",
                        "endpoint": parsed.path or "/",
                        "field": field,
                        "value": value,
                        "identifier_type": (_identifier_type(value)),
                    }
                )

    return identifiers


def _extract_json_identifiers(
    value: Any,
    endpoint: str,
    prefix: str = "",
) -> list[dict[str, Any]]:
    identifiers: list[dict[str, Any]] = []

    if isinstance(value, dict):
        for key, child in value.items():
            field_path = f"{prefix}.{key}" if prefix else str(key)

            normalized_key = re.sub(
                r"[^a-z0-9_-]",
                "",
                str(key).lower(),
            )

            if IDENTIFIER_FIELD_PATTERN.search(normalized_key) and isinstance(
                child,
                (str, int),
            ):
                identifiers.append(
                    {
                        "source": "json",
                        "endpoint": endpoint,
                        "field": field_path,
                        "value": str(child),
                        "identifier_type": (_identifier_type(str(child))),
                    }
                )

            identifiers.extend(
                _extract_json_identifiers(
                    child,
                    endpoint=endpoint,
                    prefix=field_path,
                )
            )

    elif isinstance(value, list):
        for index, child in enumerate(value):
            field_path = f"{prefix}[{index}]"

            identifiers.extend(
                _extract_json_identifiers(
                    child,
                    endpoint=endpoint,
                    prefix=field_path,
                )
            )

    return identifiers


def _extract_text_identifiers(
    text: str,
    endpoint: str,
) -> list[dict[str, Any]]:
    identifiers: list[dict[str, Any]] = []

    for field, value in JSON_KEY_VALUE_PATTERN.findall(text):
        identifiers.append(
            {
                "source": "text",
                "endpoint": endpoint,
                "field": field,
                "value": value,
                "identifier_type": _identifier_type(value),
            }
        )

    for value in UUID_PATTERN.findall(text):
        identifiers.append(
            {
                "source": "text_uuid",
                "endpoint": endpoint,
                "field": "uuid",
                "value": value,
                "identifier_type": "uuid",
            }
        )

    return identifiers


def _extract_links(
    text: str,
    base_url: str,
) -> list[str]:
    discovered: set[str] = set()

    for raw_link in HTML_LINK_PATTERN.findall(text):
        discovered.add(_normalize_url(urljoin(base_url, raw_link)))

    for raw_link in URL_PATTERN.findall(text):
        discovered.add(_normalize_url(urljoin(base_url, raw_link)))

    return sorted(discovered)


def _parse_response_content(
    response: requests.Response,
) -> tuple[Any, str]:
    content = response.content[:DEFAULT_MAX_BODY_BYTES]

    content_type = (
        response.headers.get(
            "Content-Type",
            "",
        )
        .split(";")[0]
        .strip()
        .lower()
    )

    if content_type in {
        "application/json",
        "application/problem+json",
    }:
        try:
            return response.json(), content_type
        except requests.JSONDecodeError:
            pass

    text = content.decode(
        response.encoding or "utf-8",
        errors="replace",
    )

    return text, content_type


def _deduplicate_identifiers(
    identifiers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    unique: dict[
        tuple[str, str, str, str],
        dict[str, Any],
    ] = {}

    for item in identifiers:
        identity = (
            str(item.get("source")),
            str(item.get("endpoint")),
            str(item.get("field")),
            str(item.get("value")),
        )

        unique[identity] = item

    return list(unique.values())


def _build_object_map(
    identifiers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    objects: dict[str, dict[str, Any]] = {}

    for identifier in identifiers:
        object_name = _singularize(
            str(identifier.get("field", "object")).split(".")[-1]
        )

        entry = objects.setdefault(
            object_name,
            {
                "name": object_name,
                "identifier_types": set(),
                "sample_identifiers": [],
                "endpoints": set(),
                "sources": set(),
            },
        )

        entry["identifier_types"].add(
            identifier.get(
                "identifier_type",
                "opaque",
            )
        )

        value = str(identifier.get("value", ""))

        if value and value not in entry["sample_identifiers"]:
            entry["sample_identifiers"].append(value)

        endpoint = str(identifier.get("endpoint", "/"))

        entry["endpoints"].add(endpoint)
        entry["sources"].add(identifier.get("source", "unknown"))

    final_objects: list[dict[str, Any]] = []

    for name, item in sorted(objects.items()):
        final_objects.append(
            {
                "name": name,
                "identifier_types": sorted(item["identifier_types"]),
                "sample_identifiers": item["sample_identifiers"][:10],
                "endpoints": sorted(item["endpoints"]),
                "sources": sorted(item["sources"]),
            }
        )

    return final_objects


def crawl_and_discover_ids(
    start_url: str,
    headers: dict[str, str] | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_pages: int = DEFAULT_MAX_PAGES,
    delay_seconds: float = DEFAULT_DELAY_SECONDS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    same_origin_only: bool = True,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """
    Crawl an explicitly authorized target and extract identifiers observed
    in returned content.

    The crawler does not generate numeric ranges or brute-force identifiers.
    It only records identifiers already exposed by the application.
    """
    if max_depth < 0:
        return {
            "success": False,
            "error": "max_depth cannot be negative.",
        }

    if max_pages < 1:
        return {
            "success": False,
            "error": "max_pages must be at least 1.",
        }

    parsed_start = urlparse(start_url)

    if parsed_start.scheme not in {"http", "https"} or not parsed_start.hostname:
        return {
            "success": False,
            "error": ("A valid HTTP or HTTPS start URL is required."),
        }

    scope_result = enforce_scope(start_url)

    if not scope_result.get("allowed"):
        return {
            "success": False,
            "error": scope_result.get(
                "error",
                "Start URL is outside the configured scope.",
            ),
            "scope": scope_result,
        }

    prepared_headers = {
        str(name).strip(): str(value).strip() for name, value in (headers or {}).items()
    }

    prepared_headers.setdefault(
        "User-Agent",
        "CyberCortexAI/2.0 Authorized-Discovery",
    )

    prepared_headers.setdefault(
        "Accept",
        ("application/json, text/html, " "application/javascript, text/plain, */*"),
    )

    queue: deque[tuple[str, int]] = deque(
        [
            (
                _normalize_url(start_url),
                0,
            )
        ]
    )

    queued: set[str] = {_normalize_url(start_url)}

    visited: set[str] = set()
    pages: list[dict[str, Any]] = []
    identifiers: list[dict[str, Any]] = []
    discovered_urls: set[str] = set()
    errors: list[dict[str, str]] = []

    session = requests.Session()

    while queue and len(visited) < max_pages:
        current_url, depth = queue.popleft()

        if current_url in visited:
            continue

        if same_origin_only and not _same_origin(
            start_url,
            current_url,
        ):
            continue

        current_scope = enforce_scope(current_url)

        if not current_scope.get("allowed"):
            errors.append(
                {
                    "url": current_url,
                    "error": "Discovered URL was outside scope.",
                }
            )
            continue

        try:
            started = time.perf_counter()

            response = session.get(
                current_url,
                headers=prepared_headers,
                timeout=timeout_seconds,
                allow_redirects=False,
                verify=verify_tls,
            )

            elapsed_ms = round(
                (time.perf_counter() - started) * 1000,
                2,
            )

        except requests.RequestException as error:
            errors.append(
                {
                    "url": current_url,
                    "error": str(error),
                }
            )

            visited.add(current_url)
            continue

        visited.add(current_url)

        parsed_body, content_type = _parse_response_content(response)

        endpoint = urlparse(current_url).path or "/"

        page_identifiers = []

        page_identifiers.extend(_extract_path_identifiers(current_url))

        page_identifiers.extend(_extract_query_identifiers(current_url))

        links: list[str] = []

        if isinstance(parsed_body, (dict, list)):
            page_identifiers.extend(
                _extract_json_identifiers(
                    parsed_body,
                    endpoint=endpoint,
                )
            )

            serialized_body = json.dumps(
                parsed_body,
                ensure_ascii=False,
            )

            links.extend(
                _extract_links(
                    serialized_body,
                    current_url,
                )
            )

        elif isinstance(parsed_body, str):
            page_identifiers.extend(
                _extract_text_identifiers(
                    parsed_body,
                    endpoint=endpoint,
                )
            )

            links.extend(
                _extract_links(
                    parsed_body,
                    current_url,
                )
            )

        page_identifiers = _deduplicate_identifiers(page_identifiers)

        identifiers.extend(page_identifiers)

        pages.append(
            {
                "url": current_url,
                "depth": depth,
                "status_code": response.status_code,
                "content_type": content_type,
                "elapsed_ms": elapsed_ms,
                "response_headers": _sanitize_headers(dict(response.headers)),
                "identifier_count": len(page_identifiers),
                "identifiers": page_identifiers,
            }
        )

        if depth >= max_depth:
            continue

        for discovered_url in links:
            discovered_urls.add(discovered_url)

            if same_origin_only and not _same_origin(
                start_url,
                discovered_url,
            ):
                continue

            if discovered_url in visited:
                continue

            if discovered_url in queued:
                continue

            queued.add(discovered_url)
            queue.append(
                (
                    discovered_url,
                    depth + 1,
                )
            )

        if delay_seconds > 0:
            time.sleep(delay_seconds)

    identifiers = _deduplicate_identifiers(identifiers)

    object_map = _build_object_map(identifiers)

    candidate_tests = [
        {
            "endpoint": item["endpoint"],
            "field": item["field"],
            "observed_identifier": item["value"],
            "identifier_type": item["identifier_type"],
            "source": item["source"],
            "recommendation": (
                "Use a second explicitly controlled account "
                "and a known object owned by that account for "
                "authorization comparison."
            ),
        }
        for item in identifiers
    ]

    return {
        "success": True,
        "start_url": start_url,
        "scope": scope_result,
        "configuration": {
            "max_depth": max_depth,
            "max_pages": max_pages,
            "delay_seconds": delay_seconds,
            "same_origin_only": same_origin_only,
            "verify_tls": verify_tls,
        },
        "summary": {
            "pages_visited": len(pages),
            "urls_discovered": len(discovered_urls),
            "identifier_count": len(identifiers),
            "object_count": len(object_map),
            "error_count": len(errors),
        },
        "pages": pages,
        "identifiers": identifiers,
        "objects": object_map,
        "candidate_authorization_tests": (candidate_tests),
        "errors": errors,
    }
